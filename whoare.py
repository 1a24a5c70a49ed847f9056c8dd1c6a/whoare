#!/usr/bin/python3
import argparse
import hashlib
import ipaddress
import json
import os
import re
import subprocess
import sys
import validators

JSON_INDENT = 2

RE_DNS_ARECORD = re.compile('IN\s+A')

# both take from https://uibakery.io/regex-library/ip-address-regex-python
# not tested well ...
RE_IP4 = re.compile('(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)')
RE_IP6 = re.compile('(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))')


class Logger:
    warnCnt = 0

    def logWarning(msg):
        print(f'WARNING: {msg}')
        Logger.warnCnt =+ 1


def getRawWhois(ipAddress):
    cmd = f"whois {ipAddress}"
    sp = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE)
    rawOutput, _ = sp.communicate()
    return rawOutput.decode('utf-8')


def cleanWhoisEntry(rawWhois):
    lines = rawWhois.splitlines()
    lines = [l.strip() for l in lines]
    uniqueLines = set([l for l in lines if not l.startswith('#') and not l.startswith('%')])
    cleanLines = list(uniqueLines)
    cleanLines.sort()
    return '\n'.join(cleanLines)


def getCleanWhois(ipAddress):
    rawWhois = getRawWhois(ipAddress)
    return (cleanWhoisEntry(rawWhois), rawWhois)


def doDNSLookup(domain):
    cmd = f'dig {domain}'
    sp = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE)
    rawOut, _ = sp.communicate()
    return rawOut.decode('utf-8')


def extractIPs(dnsRecord):
    lines = dnsRecord.splitlines()
    relevantLines = []
    relevantLines = [l for l in lines if re.findall(RE_DNS_ARECORD, l)]
    
    ips = set()
    for l in relevantLines:
       ips.update(re.findall(RE_IP4, l))
       ips.update(re.findall(RE_IP6, l))
    
    return list(ips)


def processIP(targetIP, whoisMap, whoisCache=None, domain=None):
    ip = str(targetIP.targetDescription)
    raw = whoisCache.lookup(ip) if whoisCache else getRawWhois(ip)
    clean = cleanWhoisEntry(raw)
    result = ResultItem(targetIP, ip, domain)
    (ipList, raw) = whoisMap[clean] if clean in whoisMap else ([], raw)
    ipList.append(result)
    if clean not in whoisMap:
        whoisMap[clean] = (ipList, raw)


def processRange(targetRange, whoisMap, strangeList, whoisCache=None):
    ipRange = targetRange.targetDescription
    first = ipRange[0]
    last = ipRange[-1]
    if first == last:
        ipTarget = TargetIP(str(first), targetRange.comment)
        processIP(ipTarget, whoisMap, whoisCache=None)
        return

    firstRaw = whoisCache.lookup(str(first)) if whoisCache else getRawWhois(str(first))
    lastRaw = whoisCache.lookup(str(last)) if whoisCache else getRawWhois(str(last))

    firstClean = cleanWhoisEntry(firstRaw)
    lastClean = cleanWhoisEntry(lastRaw)
    if firstClean != lastClean:
        strangeList.append(targetRange)
        return

    result = ResultItem(targetRange, str(ipRange), None)
    (ipList, rawWhois) = whoisMap[firstClean] if firstClean in whoisMap else ([], firstRaw)
    ipList.append(result)
    if firstClean not in whoisMap:
        whoisMap[firstClean] = (ipList, firstRaw)


def processDomain(domain, whoisMap, strangeList, dnsCache=None, whoisCache=None):
    domainName = domain.targetDescription
    dnsEntry = dnsCache.lookup(domainName) if dnsCache else doDNSLookup(domainName)
    ipAddresses = extractIPs(dnsEntry)
    for ip in ipAddresses:
        targetIP = TargetIP(ip, comment=domain.comment)
        processIP(targetIP, whoisMap, whoisCache, domain=domainName)


def writeMapToDir(directory, inputMap):
    # queries and results are expected to be strings
    os.makedirs(directory, exist_ok=True)
    mappingLines = []
    for query, result in inputMap.items():
        qHash = hashlib.sha256(query.encode()).digest().hex()
        mappingLines.append(f'{qHash} {query}')
        filename = os.path.join(directory, qHash)
        with open(filename, 'w') as outfile:
            if (type(result) == str):
                outfile.write(result)
            else:
                outfile.write(result.decode('utf-8'))
                
    mappingFilePath = os.path.join(directory, '_mapping')
    with open(mappingFilePath, 'w') as outMappingFile:
        outMappingFile.write('\n'.join(mappingLines))
         

def readMapFromDir(directory, mappingFile='_mapping'):
    mapping = os.path.join(directory, mappingFile)
    cacheMap = {}
    
    try:
        with open(mapping, 'r') as mappingFile:
            mappingLines = [l.strip() for l in mappingFile]
    except FileNotFoundError as e:
        pass

    for l in mappingLines:
        (qHash, query) = l.split(' ', 1)
        path = os.path.join(directory, qHash)
        try:
            with open(path) as contentFile:
                cacheMap[query] = contentFile.read()
        except FileNotFoundError as e:
            Logger.logWarning(f'{e}')
    
    return cacheMap


def fillinPattern(templateString, regex, replaceMap):
    # if templateString replacements match the regex, we will get an endless loop ...

    placeholders = replaceMap.keys()
    tmp = templateString
    while True:
        m = re.search(regex, tmp)
        if m == None:
            return tmp

        (pre, post) = (tmp[:m.start()], tmp[m.end():])
        matchText = m.group()
        replaced = False
        for placeholder in placeholders:
            if placeholder in matchText:
                replacement = replaceMap[placeholder]
                middle = '' if replacement == None else matchText[2:-2].replace(placeholder, replacement)
                tmp = pre + middle  + post 
                replaced = True
                break
        if not replaced:
            tmp = pre + post
 

class Target:
    """
    A lookup target.
    """
    TYPE_IP = 'IP'
    TYPE_IP_RANGE = 'IPRange'
    TYPE_DOMAIN = 'Domain'

    def fromDict(d):
        objType = d['type']
        if objType == Target.TYPE_IP:
            return TargetIP(d['targetDescription'], d['comment'])
        elif objType == Target.TYPE_IP_RANGE:
            return TargetIPRange(d['targetDescription'], d['comment'])
        elif objType == Target.TYPE_DOMAIN:
            return TargetDomain(d['targetDescription'], d['comment'])
        else:
            raise ValueError(f'Unknown type {d["type"]}')

    def fromJSON(jsonString):
        dictObj = json.loads(jsonString)
        return Target.fromDict(dictObj)
#
    def __init__(self, targetDescription, comment=None):
        self.targetDescription = targetDescription
        self.comment = comment

    def doLookup(self, whoisMap, strangeList, dnsCache=None, whoisCache=None):
        raise NotImplementedError()

    def toDict(self):
        return {
            'targetDescription' : str(self.targetDescription),
            'comment' : self.comment
        }

    def toJSON(self):
        return json.dumps(self.toDict(), sort_keys=True, indent=JSON_INDENT)


class TargetIP(Target):
    def doLookup(self, whoisMap, strangeList, dnsCache=None, whoisCache=None):
        processIP(self, whoisMap, whoisCache)

    def __str__(self):
        return f'TargetIP({self.targetDescription}, {self.comment})'

    # required for serialization to JSON
    def toDict(self):
        dictObj = super().toDict()
        dictObj['type'] = Target.TYPE_IP
        return dictObj


class TargetIPRange(Target):
    def doLookup(self, whoisMap, strangeList, dnsCache=None, whoisCache=None):
        processRange(self, whoisMap, strangeList, whoisCache)

    def __str__(self):
        return f'TargetIPRange({self.targetDescription}, {self.comment})'

    # required for serialization to JSON
    def toDict(self):
        dictObj = super().toDict()
        dictObj['type'] = Target.TYPE_IP_RANGE
        return dictObj


class TargetDomain(Target):
    def doLookup(self, whoisMap, strangeList, dnsCache=None, whoisCache=None):
        processDomain(self, whoisMap, strangeList, dnsCache, whoisCache)

    def __str__(self):
        return f'TargetDomain({self.targetDescription}, {self.comment})'

    # required for serialization to JSON
    def toDict(self):
        dictObj = super().toDict()
        dictObj['type'] = Target.TYPE_DOMAIN
        return dictObj


class ResultItem:
    """
    A single reuslt item (e.g. an IP range with corresponding whois entry).
    For convenience the input item form which the result was procuced is included.
    """

    # RE_EXTRACT_PLACEHOLDERS = re.compile('{{[^{}]+?}}')
    RE_EXTRACT_PLACEHOLDERS = re.compile('{{((?!{{).)*}}')

    PLACEHOLDER_IP = '__IP__'
    PLACEHOLDER_DOMAIN = '__DOMAIN__'
    PLACEHOLDER_COMMENT = '__COMMENT__'

    DEFAULT_TEMPLATE = '{{__IP__}} {{(__DOMAIN__)}} {{[__COMMENT__]}}'

    def fromDict(d):
        target = Target.fromDict(d['inputItem'])
        return ResultItem(target, d['ip'], d['domain'])

    def fromJSON(jsonString):
        return ResultItem.fromDict(json.loads(jsonString))

    def __init__(self, inputItem, ip, domain):
        self.inputItem = inputItem
        self.ip = ip
        self.domain = domain

    def __str__(self):
        return f'ReultItem({self.inputItem.targetDescription}, {self.domain}, {self.inputItem.comment})'

    def toDict(self):
        return {
            'inputItem' : self.inputItem.toDict(),
            'ip' : str(self.ip),
            'domain' : self.domain
        }

    def toJSON(self):
        return json.dumps(self.toDict(), sort_keys=True, indent=JSON_INDENT)

    def format(self, templateString=DEFAULT_TEMPLATE):
        replaceMap = {
            ResultItem.PLACEHOLDER_IP : self.ip,
            ResultItem.PLACEHOLDER_DOMAIN : self.domain,
            ResultItem.PLACEHOLDER_COMMENT : self.inputItem.comment
        }
        return fillinPattern(templateString, ResultItem.RE_EXTRACT_PLACEHOLDERS, replaceMap)


class WhoisLine:
    """
    A line form a whois entry.
    """

    LINE_TAG_EVIDENCE = 'evidence'
    LINE_TAG_INFO = 'info'

    def fromDict(d):
       return WhoisLine(d['preMatch'], d['match'], d['postMatch'], d['number'], d['tag']) 

    def fromJSON(jsonString):
        return WhoisLine.fromDict(json.loads(jsonString))

    def __init__(self, textPreMatch, textMatch, textPostMatch, number, tag):
        self.preMatch = textPreMatch
        self.match = textMatch
        self.postMatch = textPostMatch
        self.number = number
        self.tag = tag

    def format(self, matchPrefix='', matchSuffix=''):
        return self.preMatch + matchPrefix + self.match + matchSuffix + self.postMatch

    def toDict(self):
        return self.__dict__

    def toJSON(self):
        return json.dumps(self.toDict())
        

class WhoisGroup:
    """
    A group of IP ranges or IPs with the same whois entry.    
    """

    def fromDict(d):
        rLines = d['resultList']
        resultList = [ResultItem.fromDict(ri) for ri in rLines]

        wLines = d['whoisLines']
        whoisLines = [WhoisLine.fromDict(wl) for wl in wLines]
        whoisGroup = WhoisGroup(d['whois'], resultList, whoisLines)
        return whoisGroup

    def fromJSON(jsonString):
        return WhoisGroup.fromDict(json.loads(jsonString))

    def __init__(self, whois, resultList, whoisLines=[]):
        self.whois = whois
        self.resultList = resultList
        self.whoisLines = whoisLines

    def addLine(self, preMatch, match, postMatch, num, tag):
        self.whoisLines.append(WhoisLine(preMatch, match, postMatch, num, tag))

    def format(self, resultLineTemplate=ResultItem.DEFAULT_TEMPLATE, matchPrefix='', matchSuffix='', suppressWhoisLines=False):
        outLines = [ri.format(resultLineTemplate) for ri in self.resultList]
        
        if not suppressWhoisLines:
            for line in self.whoisLines:
                outLines.append(line.format(matchPrefix, matchSuffix))

        return '\n'.join(outLines) + '\n'

    def toDict(self):
        return {
            'whois' : self.whois,
            'resultList' : [r.toDict() for r in self.resultList],
            'whoisLines' : [l.toDict() for l in self.whoisLines]
        }

    def toJSON(self):
        return json.dumps(self.toDict())
        


#    def formatLatex(self, whoisLineTemplate, whoisPreMatch='', whoisPostMatch='',
#    TODO: implement in separate tool
#        digDomains=True, preDig='§B[# ', postDig=']B§', 
#        whoisIP=True, preWhois='§B[# ', postWhois=']B§',
#        ellipsis='§[\\sygray{\\lbrack...\\rbrack}]§'):
#        
#        outLines = []
#        for resultItem in self.resultList:
#           if digDomains and resultItem.domain:
#                outLines.append(f'{preDig}dig +short {resultItem.domain}{postDig}')
#                outLines.append(resultItem.ip)
#
#        if whoisIP:
#            ip = self.resultList[0].ip
#            outLines.append(f'{preWhois}whois {ip}{postWhois}')
#
#        prevLineNum = -1
#        for line in self.whoisLines:
#            if ellipsis and prevLineNum < line.number - 1:
#               outLines.append(ellipsis) 
#            outLines.append(line.format(whoisPreMatch, whoisPostMatch))
#            prevLineNum = line.number
#            # TODO: possible ellipsis after last line
#
#        return '\n'.join(outLines) + '\n' 

    
class DNSCache:
    def __init__(self, cacheDir=None):
        self.cacheDir = cacheDir
        self.cacheMap = {}

        if os.path.isdir(self.cacheDir):
            self.cacheMap = readMapFromDir(cacheDir) if cacheDir else {} 


    def lookup(self, domainString):
        if domainString in self.cacheMap:
            return self.cacheMap[domainString]

        dnsEntry = doDNSLookup(domainString)
        self.cacheMap[domainString] = dnsEntry
        return dnsEntry

    def writeToDir(self):
        writeMapToDir(self.cacheDir, self.cacheMap)


class WhoisCache:
    def __init__(self, cacheDir=None):
        self.cacheDir=cacheDir
        self.cacheMap = {}

        if os.path.isdir(self.cacheDir):
            self.cacheMap = readMapFromDir(cacheDir) if cacheDir else {} 


    def lookup(self, ipString):
        if ipString in self.cacheMap:
            return self.cacheMap[ipString]

        rawWhois = getRawWhois(ipString)
        self.cacheMap[ipString] = rawWhois
        return rawWhois

    def writeToDir(self):
        writeMapToDir(self.cacheDir, self.cacheMap)


# produces a list of Targets from input file
def parseInput(inputLines, commentStart='#', rangeSeparator='-'):
    """
     tries to interpret the given string as IP address or range and process it accordingly
      1) a single IP address (e.g. 2.133.7.42 
      2) an IP range in CIDR notation (e.g. 66.7.83.0/24)
      3) an IP range in dash notation (e.g. 1.1.1.4 - 1.1.1.21)
         note: blocks in this notation will be spolit in appropriate blocks
         use this notation with care!
    """

    def _splitComment(line, commentStart=commentStart):
        components = line.split(commentStart, 1)
        if len(components) == 1:
            return (components[0].strip(), None)
        return (components[0].strip(), components[1].strip())

    def _parseTarget(targetDescription, comment):
         # first we try as single IP address
        try:
            return [TargetIP(ipaddress.ip_address(targetDescription), comment)]
        except ValueError:
            # not a valid IPv4 or IPv6 address
            pass

        # next we try as IP range in CIDR notation
        try:
            return [TargetIPRange(ipaddress.ip_network(targetDescription), comment)]
        except ValueError:
            # not a valid IPv4 or IPv6 network (in CIDR notation)
            pass

        # next we try as IP range in dash notation (1.1.1.1 - 1.1.1.42)
        parts = targetDescription.split(rangeSeparator)
        if len(parts) == 2:
            try:
                first = ipaddress.ip_address(parts[0].strip())
                last = ipaddress.ip_address(parts[1].strip())
                ipRanges = ipaddress.summarize_address_range(first, last)
                items = [TargetIPRange(r, comment) for r in ipRanges]
                return items
            except ValueError as e:
                # not a valid description of an IP range in dash notation
                pass

        if validators.domain(targetDescription):
            return [TargetDomain(targetDescription, comment)]

        return None

    inputItems = [] 
    for num, line in enumerate(inputLines):
        line = line.strip()
        if line.startswith(commentStart) or not line:
            continue

        (targetDescription, comment) = _splitComment(line)
        items = _parseTarget(targetDescription, comment)
        if not items:
            Logger.logWarning(f'Cannot parse line {num+1}: {line}')
            continue
        
        inputItems.extend(items)

    return inputItems


def groupByMatch(resultEntries, matchPhrases, infoPhrases, caseSensitiveMatch=True, caseSensitiveInfo=True):
    def _extractMatch(line, phrase, caseSensitive):
        matchLine = line if caseSensitive else line.lower()
        phrase = phrase if caseSensitive else phrase.lower()
            
        i = matchLine.find(phrase)
        if i == -1:
            return None
        preMatch = line[ : i]
        match = line[i : i + len(phrase)]
        postMatch = line[i + len(phrase) : ]
        return (preMatch, match, postMatch)
 
    matched = []
    unmatched = []
    
    
    matchPhrases = matchPhrases if caseSensitiveMatch else [p.lower() for p in matchPhrases]
    infoPhrases = infoPhrases if caseSensitiveInfo else [p.lower() for p in infoPhrases]
    for k, v in resultEntries.items():
        (resultItemList, rawWhois) = v
        matchWhois = rawWhois if caseSensitiveMatch else rawWhois.lower()
        infoWhois = rawWhois if caseSensitiveInfo else rawWhois.lower()

        mPhrases = [p for p in matchPhrases if p in matchWhois]
        iPhrases = [p for p in infoPhrases if p in infoWhois]

        group = WhoisGroup(k, resultItemList)

        if mPhrases:
            matched.append(group)
        else:
            unmatched.append(group)

        lineTexts = set() # for deduplication
        whoisLines = rawWhois.splitlines()
        for i, l in enumerate(whoisLines):
            for p in mPhrases:
                m = _extractMatch(l, p, caseSensitiveMatch)
                if m and not m in lineTexts:
                    (preMatch, match, postMatch) = m
                    group.addLine(preMatch, match, postMatch, i, WhoisLine.LINE_TAG_EVIDENCE)                
                    lineTexts.add(m)
                    break

            for p in iPhrases:
                m = _extractMatch(l, p, caseSensitiveInfo)
                if m and not m in lineTexts:
                    (preMatch, match, postMatch) = m
                    group.addLine(preMatch, match, postMatch, i, WhoisLine.LINE_TAG_INFO)                
                    lineTexts.add(m)
                    break
            
    return (matched, unmatched)


def formatGroups(groups, templateString, suppressWhois=False):
    groupStrings = [g.format(templateString, suppressWhoisLines=suppressWhois) for g in groups]
    return '\n'.join(groupStrings)

# TODO rework in seperate tool
#def formatGroupsLatex(groups, templateString):
#    latexString = [g.formatLatex(templateString) for g in groups]
#    return '\\begin{prettylisting}\n' + '\n'.join(latexString) + '\\end{prettylisting}' 
    

def printResults(matchedGroups, unmatchedGroups, templateString):
    matchedOutput = formatGroups(matchedGroups, templateString)
    unmatchedOutput = formatGroups(unmatchedGroups, templateString)

    separator = 64 * '#'
    print(f"{separator}\n# MATCHED\n{separator}")
    print(matchedOutput)

    print(f"{separator}\n# UNMATCHED\n{separator}")
    print(unmatchedOutput)


# writes only the IPs and range lines into give file (no lines from whis entries)
def exportRanges(groups, filePath, templateString):
    output = formatGroups(groups, templateString, True)
    with open(filePath, 'w') as outfile:
        outfile.write(output)

# export WhoisGroups as JSON
def exportJOSN(matched, unmatched, filePath):
    dictObj = {
        'matched' : [m.toDict() for m in matched],
        'unmatched' : [u.toDict() for u in unmatched]
    } 

    with open(filePath, 'w') as outfile:
        outfile.write(json.dumps(dictObj))


# TODO: import from JSON

def main():
    ap = argparse.ArgumentParser(formatter_class=argparse.RawTextHelpFormatter)
    ap.add_argument('-if', '--inputfile', type=str, required=True, help=(  
        'File containing IP ranges and/or domais (one entry per line)\n'
        'Comments (initiated by #) at end of line can be passed to output'
    ))

    ap.add_argument('-dc', '--dnscache', type=str, help=(
        'Directory to use for DNS cache'
    ))

    ap.add_argument('-wc', '--whoiscache', type=str, help=(
        'Directory to use for whois cache'
    ))

    ap.add_argument('-mp', '--match-phrases', type=str, help=(
        'File contining phrases that idenify matches in whois entries.\n'
        'One pharase is expected per line.\n'
        'Output will be goruped by matched and unmatched entries.\n'
    ))

    ap.add_argument('-ip', '--info-phrases', type=str, help=(
        'File contining phrases that idenify informational lines in whois entries.\n'
        'One pharase is expected per line.\n'
        'Has no impact on matches but informational lines appear in output.\n'
    ))

    ap.add_argument('-of', '--output-format', type=str, help=(
        'Specify the format of output lines.\n'
        'Blocks enclosed in {{...}} are left out if the placeholder inside is not defined.\n'
        'Possible Placeholders: __IP__, __DOMAIN__, __COMMENT\n'
        'Each block may only contain one placeholder.\n'
        'Example format strings:\n'
        '  "{{__IP__}} (__DOMAIN__) [__COMMENT__]]"\n'
        '    syss.de # some comment -> "37.202.2.212 (syss.de) [some comment]"\n'
        '  "{{Domain __DOMAIN__ resolves to }}{{__IP__}}"\n'
        '    syss.de # ignored comment -> "Domain syss.de resolves to 37.202.2.212"\n'
        '    8.8.8.8 -> "8.8.8.8"'
    ))

    ap.add_argument('-em', '--export-matched', type=str, help=(
        'Specify file to export the matched IPs and ranges (without the whois output lines)'
    ))
    
    ap.add_argument('-eu', '--export-unmatched', type=str, help=(
        'Specify file to export the unmatched IPs and ranges (without the whois output lines)'
    ))

    ap.add_argument('-ef', '--export-format', type=str, help=(
        'Specify the format for the exported IPs an ranges.\n'
        'For details see help for option --output-format.'
    ))
 
    ap.add_argument('-mic', '--match-ignore-case', action='store_true', help=(
        'Ignore case for match phrases in whois entries.'
    ))

    ap.add_argument('-iic', '--info-ignore-case', action='store_true', help=(
        'Ignore case for informational phrases in whois entries.'
    ))


    args = ap.parse_args()

    with open(args.inputfile, 'r') as inFile:
        inputLines = [l for l in inFile]

    matchPhrases = []
    if args.match_phrases:
        with open(args.match_phrases, 'r') as matchfile:
            matchPhrases = [l.strip() for l in matchfile] 

    infoPhrases = []
    if args.info_phrases:
        with open(args.info_phrases, 'r') as infofile:
            infoPhrases = [l.strip() for l in infofile]

    inputItems = parseInput(inputLines)

    whoisMap = {}
    strangeList = []
    whoisCache = WhoisCache('.whoiscache')
    dnsCache = DNSCache('.dnscache')

    for item in inputItems:
        item.doLookup(whoisMap, strangeList, dnsCache, whoisCache)

    dnsCache.writeToDir()
    whoisCache.writeToDir()

    (matched, unmatched) = groupByMatch(whoisMap, matchPhrases, infoPhrases, 
        caseSensitiveMatch=not args.match_ignore_case, caseSensitiveInfo=not args.info_ignore_case)

    # TODO remove
    for u in unmatched:
        s = u.toJSON()
        u2 = WhoisGroup.fromJSON(s)
        s2 = u2.toJSON()
        print('## origJSON:')
        print(s)
    
        print('## recovJSON:')
        print(s2)

    exportJOSN(matched, unmatched, 'out.json')

    exportTemplate = args.export_format if args.export_format else '{{__IP__}}{{ # (__DOMAIN__)}}{{ # [__COMMENT__]}}'
    if args.export_matched:
        exportRanges(matched, args.export_matched, exportTemplate)
    
    if args.export_unmatched:
        exportRanges(unmatched, args.export_matched, exportTemplate)
        
    outputTemplate = args.output_format if args.output_format else '{{__IP__}}{{ (__DOMAIN__)}}{{ [__COMMENT__]}}'
    printResults(matched, unmatched, outputTemplate)
    
    warnCnt = Logger.warnCnt
    if warnCnt > 0:
        print(f'There were {warnCnt} warnings. Go read them!')
    
if __name__ == '__main__':
    main()
