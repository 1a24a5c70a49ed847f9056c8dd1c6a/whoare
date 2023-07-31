#!/usr/bin/python3
import os
import sys
sys.path.append(os.path.join(os.path.dirname(__file__), '..'))

from whoare import Target, TargetIP, TargetIPRange, TargetDomain
from whoare import ResultItem
from whoare import WhoisLine
from whoare import WhoisGroup

def _targetEquals(t1, t2):
    if not type(t1) == type(t2):
        return False
    return t1.targetDescription == t2.targetDescription and t1.comment == t2.comment


def _resultItemEquals(r1, r2):
    if not type(r1) == type(r2):
        return False
    return  _targetEquals(r1.inputItem, r2.inputItem) \
        and r1.ip == r2.ip \
        and r1.domain == r2.domain

def _whoisLineEquals(w1, w2):
    if not type(w1) == type(w2):
        return False
    return  w1.preMatch == w2.preMatch \
        and w1.match == w2.match \
        and w1.postMatch == w2.postMatch \
        and w1.number == w2.number \
        and w1.tag == w2.tag \

def _whoisGroupEquals(g1, g2):
    if not type(g1) == type(g2):
        return False
    if not g1.whois == g2.whois:
        return False 

    if len(g1.resultList) != len(g2.resultList):
        return False
    for (a, b) in zip(g1.resultList, g2.resultList): 
        if not _resultItemEquals(a, b):
            return False

    if len(g1.whoisLines) != len(g2.whoisLines):
        return False
    for (a, b) in zip(g1.whoisLines, g2.whoisLines):
        if not _whoisLineEquals(a, b):
            return False

    return True

def testJSONConversion():
    # Target
    targets = []
    targets.append(TargetIP('1.2.3.44'))
    targets.append(TargetIP('1.2.3.44', None))
    targets.append(TargetIP('1.2.3.44', 'some comment'))
    targets.append(TargetIP('1.2.3.44', '42'))

    targets.append(TargetIPRange('2.3.4.5/22'))
    targets.append(TargetIPRange('2.3.4.5/22', None))
    targets.append(TargetIPRange('2.3.4.5/22', 'some comment'))
    targets.append(TargetIPRange('2.3.4.5/22', '42'))
    targets.append(TargetIPRange('2.3.4.5 - 2.3.4.77'))
    targets.append(TargetIPRange('2.3.4.5 - 2.3.4.77', None))
    targets.append(TargetIPRange('2.3.4.5 - 2.3.4.77', 'some comment'))
    targets.append(TargetIPRange('2.3.4.5 - 2.3.4.77', '42'))

    targets.append(TargetDomain('www.google.com'))
    targets.append(TargetDomain('www.google.com', None))
    targets.append(TargetDomain('www.google.com', 'some comment'))
    targets.append(TargetDomain('www.google.com', '42'))

    for t in targets:
        assert _targetEquals(t, Target.fromJSON(t.toJSON()))


    # ResultItem
    resultItems = []
    resultItems.append(ResultItem(TargetDomain('www.google.com'), '1.2.3.4.', 'www.google.com'))
    resultItems.append(ResultItem(TargetDomain('www.google.com', None), '1.2.3.4.', 'www.google.com'))
    resultItems.append(ResultItem(TargetDomain('www.google.com', 'testcomment'), '1.2.3.4.', 'www.google.com'))
    
    for r in resultItems:
        assert _resultItemEquals(r, ResultItem.fromJSON(r.toJSON()))
    
    
    # WhoisLine
    whoisLines = []
    whoisLines.append(WhoisLine('pre', 'match', 'post', 123, WhoisLine.LINE_TAG_EVIDENCE))
    whoisLines.append(WhoisLine('', 'match', 'post', 123, WhoisLine.LINE_TAG_EVIDENCE))
    whoisLines.append(WhoisLine('pre', 'match', '', 123, WhoisLine.LINE_TAG_EVIDENCE))
    whoisLines.append(WhoisLine('', 'match', '', 123, WhoisLine.LINE_TAG_EVIDENCE))
    whoisLines.append(WhoisLine('pre', 'match', 'post " match \'', 123, WhoisLine.LINE_TAG_EVIDENCE))
    whoisLines.append(WhoisLine('pre', 'match', 'post', 0, WhoisLine.LINE_TAG_INFO))

    for w in whoisLines:
        assert _whoisLineEquals(w, WhoisLine.fromJSON(w.toJSON()))


    dummyWhois = 'some\ndummy\nwhois\nentry 1337'
    dummyResults = resultItems
    dummyWhoisLines = whoisLines

    wg = WhoisGroup(dummyWhois, dummyResults, dummyWhoisLines)
    assert _whoisGroupEquals(wg, WhoisGroup.fromJSON(wg.toJSON()))
    
    print(f'testJSONConversion: SUCCESS')

def main():
    testJSONConversion()
    

if __name__ == '__main__':
    main()
