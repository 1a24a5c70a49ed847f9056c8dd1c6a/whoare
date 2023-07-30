#!/usr/bin/python3
import os
import sys
sys.path.append(os.path.join(os.path.dirname(__file__), '..'))

from whoare import Target, TargetIP, TargetIPRange, TargetDomain
from whoare import ResultItem

def _targetEquals(t1, t2):
    if not type(t1) == type(t2):
        return False
    return t1.targetDescription == t2.targetDescription and t1.comment == t2.comment

def testJSONConversion():
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


    ri = ResultItem(TargetDomain('www.google.com', 'testcomment'), '1.2.3.4.', 'www.google.com')
    print(ri.toJSON())
    print('testJSONConversion: SUCCESS')
    


def main():
    testJSONConversion()
    

if __name__ == '__main__':
    main()
