#!/usr/bin/env python
"""
######################################################################
# Copyright (c) 2017, Sergej Srepfler <sergej.srepfler@gmail.com>
# January 2017 -
# Version 0.5.0, Last change on Feb 12, 2017
# This software is distributed under the terms of BSD license.
######################################################################
"""

import logging
import platform
import sys

# Next line includes parent directory where the library is
sys.path.append("..")
# Remove it if everything is in the same directory

import diameter

SKIP = [
    'Unassigned',
    'Experimental-Use',
    'Implementation-Specific',
    'Reserved',
    'Unallocated',
    'Not defined in .xml'
]

#######################################

if __name__ == "__main__":
    baseDict = "dictionary.xml"
    os_ = platform.system()
    if os_ == 'Windows':
        basePath = "C:/Program Files/Wireshark/diameter"
    elif os_ == 'Linux':
        basePath = "/usr/share/wireshark/diameter"
    else:
        raise ValueError("OS not supported")
    # level for decoding are: DEBUG, INFO, WARNING, ERROR, CRITICAL
    # To log to a file, enable next line
    # logging.basicConfig(filename='log', level=logging.INFO)
    logging.basicConfig(level=logging.DEBUG)
    # libDict.DEBUG=True
    xml = diameter.load_wireshark_dict(basePath, baseDict)
    dict = diameter.parse_xml(xml)
    # Test duplicate names    
    allAVP = []
    for parent in dict:
        for child in parent.avp:
            allAVP.append((child.name, child))

    uniqueName = []
    uniqueCode = []
    for (name, AVP) in allAVP:
        if name in SKIP:
            continue
        if name not in uniqueName:
            uniqueName.append(name)
        else:
            print("DUPAVPname")
            for (oName, oAVP) in allAVP:
                if name == oName:
                    print(oName, oAVP.code, oAVP.vendorname)
            print('=' * 30)
        code = AVP.vendorcode * 10000 + AVP.code
        if code not in uniqueCode:
            uniqueCode.append(code)
        else:
            print("DUPAVPcode")
            for (oCode, oAVP) in allAVP:
                if code == oAVP.vendorcode * 10000 + oAVP.code:
                    print(oCode, oAVP.code, oAVP.vendorname)
            print('=' * 30)
    print('!' * 30)
    # Test duplicate command (AppId+Cmd)
    allCMD = []
    for parent in dict:
        for cmd in parent.command.keys():
            allCMD.append((int(cmd), parent.command[cmd], int(parent.code)))
    uniqueCMDN = []
    uniqueCMDC = []
    for (cCode, cName, cAp) in allCMD:
        if cName not in uniqueCMDN:
            uniqueCMDC.append(cName)
        else:
            print("DUPCMDname")
            for (oCode, oName, oAp) in allCMD:
                if cName == oName:
                    print(oName, oCode, oAp)
        code = cAp * 10000 + cCode
        if code not in uniqueCMDC:
            uniqueCMDC.append(code)
        else:
            print("DUPCMDcode")
            for (oCode, oName, oAp) in allCMD:
                if code == oAp * 10000 + oCode:
                    print(oName, oCode, oAp)
    print('!' * 30)
    dictionary = diameter.Dictionary(dict)
    for (cCode, cName, cAp) in allCMD:
        if cAp not in dictionary.app_dic.keys():
            print("Missing AppId", cCode, cName, cAp)
        else:
            if cCode not in dictionary.app_dic[cAp].command.keys():
                print("missing command", cCode, cName, cAp)
            else:
                if cName != dictionary.app_dic[cAp].command[cCode]:
                    print("different Name", cName)
    print('!' * 30)
