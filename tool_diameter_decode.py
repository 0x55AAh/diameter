#!/usr/bin/env python
"""
######################################################################
# Copyright (c) 2017, Sergej Srepfler <sergej.srepfler@gmail.com>
# January 2017 -
# Version 0.5.0, Last change on Feb 12, 2017
# This software is distributed under the terms of BSD license.
######################################################################
"""

# Decode diameter packet into individual AVPs

import binascii
import logging
import platform
import sys

import diameter

if __name__ == "__main__":
    # level for decoding are: DEBUG, INFO, WARNING, ERROR, CRITICAL
    # To log to a file, enable next line
    # logging.basicConfig(filename='log', level=logging.INFO)
    logging.basicConfig(level=logging.DEBUG)
    # diameter3.DEBUG=True
    baseDict = "dictionary.xml"
    os_ = platform.system()
    if os_ == 'Windows':
        basePath = "C:/Program Files/Wireshark/diameter"
    elif os_ == 'Linux':
        basePath = "/usr/share/wireshark/diameter"
    else:
        raise ValueError("OS not supported")
    xml = diameter.load_wireshark_dict(basePath, baseDict)
    dictionary = diameter.Dictionary(diameter.parse_xml(xml))
    ############################
    msg = sys.argv[1].rstrip()
    if msg[:2] == '0x':
        msg = msg[2:]
    print("RAW:", msg)
    # Decoding is needed here because we are receiving it hex-encoded :-)
    rawdata = binascii.unhexlify(msg)
    print("=" * 30)
    dmsg = diameter.Message(dictionary)
    dmsg.decode(rawdata)
    ############################
    # print H.Flags, H.Code
    cmd = dictionary.command_name(dmsg.hdr.flags, dmsg.hdr.code, dmsg.hdr.appid)
    print(cmd, dmsg.hdr.code)
    print("Hop-by-Hop=", dmsg.hdr.hopbyhop,
          "End-to-End=", dmsg.hdr.endtoend,
          "ApplicationId=", dmsg.hdr.appid)
    # Now we need to split message into raw AVPs (undecoded)
    # Not normally done, but for testing/understanding...
    rawavps = diameter.split_avps(dmsg.hdr.msg)
    # And use enumerate to get pairs index, value, so I can pair up wit RAW avps.
    for i, avp in enumerate(dmsg.avps):
        print("RAW AVP", binascii.hexlify(rawavps[i]))
        print("Decoded AVP", avp)
    print("-" * 30)

######################################################
# History
######################################################
# 0.1   - Feb 06 '12 - initial version
# 0.2.2 - Feb 23 '12 - Testing client AKA/AKA'
# 0.3.2 - Nov 20 '12 - dictionary search now done by dictionary
#                    - in/out is now RAW, NOT uuencoded
# 0.3.4 - Nov 25 '12 - code speed-up & reformat
# 0.3.5 - Dec 19 '12 - dictionary functions changed
# 0.4.0 - Oct 14 '13 - allowing 0x in front of string    
# 0.4.7 - Oct 16 '14 - prepared for debugging internals
# 0.5.0 - Feb 12 '17 - adapted for py2/py3 and new diameter library
