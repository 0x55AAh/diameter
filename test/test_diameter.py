#!/usr/bin/env python
"""
######################################################################
# Copyright (c) 2017, Sergej Srepfler <sergej.srepfler@gmail.com>
# January 2017 -
# Version 0.5.0, Last change on Feb 08, 2017
# This software is distributed under the terms of BSD license.
######################################################################
"""

# http://www.drdobbs.com/testing/unit-testing-with-python/240165163?pgno=1

import binascii
import logging
import platform
import socket
# Unit Tests for automated verification
import sys
import unittest

# Next line includes parent directory where the library is
sys.path.append('..')
# Remove it if everything is in the same directory

import diameter


#######################################

class Dictionary(unittest.TestCase):
    def testAVPCodeNameBase(self):
        C = dictionary.avp_by_name('Framed-IPv6-Prefix')
        self.assertEqual(C.name, 'Framed-IPv6-Prefix')
        N = dictionary.avp_by_code(C.code, C.vendorcode)
        self.assertEqual(C, N)
        C = dictionary.avp_by_name('Framed-IPv6-Prefix', 'None')
        self.assertEqual(C, N)

    # def testAVPCodeVendorBase(self):
    #     C = dictionary.avp_by_name('Value-Digits')
    #     self.assertEqual(C.name, 'Value-Digits')
    #     N = dictionary.avp_by_code(C.code, C.vendorcode)
    #     self.assertEqual(C, N)
    #     C = dictionary.avp_by_name('Value-Digits', 'Ericsson')
    #     self.assertNotEqual(C, N)

    def testAVPCodeNameVendor(self):
        C = dictionary.avp_by_name('Radio-Access-Technology')
        self.assertEqual(C.name, 'Radio-Access-Technology')
        N = dictionary.avp_by_code(C.code, C.vendorcode)
        self.assertEqual(C, N)
        C = dictionary.avp_by_name('Radio-Access-Technology', 'Vodafone')
        self.assertEqual(C, N)

    def testCMD(self):
        name = dictionary.command_name(0, 265, 16777272)
        self.assertEqual(name, 'AA Answer')
        code = dictionary.command_code('AA')
        self.assertEqual(name, 'AA Answer')


class EncDec(unittest.TestCase):
    def testEnumerated(self):
        C = dictionary.avp_by_name('Service-Type')
        enc1 = diameter.encode_avp(dictionary, C, u'Framed')
        enc2 = diameter.encode_avp(dictionary, C, 'Framed')
        enc3 = diameter.encode_avp(dictionary, C, '2')
        enc4 = diameter.encode_avp(dictionary, C, 2)
        self.assertEqual(enc1, binascii.unhexlify('000000064000000c00000002'))
        self.assertEqual(enc1, enc2)
        self.assertEqual(enc1, enc3)
        self.assertEqual(enc1, enc4)
        dec = diameter.decode_avp(dictionary, enc1)
        self.assertEqual(dec, ('Service-Type', 'None', 2))

    def testInt32(self):
        C = dictionary.avp_by_name('Acct-Input-Packets')
        enc = diameter.encode_avp(dictionary, C, 1)
        self.assertEqual(enc, binascii.unhexlify('0000002f0000000c00000001'))
        dec = diameter.decode_avp(dictionary, enc)
        self.assertEqual(dec, (u'Acct-Input-Packets', 'None', 1))
        # Negative
        C = dictionary.avp_by_name('Number-Of-Participants')
        enc = diameter.encode_avp(dictionary, C, -1)
        self.assertEqual(enc, binascii.unhexlify('00000375c0000010000028afffffffff'))
        dec = diameter.decode_avp(dictionary, enc)
        self.assertEqual(dec, (u'Number-Of-Participants', 'TGPP', -1))

    def testInt64(self):
        C = dictionary.avp_by_name('Value-Digits')
        enc = diameter.encode_avp(dictionary, C, 12345)
        self.assertEqual(enc, binascii.unhexlify('000001bf400000100000000000003039'))
        dec = diameter.decode_avp(dictionary, enc)
        self.assertEqual(dec, (u'Value-Digits', 'None', 12345))
        # Negative
        enc = diameter.encode_avp(dictionary, C, -1)
        self.assertEqual(enc, binascii.unhexlify('000001bf40000010ffffffffffffffff'))
        dec = diameter.decode_avp(dictionary, enc)
        self.assertEqual(dec, (u'Value-Digits', 'None', -1))

    def testU32(self):
        C = dictionary.avp_by_name('NAS-Port')
        enc = diameter.encode_avp(dictionary, C, 2345)
        self.assertEqual(enc, binascii.unhexlify('000000054000000c00000929'))
        dec = diameter.decode_avp(dictionary, enc)
        self.assertEqual(dec, (u'NAS-Port', 'None', 2345))

    #
    def testU64(self):
        C = dictionary.avp_by_name('Framed-Interface-Id')
        enc = diameter.encode_avp(dictionary, C, 12345)
        self.assertEqual(enc, binascii.unhexlify('00000060400000100000000000003039'))
        dec = diameter.decode_avp(dictionary, enc)
        self.assertEqual(dec, (u'Framed-Interface-Id', 'None', 12345))

    def testF32(self):
        C = dictionary.avp_by_name('Token-Rate')
        enc = diameter.encode_avp(dictionary, C, 12.34)
        self.assertEqual(enc, binascii.unhexlify('000001f00000000c414570a4'))
        dec = diameter.decode_avp(dictionary, enc)
        self.assertEqual(dec, ('Token-Rate', 'None', 12.34000015258789))

    def testF64(self):
        C = dictionary.avp_by_name('Cost')
        enc = diameter.encode_avp(dictionary, C, 12.34)
        self.assertEqual(enc, binascii.unhexlify('0000025bc0000014000000c14028ae147ae147ae'))
        dec = diameter.decode_avp(dictionary, enc)
        self.assertEqual(dec, ('Cost', 'Ericsson', 12.34))

    def testOctetString(self):
        C = dictionary.avp_by_name('User-Password')
        enc = diameter.encode_avp(dictionary, C, b'teststr')
        self.assertEqual(enc, binascii.unhexlify('000000024000000f7465737473747200'))
        dec = diameter.decode_avp(dictionary, enc)
        self.assertEqual(dec, ('User-Password', 'None', b'teststr'))
        # Must not fail if not byte string
        enc = diameter.encode_avp(dictionary, C, 'teststr')
        self.assertEqual(enc, binascii.unhexlify('000000024000000f7465737473747200'))

    def testUtf8(self):
        C = dictionary.avp_by_name('User-Name')
        # 70 69 3a 20 cf 80
        textUTF8 = u'pi: \u03c0'
        enc = diameter.encode_avp(dictionary, C, textUTF8)
        self.assertEqual(enc, binascii.unhexlify('000000014000000e70693a20cf800000'))
        dec = diameter.decode_avp(dictionary, enc)
        self.assertEqual(dec, ('User-Name', 'None', textUTF8))
        # Must not fail if byte string
        enc = diameter.encode_avp(dictionary, C, b'teststr')
        self.assertEqual(enc, binascii.unhexlify('000000014000000f7465737473747200'))

    def testTime(self):
        C = dictionary.avp_by_name('Event-Timestamp')
        unixtime = diameter.date2epoch(2012, 11, 17, 10, 30, 00)
        enc = diameter.encode_avp(dictionary, C, unixtime)
        self.assertEqual(enc, binascii.unhexlify('000000374000000cd451ad68'))
        dec = diameter.decode_avp(dictionary, enc)
        self.assertEqual(dec, ('Event-Timestamp', 'None', unixtime))

    def testIPAddressv4(self):
        # (IPAddress)
        C = dictionary.avp_by_name('Framed-IP-Address')
        enc = diameter.encode_avp(dictionary, C, '172.30.211.2')
        self.assertEqual(enc, binascii.unhexlify('000000084000000cac1ed302'))
        dec = diameter.decode_avp(dictionary, enc)
        self.assertEqual(dec, ('Framed-IP-Address', 'None', '172.30.211.2'))
        # also with vendor
        C = dictionary.avp_by_name('3GPP-SGSN-Address')
        enc = diameter.encode_avp(dictionary, C, '1.2.3.4')
        self.assertEqual(enc, binascii.unhexlify('00000006c0000010000028af01020304'))
        dec = diameter.decode_avp(dictionary, enc)
        self.assertEqual(dec, ('3GPP-SGSN-Address', 'TGPP', '1.2.3.4'))

    def testIPAddressv6(self):
        # (IPAddress)
        C = dictionary.avp_by_name('Framed-IP-Address')
        enc = diameter.encode_avp(dictionary, C, '::ffff:d9c8:4cca')
        self.assertEqual(enc, binascii.unhexlify('000000084000001800000000000000000000ffffd9c84cca'))
        dec = diameter.decode_avp(dictionary, enc)
        self.assertEqual(dec, ('Framed-IP-Address', 'None', '::ffff:d9c8:4cca'))

    def testIPv6Prefix(self):
        C = dictionary.avp_by_name('Framed-IPv6-Prefix')
        enc = diameter.encode_avp(dictionary, C, diameter.encode_ipv6prefix('21DA:D3:0:2F3B::/64'))
        self.assertEqual(enc, binascii.unhexlify('000000614000001a004021da00d300002f3b00000000000000000000'))
        dec = diameter.decode_avp(dictionary, enc)
        # We need to restore it to original prefix, so we can compare
        restored = (dec[0], dec[1], diameter.decode_ipv6prefix(dec[2]))
        self.assertEqual(restored, ('Framed-IPv6-Prefix', 'None', '21DA:D3:0:2F3B::/64'.lower()))
        dec = diameter.decode_avp(dictionary, binascii.unhexlify('000000614000000b00010000'))
        restored = (dec[0], dec[1], diameter.decode_ipv6prefix(dec[2]))
        self.assertEqual(restored, ('Framed-IPv6-Prefix', 'None', '0::/1'))

    def testFlags(self):
        # mandatory already set
        C = dictionary.avp_by_name('CC-Request-Number')
        encM = diameter.encode_avp(dictionary, C, 5)
        C.mandatory = 'may'
        C.protected = 'must'
        encP = diameter.encode_avp(dictionary, C, 5)
        C.protected = 'may'
        encO = diameter.encode_avp(dictionary, C, 5)
        C.protected = 'must'
        C.mandatory = 'must'
        encPM = diameter.encode_avp(dictionary, C, 5)
        self.assertEqual(encO, binascii.unhexlify('0000019f0000000c00000005'))
        self.assertEqual(encP, binascii.unhexlify('0000019f2000000c00000005'))
        self.assertEqual(encM, binascii.unhexlify('0000019f4000000c00000005'))
        self.assertEqual(encPM, binascii.unhexlify('0000019f6000000c00000005'))
        decO = diameter.decode_avp(dictionary, encO)
        decP = diameter.decode_avp(dictionary, encP)
        decM = diameter.decode_avp(dictionary, encM)
        decPM = diameter.decode_avp(dictionary, encPM)
        self.assertEqual(decO, ('CC-Request-Number', 'None', 5))
        self.assertEqual(decP, ('CC-Request-Number', 'None', 5))
        self.assertEqual(decM, ('CC-Request-Number', 'None', 5))
        self.assertEqual(decPM, ('CC-Request-Number', 'None', 5))

    def testNotInDict(self):
        # (Default to OctetString)
        enc = binascii.unhexlify('0FF000024000000f7465737473747200')
        dec = diameter.decode_avp(dictionary, enc)
        self.assertEqual(dec, ('Unknown_AVP_0_267386882', 'None', b'teststr'))
        C = dictionary.avp_by_name('Unknown_AVP_0_267386882')
        enc1 = diameter.encode_avp(dictionary, C, 'teststr')
        self.assertEqual(bytearray(enc), enc1)


class EncodeDecodeGrouped(unittest.TestCase):
    def eAVP(self, avpname, value):
        C = dictionary.avp_by_name(avpname)
        return diameter.encode_avp(dictionary, C, value)

    def testGrouped(self):
        enc = self.eAVP('Non-3GPP-User-Data', [
            self.eAVP('Subscription-Id', [
                self.eAVP('Subscription-Id-Data', '123456789'),
                self.eAVP('Subscription-Id-Type', 0)]),
            self.eAVP('Non-3GPP-IP-Access', 0),
            self.eAVP('Non-3GPP-IP-Access-APN', 0),
            self.eAVP('MIP6-Feature-Vector', 1),
            self.eAVP('APN-Configuration', [
                self.eAVP('Context-Identifier', 1),
                self.eAVP('Service-Selection', 'a1'),
                self.eAVP('PDN-Type', 0),
                self.eAVP('AMBR', [
                    self.eAVP('Max-Requested-Bandwidth-UL', 500),
                    self.eAVP('Max-Requested-Bandwidth-DL', 500)]),
                self.eAVP('EPS-Subscribed-QoS-Profile', [
                    self.eAVP('QoS-Class-Identifier', 1),
                    self.eAVP('Allocation-Retention-Priority', [
                        self.eAVP('Priority-Level', 0)])])]),
            self.eAVP('Context-Identifier', 0)])
        raw = binascii.unhexlify(
            '000005dc80000110000028af000001bb40000028000001bc400000113132333435'
            '36373839000000000001c24000000c00000000000005dd80000010000028af0000'
            '0000000005de80000010000028af000000000000007c0000001000000000000000'
            '0100000596c000009c000028af0000058fc0000010000028af00000001000001ed'
            '4000000a61310000000005b0c0000010000028af000000000000059bc000002c00'
            '0028af00000204c0000010000028af000001f400000203c0000010000028af0000'
            '01f400000597c0000038000028af00000404c0000010000028af00000001000004'
            '0ac000001c000028af00000416c0000010000028af000000000000058fc0000010'
            '000028af00000000')
        self.assertEqual(enc, raw)
        dec = diameter.decode_avp(dictionary, enc)
        do = ('Non-3GPP-User-Data', 'TGPP', [
            ('Subscription-Id', 'None', [
                ('Subscription-Id-Data', 'None', '123456789'),
                ('Subscription-Id-Type', 'None', 0)]),
            ('Non-3GPP-IP-Access', 'TGPP', 0),
            ('Non-3GPP-IP-Access-APN', 'TGPP', 0),
            ('MIP6-Feature-Vector', 'None', 1),
            ('APN-Configuration', 'TGPP', [
                ('Context-Identifier', 'TGPP', 1),
                ('Service-Selection', 'None', 'a1'),
                ('PDN-Type', 'TGPP', 0),
                ('AMBR', 'TGPP', [
                    ('Max-Requested-Bandwidth-UL', 'TGPP', 500),
                    ('Max-Requested-Bandwidth-DL', 'TGPP', 500)]),
                ('EPS-Subscribed-QoS-Profile', 'TGPP', [
                    ('QoS-Class-Identifier', 'TGPP', 1),
                    ('Allocation-Retention-Priority', 'TGPP', [
                        ('Priority-Level', 'TGPP', 0)])])]),
            ('Context-Identifier', 'TGPP', 0)])
        self.maxDiff = None
        self.assertEqual(dec, do)


class InetProto(unittest.TestCase):
    def ComparePrefix(self, IPv6Prefix, EncodedStr):
        packed = diameter.encode_ipv6prefix(IPv6Prefix)
        self.assertEqual(packed, binascii.unhexlify(EncodedStr))
        decoded = diameter.decode_ipv6prefix(binascii.unhexlify(EncodedStr))
        self.assertEqual(IPv6Prefix.lower(), decoded)

    def testIPv6Prefix(self):
        # IETF recommendations suggest the use of lower case letters, test for case-insensitive
        self.ComparePrefix('21DA:D3:0:2F3B::/64', b'004021da00d300002f3b0000000000000000')
        self.ComparePrefix('21DA:D3:0:0:2F3B::/64', b'004021da00d3000000002f3b000000000000')
        self.ComparePrefix('0:0:21DA:D3:0:2F3B::/64', b'00400000000021da00d300002f3b00000000')
        self.ComparePrefix('::1/128', b'008000000000000000000000000000000001')
        self.ComparePrefix('2001:db8::ff00:42:8329/128', b'008020010db8000000000000ff0000428329')
        self.ComparePrefix('2001:db8:8714:3a90::12/128', b'008020010db887143a900000000000000012')
        self.ComparePrefix('2001:0:0:3a90::12/128', b'00802001000000003a900000000000000012')

    def testIPv4(self):
        a1 = diameter.inet_pton(socket.AF_INET, '0.0.0.0')
        self.assertEqual(a1, binascii.unhexlify('00000000'))
        a2 = diameter.inet_ntop(socket.AF_INET, a1)
        self.assertEqual(a2, '0.0.0.0')
        #
        a1 = diameter.inet_pton(socket.AF_INET, '1.2.3.4')
        self.assertEqual(a1, binascii.unhexlify('01020304'))
        a2 = diameter.inet_ntop(socket.AF_INET, a1)
        self.assertEqual(a2, '1.2.3.4')
        #
        a1 = diameter.inet_pton(socket.AF_INET, '255.255.255.255')
        self.assertEqual(a1, binascii.unhexlify('ffffffff'))
        a2 = diameter.inet_ntop(socket.AF_INET, a1)
        self.assertEqual(a2, '255.255.255.255')

    def testIPv6(self):
        a1 = diameter.inet_pton(socket.AF_INET6, '2001:db8:8714:3a90::12')
        self.assertEqual(a1, binascii.unhexlify('20010db887143a900000000000000012'))
        a2 = diameter.inet_ntop(socket.AF_INET6, a1)
        self.assertEqual(a2, '2001:db8:8714:3a90::12')
        #
        a1 = diameter.inet_pton(socket.AF_INET6, '2001:db8:8714:3a90::1.2.3.4')
        self.assertEqual(a1, binascii.unhexlify('20010db887143a900000000001020304'))
        a2 = diameter.inet_ntop(socket.AF_INET6, a1)
        self.assertEqual(a2, '2001:db8:8714:3a90::102:304')


class Msg(unittest.TestCase):
    def testCreateMsg(self):
        # Let's build CER
        msg = diameter.Message(dictionary)
        msg.new('Capabilities-Exchange', 0)
        msg.encode('Acct-Input-Packets', 1)  # Int32
        msg.encode('Value-Digits', 12345)  # Int64
        msg.encode('NAS-Port', 2345)  # U32
        msg.encode('Framed-Interface-Id', 3456)  # U64
        msg.encode('Token-Rate', 1.1)  # F32
        msg.encode('Cost', 3.64)  # F64
        msg.encode('NAS-IP-Address', b'teststr')  # OctetString
        msg.encode('User-Name', '172.30.211.2')  # UTF8String
        # msg now contains CER Request    
        wireshark(msg.create_request())
        wireshark(msg.create_answer())

    def testDecodeMsg(self):
        rec = binascii.unhexlify(
            '010000a0800001010000000037e6070bcced55c000000108400000253030392d41'
            '2d6469616d726f757465722d312e737072696e742e636f6d000000000001284000'
            '0012737072696e742e636f6d00000000010a4000000c00006f2a0000010d000000'
            '0f4f6e652d41414100000001014000000e00010a0000010000000001094000000c'
            '000028af000001024000000cffffffff000001034000000cffffffff')
        wireshark(rec)
        msg = diameter.Message(dictionary)
        msg.decode(rec)
        self.assertEqual(len(msg.avps), 8)
        self.assertEqual(('Origin-Host', 'None', bytearray(b'009-A-diamrouter-1.sprint.com')), msg.avps[0])
        self.assertEqual(('Origin-Realm', 'None', bytearray(b'sprint.com')), msg.avps[1])
        self.assertEqual(('Vendor-Id', 'None', 28458), msg.avps[2])
        self.assertEqual(('Product-Name', 'None', 'One-AAA'), msg.avps[3])
        self.assertEqual(('Host-IP-Address', 'None', '10.0.0.1'), msg.avps[4])
        self.assertEqual(('Supported-Vendor-Id', 'None', 10415), msg.avps[5])
        if sys.version_info >= (2, 7, 12):
            self.assertEqual(('Auth-Application-Id', 'None', 4294967295), msg.avps[6])
            self.assertEqual(('Acct-Application-Id', 'None', 4294967295), msg.avps[7])
        else:
            self.assertEqual(('Auth-Application-Id', 'None', -1), msg.avps[6])
            self.assertEqual(('Acct-Application-Id', 'None', -1), msg.avps[7])


# Verify via wireshark
def wireshark(msg):
    # send data
    # print 'S', binascii.hexlify(msg), HOST
    Conn.sendto(msg, (HOST, PORT))


#######################################
#
#######################################

# Tests are executed in alphabetical order (after ClassNames)
# Usage: tests.py [options] [test] [...]
# Options:
#  -v, --verbose    Verbose output
#  -q, --quiet      Minimal output
#  -f, --failfast   Stop on first failure
#  -c, --catch      Catch control-C and display results
#  -b, --buffer     Buffer stdout and stderr during test runs
#
# Examples:
#  tests.py                               - run default set of tests
#  tests.py MyTestSuite                   - run suite 'MyTestSuite'
#  tests.py MyTestCase.testSomething      - run MyTestCase.testSomething
#  tests.py MyTestCase                    - run all 'test*' test methods in MyTestCase

if __name__ == '__main__':
    baseDict = 'dictionary.xml'
    os_ = platform.system()
    if os_ == 'Windows':
        basePath = 'C:/Program Files/Wireshark/diameter'
    elif os_ == 'Linux':
        basePath = '/usr/share/wireshark/diameter'
    else:
        raise ValueError("OS not supported")
    # level for decoding are: DEBUG, INFO, WARNING, ERROR, CRITICAL
    # To log to a file, enable next line
    # logging.basicConfig(filename='log', level=logging.INFO)
    logging.basicConfig(level=logging.DEBUG)
    # diameter.DEBUG=True
    xml = diameter.load_wireshark_dict(basePath, baseDict)
    dictionary = diameter.Dictionary(diameter.parse_xml(xml))
    # diameter.DEBUG=True
    #
    HOST = '192.168.0.1'
    PORT = 1111
    Conn = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    #
    unittest.main()

######################################################
# History
######################################################
# 0.5.0 - Jan 21 '17 - initial version
#       - Feb 07 '17 - work with py2/py3
