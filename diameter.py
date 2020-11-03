"""
######################################################################
# Copyright (c) 2017, Sergej Srepfler <sergej.srepfler@gmail.com>
# January 2017 -
# Version 0.5.0, Last change on Feb 12, 2017
# This software is distributed under the terms of BSD license.
######################################################################
"""
# All functions needed to build/decode diameter messages

import binascii
import logging
import os.path
import socket
import struct
import sys
import time
import xml.etree.ElementTree as ET

# Many thanks to Mike Driscoll for his explanation of XML parsing
# I easily figured it out after reading
# http://www.blog.pythonlibrary.org/2013/04/30/python-101-intro-to-xml-parsing-with-elementtree/

#######################################

DEBUG = False
ERROR = -1

VENDOR_DIC = {}

ZEROS = {1: b'\x00', 2: b'\x00\x00', 3: b'\x00\x00\x00'}

SECONDS_BETWEEN_1900_AND_1970 = ((70 * 365) + 17) * 86400

# Diameter Header fields
DIAMETER_FLAG_PROTECTED = 0x20
DIAMETER_FLAG_MANDATORY = 0x40
DIAMETER_FLAG_VENDOR = 0x80

DIAMETER_HDR_REQUEST = 0x80
DIAMETER_HDR_PROXIABLE = 0x40
DIAMETER_HDR_ERROR = 0x20
DIAMETER_HDR_RETRANSMIT = 0x10


#######################################

class DictItem:
    """Properties of each AVP in dictionary"""

    def __init__(self):
        self.code = 0
        self.name = ''
        self.vendorcode = 0
        self.vendorname = 'None'
        self.mandatory = 'may'
        self.protected = 'mustnot'
        self.vendor_bit = 'mustnot'
        self.may_encript = 'yes'
        self.type = ''
        self.enumvalues = {}
        self.grouped = []

    def _parse_type(self, parent):
        self.type = parent.attrib['type-name']

    def _parse_enum(self, parent):
        self.enumvalues[parent.attrib['name']] = parent.attrib['code']
        self.enumvalues[parent.attrib['code']] = parent.attrib['name']

    def _parse_grouped(self, parent):
        self.type = 'Grouped'
        for child in list(parent):
            self.grouped.append(child.attrib['name'])

    _parseAvp = {
        'type': _parse_type,
        'enum': _parse_enum,
        'grouped': _parse_grouped
    }

    def new(self, avpdef):
        """Copy values from tags"""
        if DEBUG:
            dbg = 'Adding AVP:', avpdef
            logging.debug(dbg)
        self.name = avpdef['name']
        self.code = avpdef['code']
        if 'vendor-id' in avpdef:
            self.vendorname = avpdef['vendor-id']
        if 'mandatory' in avpdef:
            self.mandatory = avpdef['mandatory']
        if 'protected' in avpdef:
            self.protected = avpdef['protected']
        if 'vendor-bit' in avpdef:
            self.vendor_bit = avpdef['vendor-bit']
        if 'may-encript' in avpdef:
            self.may_encript = avpdef['may-encript']

    def parse(self, child):
        """Parse tags by type"""
        self._parseAvp[child.tag](self, child)
        if DEBUG:
            dbg = 'Parsing AVP params:', child.tag, '=', child.attrib
            logging.debug(dbg)

    def enum_by_name(self, enumname):
        """Find enum value by name"""
        if DEBUG:
            dbg = 'Searching AVP (%s, %s) with enum %s' % (self.name, self.vendorname, enumname)
            logging.debug(dbg)
        if isinstance(enumname, int):
            return enumname
        if enumname.isdigit():
            return int(enumname)
        if DEBUG:
            dbg = 'Found enum types ', self.enumvalues[enumname], self.enumvalues
            logging.debug(dbg)
        return int(self.enumvalues[enumname])

    def enum_by_value(self, enumvalue):
        """Find enum value by code"""
        if DEBUG:
            dbg = 'Searching AVP (%s, %s) with enum %s' % (self.name, self.vendorname, enumvalue)
            logging.debug(dbg)
        if str(enumvalue) in self.enumvalues:
            return self.enumvalues[str(enumvalue)]
        else:
            return enumvalue


class BaseDict:
    """Properties of each dictionary item.
       Not use once dictionary is created"""

    def __init__(self, node):
        self.type = None
        self.code = 0
        self.name = None
        self.vendor_id = ''
        self.command = {}
        self.typedef = {}
        self.avp = []
        self._init_node(node)

    def _init_node(self, node):
        self.type = node.tag
        if self.type == 'vendor':
            self.code = node.attrib['code']
            self.name = node.attrib['name']
            self.vendor_id = node.attrib['vendor-id']
        elif self.type == 'application':
            self.code = node.attrib['id']
            self.name = node.attrib['name']

    def _parse_command(self, child):
        self.vendor_id = child.attrib['vendor-id']
        self.command[int(child.attrib['code'])] = child.attrib['name']

    def _parse_typedefn(self, child):
        if 'type-parent' in child.attrib:
            self.typedef[child.attrib['type-name']] = child.attrib['type-parent']
        else:
            self.typedef[child.attrib['type-name']] = child.attrib['type-name']

    def _parse_avp(self, child):
        newavp = DictItem()
        newavp.new(child.attrib)
        for leaf in list(child):
            newavp.parse(leaf)
        self.avp.append(newavp)

    def _parse_vendor(self, child):
        global VENDOR_DIC
        VENDOR_DIC[child.attrib['vendor-id']] = child.attrib['code']

    _parseDict = {
        'command': _parse_command,
        'typedefn': _parse_typedefn,
        'avp': _parse_avp,
        'vendor': _parse_vendor
    }

    def parse(self, child):
        """Parse dictionary by type"""
        if DEBUG:
            dbg = 'Parsing:', child.tag, '=', child.attrib
            logging.debug(dbg)
        self._parseDict[child.tag](self, child)


#######################################

def parse_xml(xmllist):
    """Parse loaded XML into dictionary (BaseDict)"""
    root = ET.fromstring(''.join(xmllist))
    dictionary = []
    global VENDOR_DIC
    VENDOR_DIC = {'None': '0'}
    for node in list(root):
        if DEBUG:
            dbg = 'New Dict:', node.tag, '=', node.attrib
            logging.debug(dbg)
        _dict = BaseDict(node)
        if _dict.type == 'vendor':
            VENDOR_DIC[node.attrib['vendor-id']] = node.attrib['code']
        for child in list(node):
            _dict.parse(child)
        dictionary.append(_dict)
    # Second pass to assign vendorcode
    for parent in dictionary:
        for avp in parent.avp:
            avp.vendorcode = VENDOR_DIC[avp.vendorname]
    return dictionary


def load_dict(path, filename):
    fname = '%s/%s' % (path, filename)
    if DEBUG:
        dbg = 'Loading file:', fname
        logging.debug(dbg)
    if os.path.isfile(fname):
        with open(fname) as fhandle:
            return fhandle.readlines()
    if DEBUG:
        dbg = 'File %s does not exist:' % fname
        logging.debug(dbg)
    return []


def load_wireshark_dict(basepath, basedict):
    xml = load_dict(basepath, basedict)
    # Find lines containing & (ampersand) and include them
    while True:
        include = next((x for x in xml if '&' in x), None)
        if include is None:
            break
        filename = include[int(include.find('&') + 1):int(include.find(';'))]
        xml1 = []
        # Loading Custom dictionary not supported yet
        # (e.g. on Linux it would have multiple dictionary sections which parser
        # could not parse)
        if filename != 'Custom':
            xml1 = load_dict(basepath, filename + '.xml')
            # We need to remove xml header for include file
            xmlhdr = next((x for x in xml1 if 'xml' in x), None)
            if xmlhdr is not None:
                del xml1[xml1.index(xmlhdr)]
            xml1.append('<!-- End %s  -->\n' % filename)
        # Find line where we should replace it with a list
        pos = xml.index(include)
        # Replace include file line
        xml[pos] = '<!-- Start including %s -->\n' % filename
        # Use list slicing to insert list into list
        xml[pos + 1:pos + 1] = xml1
    return xml


#######################################

class AppDict:
    """Each application contains it own dictionary"""

    def __init__(self, parent):
        self.code = int(parent.code)
        self.name = parent.name
        self.command = {}

    def update_command(self, parent):
        """Commands defined for Application"""
        self.command.update(parent.command)

    def find(self, codename):
        """Find Command definition in dictionary: CE->257"""
        for key, value in self.command.items():
            if value == codename:
                return key
        dbg = 'Unable to find CMD', codename
        _bail_out(dbg)


class Dictionary:
    """Main dictionary class"""

    def __init__(self, dictionary):
        self.avp_dic = {}
        self.app_dic = {}
        self.type_dic = {
            'OctetString': 'OctetString',
            'UTF8String': 'UTF8String',
            'Integer32': 'Integer32',
            'Unsigned32': 'Unsigned32',
            'Integer64': 'Integer64',
            'Unsigned64': 'Unsigned64',
            'Float32': 'Float32',
            'Float64': 'Float64',
            'IPAddress': 'IPAddress',
            'Time': 'Time',
            'Enumerated': 'Enumerated',
            'Grouped': 'Grouped'
        }

        self._optimize_application(dictionary)
        self._optimize_typedef(dictionary)
        self._optimize_dictionary(dictionary)

    def _optimize_application(self, dictionary):
        self.app_dic = {}
        for parent in dictionary:
            if int(parent.code) not in self.app_dic:
                if DEBUG:
                    dbg = 'New app_dic:', parent.name, '=', parent.code, parent.command
                    # , '=', parent.code.attrib
                    logging.debug(dbg)
                newapp = AppDict(parent)
                self.app_dic[newapp.code] = newapp
            self.app_dic[int(parent.code)].update_command(parent)

    def _optimize_typedef(self, dictionary):
        for parent in dictionary:
            self.type_dic.update(parent.typedef)
        # Restore additional implemented types
        self.type_dic.update({'IPAddress': 'IPAddress'})
        self.type_dic.update({'UTF8String': 'UTF8String'})
        self.type_dic.update({'Enumerated': 'Enumerated'})
        self.type_dic.update({'Grouped': 'Grouped'})

    def _optimize_dictionary(self, dictionary):
        self.avp_dic = {}
        for parent in dictionary:
            for child in parent.avp:
                newavp = DictItem()
                newavp.code = int(child.code)
                newavp.name = child.name
                newavp.vendorcode = int(child.vendorcode)
                newavp.vendorname = child.vendorname
                newavp.mandatory = child.mandatory
                newavp.protected = child.protected
                newavp.vendor_bit = child.vendor_bit
                newavp.may_encript = child.may_encript
                newavp.type = child.type
                newavp.enumvalues.update(child.enumvalues)
                newavp.grouped.extend(child.grouped)
                self.avp_dic[(child.name, child.vendorname)] = newavp
                self.avp_dic[(int(child.code), int(child.vendorcode))] = newavp

    def avp_by_name(self, avpname, vendorname='None'):
        """Find AVP definition by name (vendor optional)"""
        if DEBUG:
            dbg = 'Searching for AVP (%s, %s)' % (avpname, vendorname)
            logging.debug(dbg)
        if (avpname, vendorname) in self.avp_dic.keys():
            return self.avp_dic[(avpname, vendorname)]
        else:
            for vendor in VENDOR_DIC:
                if (avpname, vendor) in self.avp_dic:
                    return self.avp_dic[(avpname, vendor)]
        dbg = 'Unable to find AVP', avpname, vendorname
        _bail_out(dbg)

    def avp_by_code(self, avpcode, vendorcode, flags=0):
        """Find AVP definition by code+vendor"""
        if DEBUG:
            dbg = 'Searching for AVP (%s, %s)' % (avpcode, vendorcode)
            logging.debug(dbg)
        if (avpcode, vendorcode) in self.avp_dic:
            return self.avp_dic[(avpcode, vendorcode)]
        else:
            for vendor in VENDOR_DIC.values():
                if (avpcode, int(vendor)) in self.avp_dic:
                    return self.avp_dic[(avpcode, int(vendor))]
        # dbg = 'Unable to find AVP', avpcode, vendorcode
        # _bail_out(dbg)
        # Allow decoding undefined AVPs as OctetString
        newavp = DictItem()
        newavp.code = avpcode
        newavp.name = 'Unknown_AVP_' + str(vendorcode) + '_' + str(avpcode)
        newavp.vendorcode = vendorcode
        newavp.vendorname = None
        for vname in VENDOR_DIC:
            if str(vendorcode) == VENDOR_DIC[vname]:
                newavp.vendorname = vname
        if newavp.vendorname is None:
            newavp.vendorname = 'Unknown_' + str(vendorcode)
            VENDOR_DIC[newavp.vendorname] = str(vendorcode)
        newavp.type = 'OctetString'
        if flags & DIAMETER_FLAG_MANDATORY:
            newavp.mandatory = 'must'
        if flags & DIAMETER_FLAG_PROTECTED:
            newavp.protected = 'must'
        if flags & DIAMETER_FLAG_VENDOR:
            newavp.vendor_bit = 'must'
        self.avp_dic[(avpcode, vendorcode)] = newavp
        self.avp_dic[(newavp.name, newavp.vendorname)] = newavp
        return newavp

    def command_name(self, flags, code, appid=0):
        """Find Command definition in dictionary: 257->Capability-Exchange"""
        name = None
        if code in self.app_dic[appid].command:
            name = self.app_dic[appid].command[code]
        else:
            for key in self.app_dic:
                if code in self.app_dic[key].command:
                    name = self.app_dic[key].command[code]
        if name is None:
            dbg = 'Unable to find CMD', code, appid
            _bail_out(dbg)
        if flags & DIAMETER_HDR_REQUEST == DIAMETER_HDR_REQUEST:
            ret = name + ' Request'
        else:
            ret = name + ' Answer'
        return ret

    def command_code(self, codename, appid=0):
        """Find Command definition in dictionary: Capability-Exchange->257"""
        if DEBUG:
            dbg = 'Searching for CMD (%s, %s)' % (codename, appid)
            logging.debug(dbg)
        code = None
        if codename in self.app_dic[appid].command.values():
            return self.app_dic[appid].find(codename)
        else:
            for key in self.app_dic:
                if codename in self.app_dic[key].command.values():
                    return self.app_dic[key].find(codename)
        if code is None:
            dbg = 'Unable to find CMD', codename, appid
            _bail_out(dbg)

#######################################


def _bail_out(msg):
    """Quit program with error"""
    if DEBUG:
        logging.error(msg)
    raise Exception(msg)


#######################################
#   AVP (typical)
#    0                   1                   2                   3
#    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
#   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#   |                           AVP Code                            |
#   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#   |V M P r r r r r|                  AVP Length                   |
#   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#   |                        Vendor-ID (opt)                        |
#   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#   |    Data ...
#   +-+-+-+-+-+-+-+-+

def encode_avp(dictionary, avp, value, flags=0):
    """Main encoding routine for single AVP"""

    def _encode_octetstring(value):
        if isinstance(value, str):
            if sys.version_info >= (3, 0):
                ret = bytearray(bytes(value, 'utf-8'))
            else:
                ret = bytearray(value)
        else:
            ret = bytearray(value)
        return ret, len(ret)

    def _encode_utf8string(value):
        if isinstance(value, str):
            ret = bytearray(value, 'utf-8')
        else:
            if sys.version_info >= (3, 0):
                ret = bytearray(value)
            else:
                ret = bytearray(value, 'utf-8')
        return ret, len(ret)

    def _encode_enumerated(value):
        return bytearray(struct.pack('!i', avp.enum_by_name(value))), 4

    def _encode_integer32(value):
        return bytearray(struct.pack('!i', value)), 4

    def _encode_unsigned32(value):
        return bytearray(struct.pack('!I', value)), 4

    def _encode_integer64(value):
        return bytearray(struct.pack('!q', value)), 8

    def _encode_unsigned64(value):
        return bytearray(struct.pack('!Q', value)), 8

    def _encode_float32(value):
        return bytearray(struct.pack('!f', value)), 4

    def _encode_float64(value):
        return bytearray(struct.pack('!d', value)), 8

    def _encode_ipaddress(value):
        ret = pack_address(value)[2:]
        return bytearray(ret), len(ret)

    def _encode_time(value):
        """AVP_Time contains a second count since 1900
        But unix counts time from EPOCH (1.1.1970)"""
        return _encode_unsigned32(int(value) + SECONDS_BETWEEN_1900_AND_1970)

    def _encode_grouped(value):
        ret = bytearray('', 'utf-8')
        for item in value:
            ret.extend(item)
        return ret, len(ret)

    _encode_avp = {
        'OctetString': _encode_octetstring,
        'UTF8String': _encode_utf8string,
        'Integer32': _encode_integer32,
        'Unsigned32': _encode_unsigned32,
        'Integer64': _encode_integer64,
        'Unsigned64': _encode_unsigned64,
        'Float32': _encode_float32,
        'Float64': _encode_float64,
        'IPAddress': _encode_ipaddress,
        'Time': _encode_time,
        'Enumerated': _encode_enumerated,
        'Grouped': _encode_grouped
    }

    def _add_padding(ret):
        """Align AVP to a 4-byte boundary"""
        padsize = _calc_padding(len(ret)) - len(ret)
        if padsize != 0:
            ret.extend(ZEROS[padsize])
        return ret

    if DEBUG:
        dbg = 'Encoding type', avp.type, dictionary.type_dic[avp.type]
        logging.debug(dbg)
    data, pktlen = _encode_avp[dictionary.type_dic[avp.type]](value)
    ret = bytearray()
    if avp.mandatory == 'must':
        flags |= DIAMETER_FLAG_MANDATORY
    if avp.protected == 'must':
        flags |= DIAMETER_FLAG_PROTECTED
    if avp.vendor_bit == 'must':
        flags |= DIAMETER_FLAG_VENDOR
        ret.extend(struct.pack('!III', avp.code, _join_top(flags, pktlen + 12), avp.vendorcode))
    else:
        ret.extend(struct.pack('!II', avp.code, _join_top(flags, pktlen + 8)))
    if DEBUG:
        dbg = 'C:', avp.code, 'V', avp.vendorcode, avp.vendor_bit, 'L', pktlen
        logging.debug(dbg)
        dbg = 'Encoding ', avp.name, avp.vendorname, dictionary.type_dic[avp.type], 'as', \
              binascii.hexlify(data)
        logging.info(dbg)
    ret.extend(data)
    return _add_padding(ret)


def decode_avp(dictionary, msg):
    """Main decoding routine for single AVP"""

    def _decode_octetstring(data):
        return data[:m_len - 8]

    def _decode_utf8string(data):
        return data[:m_len - 8].decode('utf-8')

    def _decode_enumerated(data):
        return avp.enum_by_value(struct.unpack('!i', data)[0])

    def _decode_integer32(data):
        return struct.unpack('!i', data)[0]

    def _decode_unsigned32(data):
        return struct.unpack('!I', data)[0]

    def _decode_integer64(data):
        return struct.unpack('!q', data)[0]

    def _decode_unsigned64(data):
        return struct.unpack('!Q', data)[0]

    def _decode_float32(data):
        return struct.unpack('!f', data)[0]

    def _decode_float64(data):
        return struct.unpack('!d', data)[0]

    def _decode_ipaddress(data):
        if len(data) <= 6:
            return inet_ntop(socket.AF_INET, data[-4:])
        else:
            return inet_ntop(socket.AF_INET6, data[-16:])

    def _decode_time(data):
        return _decode_unsigned32(data) - SECONDS_BETWEEN_1900_AND_1970

    def _decode_grouped(data):
        ret = []
        for item in split_avps(data):
            ret.append(decode_avp(dictionary, item))
        return ret

    _decode_avp = {
        'OctetString': _decode_octetstring,
        'UTF8String': _decode_utf8string,
        'Integer32': _decode_integer32,
        'Unsigned32': _decode_unsigned32,
        'Integer64': _decode_integer64,
        'Unsigned64': _decode_unsigned64,
        'Float32': _decode_float32,
        'Float64': _decode_float64,
        'IPAddress': _decode_ipaddress,
        'Time': _decode_time,
        'Enumerated': _decode_integer32,
        'Grouped': _decode_grouped
    }

    m_code, composite = struct.unpack('!II', bytes(msg[:8]))
    m_flags, m_len = _split_top(composite)
    if DEBUG:
        dbg = 'Decoding (in msg) C', m_code, 'F', m_flags, 'L', m_len, \
              'D', binascii.hexlify(msg)
        logging.debug(dbg)
    if len(msg) != m_len:
        msg = msg[:m_len]
    if m_flags & DIAMETER_FLAG_VENDOR:
        m_len -= 4
        vendor_id = _decode_unsigned32(msg[8:12])
        msg = msg[12:]
    else:
        vendor_id = 0
        msg = msg[8:]
    avp = dictionary.avp_by_code(m_code, vendor_id, m_flags)
    if DEBUG:
        dbg = 'decoding C:', avp.name, avp.vendorname, avp.type, \
              dictionary.type_dic[avp.type], binascii.hexlify(msg)
        logging.debug(dbg)
    ret = (avp.name, avp.vendorname, _decode_avp[dictionary.type_dic[avp.type]](msg))
    if DEBUG:
        dbg = 'Decoded as :', ret[1]
        logging.info(dbg)
    return ret


def _decode_u24(data):
    ret = struct.unpack('!I', bytes(b'\x00' + bytes(data)))[0]
    return ret


def _calc_padding(msg_len):
    """Calculate message padding (align to n*4 byte)"""
    return (msg_len + 3) & ~3


# ----------------------------------------------------------------------
def inet_pton(address_family, ip_string):
    """Convert an IP address from text representation to binary form
    These are defined on Unix python.socket, but not on Windows"""
    if address_family == socket.AF_INET:
        return socket.inet_aton(ip_string)
    elif address_family == socket.AF_INET6:
        groups = ip_string.split(':')
        # The last part of an IPv6 address can be an IPv4 address
        if '.' in groups[-1]:
            groups[-1:] = ['%x' % x for x in struct.unpack('!HH',
                                                           socket.inet_aton(groups[-1]))]
        # '::' is only allowed once
        if len(ip_string.split('::')) > 2:
            return _bail_out('Illegal syntax for IP address %s' % ip_string)
        # The use of '::' indicates one or more groups of 16 bits of zeros.
        spaces = groups.count('')
        if spaces == 1:
            idx = groups.index('')
            groups = groups[:idx] + ['0'] * (8 - len(groups) + 1) + groups[idx + 1:]
        elif spaces == 2:
            zeros = ['0'] * (8 - len(groups) + 2)
            if ip_string.startswith('::'):
                groups[:2] = zeros
            elif ip_string.endswith('::'):
                groups[-2:] = zeros
            else:
                return _bail_out('Illegal syntax for IP address %s' % ip_string)
        elif spaces >= 3:
            return _bail_out('Illegal syntax for IP address %s' % ip_string)
        for i, item in enumerate(groups):
            groups[i] = int(item, 16)  # hex to int
        # Use splat operator for simplicity (list to values)
        return struct.pack('!8H', *groups)
    else:
        _bail_out('Address family not supported')


def _inet_ntop6(packed_ip):
    # IPv6 addresses have 128bits (16 bytes)
    parts = []
    for left in range(0, 16, 2):
        try:
            value = struct.unpack('!H', packed_ip[left:left + 2])[0]
            hexstr = hex(value)[2:]
        except TypeError:
            return _bail_out('Illegal syntax for IP address')
        if hexstr == '0':
            parts.append('0')
        else:
            parts.append(hexstr.lstrip('0').lower())
    result = ':'.join(parts)
    # Leaving out leading and trailing zeros is only allowed with ::
    grouped = False
    if result.endswith(':0:0'):
        grouped = True
        while result.endswith(':0'):
            result = result[:-2]
        result = result + '::'
    if result.startswith('0:0:') and not grouped:
        grouped = True
        while result.startswith('0:'):
            result = result[2:]
        result = '::' + result
    if not grouped:
        list_of_zeroes = ':0:0:0:0:0:0:'
        while len(list_of_zeroes) > 3:
            if list_of_zeroes in result:
                result = result.replace(list_of_zeroes, '::')
                break
            else:
                list_of_zeroes = list_of_zeroes[:-2]
    return result


def inet_ntop(address_family, packed_ip):
    """Convert an IP address from binary form into text representation"""
    if DEBUG:
        dbg = 'PackedIP', type(packed_ip), binascii.hexlify(packed_ip)
        logging.debug(dbg)
    if address_family == socket.AF_INET:
        if sys.version_info >= (3, 0):
            ret = ''
            for value in packed_ip:
                ret += str(value) + '.'
            return ret[:-1]
        else:
            return socket.inet_ntoa(packed_ip)
    elif address_family == socket.AF_INET6:
        if len(packed_ip) != 16:
            _bail_out('Illegal syntax for IP address')
        return _inet_ntop6(packed_ip)
    else:
        _bail_out('Address family not supported yet')


def pack_address(address):
    """addrs = socket.getaddrinfo(address, None)
    That has issue on Windows platform
    This is NOT a proper code, but it will do for now
    unfortunately, getaddrinfo does not work on windows with IPv6
    Order is important to match address like ::1.2.3.4"""
    if address.find(':') != ERROR:
        raw = inet_pton(socket.AF_INET6, address)
        return struct.pack('!h16s', 2, raw)
    if address.find('.') != ERROR:
        raw = inet_pton(socket.AF_INET, address)
        return struct.pack('!h4s', 1, raw)
    _bail_out('Malformed IP')


def encode_ipv6prefix(value):
    """In: Ipv6 prefix, e.g. 21da:d3::2f3b::/64"""
    prefix, len_in_bits = value.split('/')
    ret = struct.pack('!BB', 0, int(len_in_bits))
    ret += inet_pton(socket.AF_INET6, prefix)
    return ret


def decode_ipv6prefix(data):
    """Type&Length omitted by design
    In: Ipv6 prefix, e.g. 21da:d3::2f3b::/64"""
    len_in_bits = struct.unpack('!BB', data[:2])[1]
    ip_addr = bytearray(data[2:])
    if len(ip_addr) < 16:
        ip_addr.extend(0 for i in range(16 - len(ip_addr)))
    prefix = inet_ntop(socket.AF_INET6, ip_addr)
    return ''.join([prefix, '/', str(len_in_bits)])


# ----------------------------------------------------------------------
# DateTime routines

def get_current_datetime():
    """Local time (split)"""
    ltm = time.localtime()
    return ltm.tm_year, ltm.tm_mon, ltm.tm_mday, ltm.tm_hour, ltm.tm_min, ltm.tm_sec


def epoch2date(sec):
    """Converts seconds since epoch to date"""
    ltm = time.localtime(sec)
    return ltm.tm_year, ltm.tm_mon, ltm.tm_mday, ltm.tm_hour, ltm.tm_min, ltm.tm_sec


def date2epoch(year, month, date, hour, minute, second):
    """converts to seconds since epoch"""
    ltm = time.strptime('{0} {1} {2} {3} {4} {5}'.format(year, month, date,
                                                         hour, minute, second),
                        '%Y %m %d %H %M %S')
    return time.mktime(ltm)


# ----------------------------------------------------------------------
# Header and packet routines

#    0                   1                   2                   3
#    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
#   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#   |    Version    |                 Message Length                |
#   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#   | command flags |                  Command-Code                 |
#   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#   |                         Application-ID                        |
#   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#   |                      Hop-by-Hop Identifier                    |
#   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#   |                      End-to-End Identifier                    |
#   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#   |  AVPs ...
#   +-+-+-+-+-+-+-+-+-+-+-+-+-

class HDRItem:
    """Diameter header + message"""

    def __init__(self):
        self.ver = 1
        self.flags = 0
        self.len = 0
        self.code = 0
        self.appid = 0
        self.hopbyhop = 0
        self.endtoend = 0
        self.msg = bytearray('', 'utf-8')

    def create(self):
        if self.len == 0:  # add header length
            self.len = len(self.msg) + 20
        ret = bytearray(struct.pack('!IIIII', _join_top(self.ver, self.len),
                                    _join_top(self.flags, self.code), self.appid,
                                    self.hopbyhop, self.endtoend))
        ret.extend(self.msg)
        if DEBUG:
            dbg = 'Header fields', 'L', self.len, 'F', self.flags, 'C', self.code, \
                  'A', self.appid, 'H', self.hopbyhop, 'E', self.endtoend
            logging.debug(dbg)
        return ret

    def decode(self, dictionary, msg):
        """Split message into header + msg. Decode header"""
        hdr1, hdr2 = struct.unpack('!II', msg[:8])
        self.appid, self.hopbyhop, self.endtoend = struct.unpack('!III', msg[8:20])
        self.ver, self.len = _split_top(hdr1)
        self.flags, self.code = _split_top(hdr2)
        if DEBUG:
            dbg = 'Header:', 'V:', self.ver, 'L:', self.len, \
                  'F:', self.flags, 'C:', self.code, \
                  'A:', self.appid, 'H:', self.hopbyhop, 'E:', self.endtoend
            logging.debug(dbg)
            dbg = dictionary.command_name(self.flags, self.code,
                                          self.appid)
            logging.info(dbg)
        # self.msg[:] = msg[20:]
        # msg can be a buffer data
        if len(msg) < self.len:
            _bail_out("Incomplete message")
        self.msg[:] = msg[20:self.len]

    def _flag_is_set(self, flag):
        return self.flags & flag == flag

    @property
    def is_request(self):
        return self._flag_is_set(DIAMETER_HDR_REQUEST)

    @property
    def is_proxiable(self):
        return self._flag_is_set(DIAMETER_HDR_PROXIABLE)

    @property
    def is_error(self):
        return self._flag_is_set(DIAMETER_HDR_ERROR)


class Message:
    """Create a message while taking in account the application.
    Some application AVPs have overridden base AVPs. To handle them
    we always have to give the application to the encode_avp method.
    """

    def __init__(self, dictionary):
        self.avps = []
        self.hdr = HDRItem()
        self.msg = bytearray('', 'utf-8')
        self.dictionary = dictionary

    def _decode_header(self, msg):
        self.hdr.decode(self.dictionary, msg)

    def _create(self):
        self.hdr.msg = bytearray('', 'utf-8')
        for avpdef, avpvalue in self.avps:
            self.hdr.msg.extend(encode_avp(self.dictionary, avpdef, avpvalue))
        self.msg[:] = self.hdr.create()
        return self.msg

    def new(self, cmdname, appid):
        """Set Command Code & Application Id"""
        self.hdr.code = self.dictionary.command_code(cmdname, appid)
        self.hdr.appid = appid
        # Set Hop-by-Hop and End-to-End
        _initialize_hops(self.hdr)

    def decode(self, msg):
        """Decode header and all AVPs"""
        self._decode_header(msg)
        # self.msg[:] = msg
        # msg can be a buffer data
        self.msg[:] = msg[:self.hdr.len]
        self.avps = []
        for raw in split_avps(self.hdr.msg):
            self.avps.append(decode_avp(self.dictionary, raw))

    def encode(self, avpname, avpvalue, avpvendor='None'):
        """Add single AVP"""
        self.avps.append((self.dictionary.avp_by_name(avpname, avpvendor), avpvalue))

    def create_request(self):
        """Add AVPs to header and calculate remaining fields and return Request"""
        self.hdr.flags |= DIAMETER_HDR_REQUEST
        return self._create()

    def create_answer(self):
        """Add AVPs to header and calculate remaining fields and return Answer"""
        return self._create()


def _initialize_hops(hdr):
    """Set Hop-by-Hop and End-to-End fields to sane values
    Hop-by-Hop aids in matching requests and replies.
    The Hop-by-Hop identifier is normally a monotonically increasing number,
    whose start value was randomly generated.
    End-to-End Identifier is used to detect duplicate messages.
    implementations MAY set the high order 12 bits to contain the
    low order 12 bits of current time,
    and the low order 20 bits to a random value."""
    # Not by RFC, but close enough
    try:
        _initialize_hops.Hop_by_Hop += 1
        _initialize_hops.End_to_End += 1
    except AttributeError:
        _initialize_hops.Hop_by_Hop = int(time.time())
        _initialize_hops.End_to_End = (_initialize_hops.Hop_by_Hop % 32768) * 32768
    hdr.hopbyhop = _initialize_hops.Hop_by_Hop
    hdr.endtoend = _initialize_hops.End_to_End


def _join_top(top, low):
    """Join 1,3 to 4-byte value"""
    return (top << 24) + low


def _split_top(data):
    """Split Top Byte from Lower 3 bytes"""
    top = data >> 24
    low = data & 0xFFFFFF
    return top, low


def split_avps(msg):
    """Split AVPs
    Input: H.Msg
    Result: list of undecoded AVPs"""
    msg_pointer = 0
    ret = []
    while msg_pointer < len(msg):
        mlen = _decode_u24(msg[msg_pointer + 5:msg_pointer + 8])
        # Increase to boundary
        plen = _calc_padding(mlen)
        avp = msg[msg_pointer:msg_pointer + plen]
        msg_pointer += plen
        if DEBUG:
            dbg = 'Single AVP', 'L', mlen, plen, 'D', binascii.hexlify(avp)
            logging.debug(dbg)
        ret.append(avp)
    return ret


#######################################
# History
#######################################
#
# 0.5.0 - Jan 21 '17 - Initial version
#   Created to be python2/python3 compatible
#   Known issues - not noticed with 2.2.3 or newer
#   + tshark-2.0.2 (default on Ubuntu 16.04) dictionary issues
#      1) unclosed command tags in HP.xml causing parser to break
#      2) User-Session-ID is defined as User-Session-Id
#       # workaround is to manually fix errors
#      3) Loading Custom dictionary not supported yet
#         e.g. on Linux it would have multiple dictionary sections which parser
#         could not parse
