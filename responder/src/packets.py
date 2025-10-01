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

# Built-in imports
import re
from os import urandom
from base64 import b64encode

# Local library imports
from responder.src import settings
from responder.src.odict import OrderedDict
from responder.src.utils import (
    HTTPCurrentDate,
    SMBTime,
    RespondWithIPAton,
    RespondWithIPPton,
    RespondWithIP,
    StructPython2or3,
    NetworkRecvBufferPython2or3,
    StructWithLenPython2or3,
)


# Packet class handling all packet generation (see odict.py).
class Packet:
    fields = OrderedDict(
        [
            ("data", ""),
        ]
    )

    def __init__(self, **kw):
        self.fields = OrderedDict(self.__class__.fields)
        for k, v in kw.items():
            if callable(v):
                self.fields[k] = v(self.fields[k])
            else:
                self.fields[k] = v

    def __str__(self):
        return "".join(map(str, self.fields.values()))


# NBT Answer Packet
class NBT_Ans(Packet):
    fields = OrderedDict(
        [
            ("Tid", ""),
            ("Flags", "\x85\x00"),
            ("Question", "\x00\x00"),
            ("AnswerRRS", "\x00\x01"),
            ("AuthorityRRS", "\x00\x00"),
            ("AdditionalRRS", "\x00\x00"),
            ("NbtName", ""),
            ("Type", "\x00\x20"),
            ("Classy", "\x00\x01"),
            (
                "TTL",
                "\x00\x04\x93\xe0",
            ),  # TTL: 3 days, 11 hours, 20 minutes (Default windows behavior)
            ("Len", "\x00\x06"),
            ("Flags1", "\x00\x00"),
            ("IP", "\x00\x00\x00\x00"),
        ]
    )

    def calculate(self, data):
        self.fields["Tid"] = NetworkRecvBufferPython2or3(data[0:2])
        self.fields["NbtName"] = NetworkRecvBufferPython2or3(data[12:46])
        self.fields["IP"] = RespondWithIPAton()


# DNS Answer Packet
class DNS_Ans(Packet):
    fields = OrderedDict(
        [
            ("Tid", ""),
            ("Flags", "\x85\x10"),
            ("Question", "\x00\x01"),
            ("AnswerRRS", "\x00\x01"),
            ("AuthorityRRS", "\x00\x00"),
            ("AdditionalRRS", "\x00\x00"),
            ("QuestionName", ""),
            ("QuestionNameNull", "\x00"),
            ("Type", "\x00\x01"),
            ("Class", "\x00\x01"),
            ("AnswerPointer", "\xc0\x0c"),
            ("Type1", "\x00\x01"),
            ("Class1", "\x00\x01"),
            (
                "TTL",
                "\x00\x00\x00\x1e",
            ),  # 30 secs, don't mess with their cache for too long..
            ("IPLen", "\x00\x04"),
            ("IP", "\x00\x00\x00\x00"),
        ]
    )

    def calculate(self, data):
        self.fields["Tid"] = data[0:2]
        self.fields["QuestionName"] = "".join(data[12:].split("\x00")[:1])
        self.fields["IP"] = RespondWithIPAton()
        self.fields["IPLen"] = StructPython2or3(">h", self.fields["IP"])


# DNS Answer Packet OPT
class DNS_AnsOPT(Packet):
    fields = OrderedDict(
        [
            ("Tid", ""),
            ("Flags", "\x85\x10"),
            ("Question", "\x00\x01"),
            ("AnswerRRS", "\x00\x01"),
            ("AuthorityRRS", "\x00\x00"),
            ("AdditionalRRS", "\x00\x01"),
            ("QuestionName", ""),
            ("QuestionNameNull", "\x00"),
            ("Type", "\x00\x01"),
            ("Class", "\x00\x01"),
            ("AnswerPointer", "\xc0\x0c"),
            ("Type1", "\x00\x01"),
            ("Class1", "\x00\x01"),
            (
                "TTL",
                "\x00\x00\x00\x1e",
            ),  # 30 secs, don't mess with their cache for too long..
            ("IPLen", "\x00\x04"),
            ("IP", "\x00\x00\x00\x00"),
            ("OPTName", "\x00"),
            ("OPTType", "\x00\x29"),
            ("OPTUDPSize", "\x10\x00"),
            ("OPTRCode", "\x00"),
            ("OPTEDNSVersion", "\x00"),
            ("OPTLen", "\x00\x00"),  # Hardcoded since it's fixed to 0 in this case.
            ("OPTStr", "\x00\x00"),
        ]
    )

    def calculate(self, data):
        self.fields["Tid"] = data[0:2]
        self.fields["QuestionName"] = "".join(data[12:].split("\x00")[:1])
        self.fields["IP"] = RespondWithIPAton()
        self.fields["IPLen"] = StructPython2or3(">h", self.fields["IP"])


class DNS6_Ans(Packet):
    fields = OrderedDict(
        [
            ("Tid", ""),
            ("Flags", "\x85\x10"),
            ("Question", "\x00\x01"),
            ("AnswerRRS", "\x00\x01"),
            ("AuthorityRRS", "\x00\x00"),
            ("AdditionalRRS", "\x00\x00"),
            ("QuestionName", ""),
            ("QuestionNameNull", "\x00"),
            ("Type", "\x00\x1c"),
            ("Class", "\x00\x01"),
            ("AnswerPointer", "\xc0\x0c"),
            ("Type1", "\x00\x1c"),
            ("Class1", "\x00\x01"),
            (
                "TTL",
                "\x00\x00\x00\x1e",
            ),  # 30 secs, don't mess with their cache for too long..
            ("IPLen", "\x00\x04"),
            ("IP", "\x00\x00\x00\x00"),
        ]
    )

    def calculate(self, data):
        self.fields["Tid"] = data[0:2]
        self.fields["QuestionName"] = "".join(data[12:].split("\x00")[:1])
        self.fields["IP"] = RespondWithIPPton()
        self.fields["IPLen"] = StructPython2or3(">h", self.fields["IP"])


class DNS6_AnsOPT(Packet):
    fields = OrderedDict(
        [
            ("Tid", ""),
            ("Flags", "\x85\x10"),
            ("Question", "\x00\x01"),
            ("AnswerRRS", "\x00\x01"),
            ("AuthorityRRS", "\x00\x00"),
            ("AdditionalRRS", "\x00\x01"),
            ("QuestionName", ""),
            ("QuestionNameNull", "\x00"),
            ("Type", "\x00\x1c"),
            ("Class", "\x00\x01"),
            ("AnswerPointer", "\xc0\x0c"),
            ("Type1", "\x00\x1c"),
            ("Class1", "\x00\x01"),
            (
                "TTL",
                "\x00\x00\x00\x1e",
            ),  # 30 secs, don't mess with their cache for too long..
            ("IPLen", "\x00\x04"),
            ("IP", "\x00\x00\x00\x00"),
            ("OPTName", "\x00"),
            ("OPTType", "\x00\x29"),
            ("OPTUDPSize", "\x10\x00"),
            ("OPTRCode", "\x00"),
            ("OPTEDNSVersion", "\x00"),
            ("OPTLen", "\x00\x00"),  # Hardcoded since it's fixed to 0 in this case.
            ("OPTStr", "\x00\x00"),
        ]
    )

    def calculate(self, data):
        self.fields["Tid"] = data[0:2]
        self.fields["QuestionName"] = "".join(data[12:].split("\x00")[:1])
        self.fields["IP"] = RespondWithIPPton()
        self.fields["IPLen"] = StructPython2or3(">h", self.fields["IP"])


class DNS_SRV_Ans(Packet):
    fields = OrderedDict(
        [
            ("Tid", ""),
            ("Flags", "\x85\x80"),
            ("Question", "\x00\x01"),
            ("AnswerRRS", "\x00\x01"),
            ("AuthorityRRS", "\x00\x00"),
            ("AdditionalRRS", "\x00\x00"),
            ("QuestionName", ""),
            ("QuestionNameNull", "\x00"),
            ("Type", "\x00\x21"),  # srv
            ("Class", "\x00\x01"),
            ("AnswerPointer", "\xc0\x0c"),
            ("Type1", "\x00\x21"),  # srv
            ("Class1", "\x00\x01"),
            (
                "TTL",
                "\x00\x00\x00\x1e",
            ),  # 30 secs, don't mess with their cache for too long..
            ("RecordLen", ""),
            ("Priority", "\x00\x00"),
            ("Weight", "\x00\x64"),
            ("Port", "\x00\x00"),
            (
                "TargetLenPre",
                "\x0f",
            ),  # static, we provide netbios computer name 15 chars like Windows by default.
            ("TargetPrefix", ""),
            ("TargetLenSuff", ""),
            ("TargetSuffix", ""),
            ("TargetLenSuff2", ""),
            ("TargetSuffix2", ""),
            ("TargetNull", "\x00"),
        ]
    )

    def calculate(self, data):
        self.fields["Tid"] = data[0:2]
        DNSName = "".join(data[12:].split("\x00")[:1])
        SplitFQDN = re.split(
            r"\W+", DNSName
        )  # split the ldap.tcp.blah.blah.blah.domain.tld

        # What's the question? we need it first to calc all other len.
        self.fields["QuestionName"] = DNSName

        # Want to be detected that easily by xyz sensor?
        self.fields["TargetPrefix"] = settings.Config.MachineName

        # two last parts of the domain are the actual Domain name.. eg: contoso.com
        self.fields["TargetSuffix"] = SplitFQDN[-2]
        self.fields["TargetSuffix2"] = SplitFQDN[-1]
        # We calculate the len for that domain...
        self.fields["TargetLenSuff2"] = StructPython2or3(
            ">B", self.fields["TargetSuffix2"]
        )
        self.fields["TargetLenSuff"] = StructPython2or3(
            ">B", self.fields["TargetSuffix"]
        )

        # Calculate Record len.
        CalcLen = (
            self.fields["Priority"]
            + self.fields["Weight"]
            + self.fields["Port"]
            + self.fields["TargetLenPre"]
            + self.fields["TargetPrefix"]
            + self.fields["TargetLenSuff"]
            + self.fields["TargetSuffix"]
            + self.fields["TargetLenSuff2"]
            + self.fields["TargetSuffix2"]
            + self.fields["TargetNull"]
        )

        # Our answer len..
        self.fields["RecordLen"] = StructPython2or3(">h", CalcLen)

        # for now we support ldap and kerberos...
        if "ldap" in DNSName:
            self.fields["Port"] = StructWithLenPython2or3(">h", 389)

        if "kerberos" in DNSName:
            self.fields["Port"] = StructWithLenPython2or3(">h", 88)


# LLMNR Answer Packet
class LLMNR_Ans(Packet):
    fields = OrderedDict(
        [
            ("Tid", ""),
            ("Flags", "\x80\x00"),
            ("Question", "\x00\x01"),
            ("AnswerRRS", "\x00\x01"),
            ("AuthorityRRS", "\x00\x00"),
            ("AdditionalRRS", "\x00\x00"),
            ("QuestionNameLen", "\x09"),
            ("QuestionName", ""),
            ("QuestionNameNull", "\x00"),
            ("Type", "\x00\x01"),
            ("Class", "\x00\x01"),
            ("AnswerNameLen", "\x09"),
            ("AnswerName", ""),
            ("AnswerNameNull", "\x00"),
            ("Type1", "\x00\x01"),
            ("Class1", "\x00\x01"),
            ("TTL", "\x00\x00\x00\x1e"),  ##Poison for 30 sec (Default windows behavior)
            ("IPLen", "\x00\x04"),
            ("IP", "\x00\x00\x00\x00"),
        ]
    )

    def calculate(self):
        self.fields["IP"] = RespondWithIPAton()
        self.fields["IPLen"] = StructPython2or3(">h", self.fields["IP"])
        self.fields["AnswerNameLen"] = StructPython2or3(">B", self.fields["AnswerName"])
        self.fields["QuestionNameLen"] = StructPython2or3(
            ">B", self.fields["QuestionName"]
        )


class LLMNR6_Ans(Packet):
    fields = OrderedDict(
        [
            ("Tid", ""),
            ("Flags", "\x80\x00"),
            ("Question", "\x00\x01"),
            ("AnswerRRS", "\x00\x01"),
            ("AuthorityRRS", "\x00\x00"),
            ("AdditionalRRS", "\x00\x00"),
            ("QuestionNameLen", "\x09"),
            ("QuestionName", ""),
            ("QuestionNameNull", "\x00"),
            ("Type", "\x00\x1c"),
            ("Class", "\x00\x01"),
            ("AnswerNameLen", "\x09"),
            ("AnswerName", ""),
            ("AnswerNameNull", "\x00"),
            ("Type1", "\x00\x1c"),
            ("Class1", "\x00\x01"),
            (
                "TTL",
                "\x00\x00\x00\x1e",
            ),  ##Poison for 30 sec (Default windows behavior).
            ("IPLen", "\x00\x04"),
            ("IP", "\x00\x00\x00\x00"),
        ]
    )

    def calculate(self):
        self.fields["IP"] = RespondWithIPPton()
        self.fields["IPLen"] = StructPython2or3(">h", self.fields["IP"])
        self.fields["AnswerNameLen"] = StructPython2or3(">B", self.fields["AnswerName"])
        self.fields["QuestionNameLen"] = StructPython2or3(
            ">B", self.fields["QuestionName"]
        )


# MDNS Answer Packet
class MDNS_Ans(Packet):
    fields = OrderedDict(
        [
            ("Tid", "\x00\x00"),
            ("Flags", "\x84\x00"),
            ("Question", "\x00\x00"),
            ("AnswerRRS", "\x00\x01"),
            ("AuthorityRRS", "\x00\x00"),
            ("AdditionalRRS", "\x00\x00"),
            ("AnswerName", ""),
            ("AnswerNameNull", "\x00"),
            ("Type", "\x00\x01"),
            ("Class", "\x00\x01"),
            ("TTL", "\x00\x00\x00\x78"),  ##Poison for 2mn (Default windows behavior)
            ("IPLen", "\x00\x04"),
            ("IP", "\x00\x00\x00\x00"),
        ]
    )

    def calculate(self):
        self.fields["IP"] = RespondWithIPAton()
        self.fields["IPLen"] = StructPython2or3(">h", self.fields["IP"])


# MDNS6 Answer Packet
class MDNS6_Ans(Packet):
    fields = OrderedDict(
        [
            ("Tid", "\x00\x00"),
            ("Flags", "\x84\x00"),
            ("Question", "\x00\x00"),
            ("AnswerRRS", "\x00\x01"),
            ("AuthorityRRS", "\x00\x00"),
            ("AdditionalRRS", "\x00\x00"),
            ("AnswerName", ""),
            ("AnswerNameNull", "\x00"),
            ("Type", "\x00\x1c"),
            ("Class", "\x00\x01"),
            ("TTL", "\x00\x00\x00\x78"),  ##Poison for 2mn (Default windows behavior)
            ("IPLen", "\x00\x04"),
            ("IP", "\x00\x00\x00\x00"),
        ]
    )

    def calculate(self):
        self.fields["IP"] = RespondWithIPPton()
        self.fields["IPLen"] = StructPython2or3(">h", self.fields["IP"])


################### DHCP SRV ######################


##### HTTP Packets #####
class NTLM_Challenge(Packet):
    fields = OrderedDict(
        [
            ("Signature", "NTLMSSP"),
            ("SignatureNull", "\x00"),
            ("MessageType", "\x02\x00\x00\x00"),
            ("TargetNameLen", "\x06\x00"),
            ("TargetNameMaxLen", "\x06\x00"),
            ("TargetNameOffset", "\x38\x00\x00\x00"),
            (
                "NegoFlags",
                (
                    "\x05\x02\x81\xa2"
                    if settings.Config.NOESS_On_Off
                    else "\x05\x02\x89\xa2"
                ),
            ),
            ("ServerChallenge", ""),
            ("Reserved", "\x00\x00\x00\x00\x00\x00\x00\x00"),
            ("TargetInfoLen", "\x7e\x00"),
            ("TargetInfoMaxLen", "\x7e\x00"),
            ("TargetInfoOffset", "\x3e\x00\x00\x00"),
            ("NTLMOsVersion", "\x0a\x00\x7c\x4f\x00\x00\x00\x0f"),
            ("TargetNameStr", settings.Config.Domain),
            ("Av1", "\x02\x00"),  # nbt name
            ("Av1Len", "\x06\x00"),
            ("Av1Str", settings.Config.Domain),
            ("Av2", "\x01\x00"),  # Server name
            ("Av2Len", "\x14\x00"),
            ("Av2Str", settings.Config.MachineName),
            ("Av3", "\x04\x00"),  # Full Domain name
            ("Av3Len", "\x12\x00"),
            ("Av3Str", settings.Config.DomainName),
            ("Av4", "\x03\x00"),  # Full machine domain name
            ("Av4Len", "\x28\x00"),
            ("Av4Str", settings.Config.MachineName + "." + settings.Config.DomainName),
            ("Av5", "\x05\x00"),  # Domain Forest Name
            ("Av5Len", "\x12\x00"),
            ("Av5Str", settings.Config.DomainName),
            ("Av6", "\x00\x00"),  # AvPairs Terminator
            ("Av6Len", "\x00\x00"),
        ]
    )

    def calculate(self):
        # First convert to unicode
        self.fields["TargetNameStr"] = self.fields["TargetNameStr"].encode("utf-16le")
        self.fields["Av1Str"] = self.fields["Av1Str"].encode("utf-16le")
        self.fields["Av2Str"] = self.fields["Av2Str"].encode("utf-16le")
        self.fields["Av3Str"] = self.fields["Av3Str"].encode("utf-16le")
        self.fields["Av4Str"] = self.fields["Av4Str"].encode("utf-16le")
        self.fields["Av5Str"] = self.fields["Av5Str"].encode("utf-16le")
        # Now from bytes to str..
        self.fields["TargetNameStr"] = self.fields["TargetNameStr"].decode("latin-1")
        self.fields["Av1Str"] = self.fields["Av1Str"].decode("latin-1")
        self.fields["Av2Str"] = self.fields["Av2Str"].decode("latin-1")
        self.fields["Av3Str"] = self.fields["Av3Str"].decode("latin-1")
        self.fields["Av4Str"] = self.fields["Av4Str"].decode("latin-1")
        self.fields["Av5Str"] = self.fields["Av5Str"].decode("latin-1")
        # Then calculate

        CalculateNameOffset = (
            str(self.fields["Signature"])
            + str(self.fields["SignatureNull"])
            + str(self.fields["MessageType"])
            + str(self.fields["TargetNameLen"])
            + str(self.fields["TargetNameMaxLen"])
            + str(self.fields["TargetNameOffset"])
            + str(self.fields["NegoFlags"])
            + str("A" * 8)
            + str(self.fields["Reserved"])
            + str(self.fields["TargetInfoLen"])
            + str(self.fields["TargetInfoMaxLen"])
            + str(self.fields["TargetInfoOffset"])
            + str(self.fields["NTLMOsVersion"])
        )

        CalculateAvPairsOffset = CalculateNameOffset + str(self.fields["TargetNameStr"])
        CalculateAvPairsLen = (
            str(self.fields["Av1"])
            + str(self.fields["Av1Len"])
            + str(self.fields["Av1Str"])
            + str(self.fields["Av2"])
            + str(self.fields["Av2Len"])
            + str(self.fields["Av2Str"])
            + str(self.fields["Av3"])
            + str(self.fields["Av3Len"])
            + str(self.fields["Av3Str"])
            + str(self.fields["Av4"])
            + str(self.fields["Av4Len"])
            + str(self.fields["Av4Str"])
            + str(self.fields["Av5"])
            + str(self.fields["Av5Len"])
            + str(self.fields["Av5Str"])
            + str(self.fields["Av6"])
            + str(self.fields["Av6Len"])
        )

        # Target Name Offsets
        self.fields["TargetNameOffset"] = StructPython2or3("<i", CalculateNameOffset)
        self.fields["TargetNameLen"] = StructPython2or3(
            "<h", self.fields["TargetNameStr"]
        )
        self.fields["TargetNameMaxLen"] = StructPython2or3(
            "<h", self.fields["TargetNameStr"]
        )
        # AvPairs Offsets
        self.fields["TargetInfoOffset"] = StructPython2or3("<i", CalculateAvPairsOffset)
        self.fields["TargetInfoLen"] = StructPython2or3("<h", CalculateAvPairsLen)
        self.fields["TargetInfoMaxLen"] = StructPython2or3("<h", CalculateAvPairsLen)
        # AvPairs StrLen
        self.fields["Av1Len"] = StructPython2or3("<h", self.fields["Av1Str"])
        self.fields["Av2Len"] = StructPython2or3("<h", self.fields["Av2Str"])
        self.fields["Av3Len"] = StructPython2or3("<h", self.fields["Av3Str"])
        self.fields["Av4Len"] = StructPython2or3("<h", self.fields["Av4Str"])
        self.fields["Av5Len"] = StructPython2or3("<h", self.fields["Av5Str"])


class IIS_Auth_401_Ans(Packet):
    fields = OrderedDict(
        [
            ("Code", "HTTP/1.1 401 Unauthorized\r\n"),
            ("Type", "Content-Type: text/html\r\n"),
            ("ServerType", "Server: Microsoft-IIS/10.0\r\n"),
            ("Date", "Date: " + HTTPCurrentDate() + "\r\n"),
            ("WWW-Auth", "WWW-Authenticate: Negotiate\r\n"),
            ("WWW-Auth2", "WWW-Authenticate: NTLM\r\n"),
            ("Len", "Content-Length: "),
            ("ActualLen", "76"),
            ("CRLF", "\r\n\r\n"),
            (
                "Payload",
                """<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">
<head>
<meta http-equiv="Content-Type" content="text/html; charset=iso-8859-1"/>
<title>401 - Unauthorized: Access is denied due to invalid credentials.</title>
<style type="text/css">
<!--
body{margin:0;font-size:.7em;font-family:Verdana, Arial, Helvetica, sans-serif;background:#EEEEEE;}
fieldset{padding:0 15px 10px 15px;}
h1{font-size:2.4em;margin:0;color:#FFF;}
h2{font-size:1.7em;margin:0;color:#CC0000;}
h3{font-size:1.2em;margin:10px 0 0 0;color:#000000;}
#header{width:96%;margin:0 0 0 0;padding:6px 2% 6px 2%;font-family:"trebuchet MS", Verdana, sans-serif;color:#FFF;
background-color:#555555;}
#content{margin:0 0 0 2%;position:relative;}
.content-container{background:#FFF;width:96%;margin-top:8px;padding:10px;position:relative;}
-->
</style>
</head>
<body>
<div id="header"><h1>Server Error</h1></div>
<div id="content">
 <div class="content-container"><fieldset>
  <h2>401 - Unauthorized: Access is denied due to invalid credentials.</h2>
  <h3>You do not have permission to view this directory or page using the credentials that you supplied.</h3>
 </fieldset></div>
</div>
</body>
</html>
""",
            ),
        ]
    )

    def calculate(self):
        self.fields["ActualLen"] = len(str(self.fields["Payload"]))


class IIS_Auth_Granted(Packet):
    fields = OrderedDict(
        [
            ("Code", "HTTP/1.1 200 OK\r\n"),
            ("ServerType", "Server: Microsoft-IIS/10.0\r\n"),
            ("Date", "Date: " + HTTPCurrentDate() + "\r\n"),
            ("Type", "Content-Type: text/html\r\n"),
            ("WWW-Auth", "WWW-Authenticate: NTLM\r\n"),
            ("ContentLen", "Content-Length: "),
            ("ActualLen", "76"),
            ("CRLF", "\r\n\r\n"),
            ("Payload", ""),
        ]
    )

    def calculate(self):
        self.fields["ActualLen"] = len(str(self.fields["Payload"]))


class IIS_NTLM_Challenge_Ans(Packet):
    fields = OrderedDict(
        [
            ("Code", "HTTP/1.1 401 Unauthorized\r\n"),
            ("ServerType", "Server: Microsoft-IIS/10.0\r\n"),
            ("Date", "Date: " + HTTPCurrentDate() + "\r\n"),
            ("Type", "Content-Type: text/html\r\n"),
            ("WWWAuth", "WWW-Authenticate: NTLM "),
            ("Payload", ""),
            ("Payload-CRLF", "\r\n"),
            ("ContentLen", "Content-Length: "),
            ("ActualLen", "76"),
            ("CRLF", "\r\n\r\n"),
            (
                "Payload2",
                """<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01//EN""http://www.w3.org/TR/html4/strict.dtd">
<HTML><HEAD><TITLE>Not Authorized</TITLE>
<META HTTP-EQUIV="Content-Type" Content="text/html; charset=us-ascii"></HEAD>
<BODY><h2>Not Authorized</h2>
<hr><p>HTTP Error 401. The requested resource requires user authentication.</p>
</BODY></HTML>
""",
            ),
        ]
    )

    def calculate(self):
        self.fields["ActualLen"] = len(str(self.fields["Payload2"]))


class WinRM_NTLM_Challenge_Ans(Packet):
    fields = OrderedDict(
        [
            ("Code", "HTTP/1.1 401\r\n"),
            ("WWWAuth", "WWW-Authenticate: Negotiate "),
            ("Payload", ""),
            ("Payload-CRLF", "\r\n"),
            ("ServerType", "Server: Microsoft-HTTPAPI/2.0\r\n"),
            ("Date", "Date: " + HTTPCurrentDate() + "\r\n"),
            ("Len", "Content-Length: 0\r\n"),
            ("CRLF", "\r\n"),
        ]
    )

    def calculate(self, payload):
        self.fields["Payload"] = b64encode(payload)


class IIS_Basic_401_Ans(Packet):
    fields = OrderedDict(
        [
            ("Code", "HTTP/1.1 401 Unauthorized\r\n"),
            ("ServerType", "Server: Microsoft-IIS/10.0\r\n"),
            ("Type", "Content-Type: text/html\r\n"),
            ("WWW-Auth", 'WWW-Authenticate: Basic realm="Authentication Required"\r\n'),
            ("Date", "Date: " + HTTPCurrentDate() + "\r\n"),
            ("Len", "Content-Length: "),
            ("ActualLen", "76"),
            ("CRLF", "\r\n\r\n"),
            (
                "Payload",
                """<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">
<head>
<meta http-equiv="Content-Type" content="text/html; charset=iso-8859-1"/>
<title>401 - Unauthorized: Access is denied due to invalid credentials.</title>
<style type="text/css">
<!--
body{margin:0;font-size:.7em;font-family:Verdana, Arial, Helvetica, sans-serif;background:#EEEEEE;}
fieldset{padding:0 15px 10px 15px;}
h1{font-size:2.4em;margin:0;color:#FFF;}
h2{font-size:1.7em;margin:0;color:#CC0000;}
h3{font-size:1.2em;margin:10px 0 0 0;color:#000000;}
#header{width:96%;margin:0 0 0 0;padding:6px 2% 6px 2%;font-family:"trebuchet MS", Verdana, sans-serif;color:#FFF;
background-color:#555555;}
#content{margin:0 0 0 2%;position:relative;}
.content-container{background:#FFF;width:96%;margin-top:8px;padding:10px;position:relative;}
-->
</style>
</head>
<body>
<div id="header"><h1>Server Error</h1></div>
<div id="content">
 <div class="content-container"><fieldset>
  <h2>401 - Unauthorized: Access is denied due to invalid credentials.</h2>
  <h3>You do not have permission to view this directory or page using the credentials that you supplied.</h3>
 </fieldset></div>
</div>
</body>
</html>
""",
            ),
        ]
    )

    def calculate(self):
        self.fields["ActualLen"] = len(str(self.fields["Payload"]))


##### Proxy mode Packets #####
class WPADScript(Packet):
    fields = OrderedDict(
        [
            ("Code", "HTTP/1.1 200 OK\r\n"),
            ("Type", "Content-Type: application/x-ns-proxy-autoconfig\r\n"),
            ("Cache", "Pragma: no-cache\r\n"),
            ("Server", "Server: BigIP\r\n"),
            ("ContentLen", "Content-Length: "),
            ("ActualLen", "76"),
            ("CRLF", "\r\n\r\n"),
            (
                "Payload",
                "function FindProxyForURL(url, host){return 'PROXY "
                + RespondWithIP()
                + ":3141; DIRECT';}",
            ),
        ]
    )

    def calculate(self):
        self.fields["ActualLen"] = len(str(self.fields["Payload"]))


class ServeExeFile(Packet):
    fields = OrderedDict(
        [
            ("Code", "HTTP/1.1 200 OK\r\n"),
            ("ContentType", "Content-Type: application/octet-stream\r\n"),
            ("LastModified", "Last-Modified: " + HTTPCurrentDate() + "\r\n"),
            ("AcceptRanges", "Accept-Ranges: bytes\r\n"),
            ("Server", "Server: Microsoft-IIS/10.0\r\n"),
            ("ContentDisp", "Content-Disposition: attachment; filename="),
            ("ContentDiFile", ""),
            ("FileCRLF", ";\r\n"),
            ("ContentLen", "Content-Length: "),
            ("ActualLen", "76"),
            ("Date", "\r\nDate: " + HTTPCurrentDate() + "\r\n"),
            ("Connection", "Connection: keep-alive\r\n"),
            ("X-CCC", "US\r\n"),
            ("X-CID", "2\r\n"),
            ("CRLF", "\r\n"),
            ("Payload", "jj"),
        ]
    )

    def calculate(self):
        self.fields["ActualLen"] = len(str(self.fields["Payload"]))


class ServeHtmlFile(Packet):
    fields = OrderedDict(
        [
            ("Code", "HTTP/1.1 200 OK\r\n"),
            ("ContentType", "Content-Type: text/html\r\n"),
            ("LastModified", "Last-Modified: " + HTTPCurrentDate() + "\r\n"),
            ("AcceptRanges", "Accept-Ranges: bytes\r\n"),
            ("Server", "Server: Microsoft-IIS/10.0\r\n"),
            ("ContentLen", "Content-Length: "),
            ("ActualLen", "76"),
            ("Date", "\r\nDate: " + HTTPCurrentDate() + "\r\n"),
            ("Connection", "Connection: keep-alive\r\n"),
            ("CRLF", "\r\n"),
            ("Payload", "jj"),
        ]
    )

    def calculate(self):
        self.fields["ActualLen"] = len(str(self.fields["Payload"]))


##### WPAD Auth Packets #####
class WPAD_Auth_407_Ans(Packet):
    fields = OrderedDict(
        [
            ("Code", "HTTP/1.1 407 Unauthorized\r\n"),
            ("ServerType", "Server: Microsoft-IIS/10.0\r\n"),
            ("Date", "Date: " + HTTPCurrentDate() + "\r\n"),
            ("Type", "Content-Type: text/html\r\n"),
            ("WWW-Auth", "Proxy-Authenticate: NTLM\r\n"),
            ("Connection", "Proxy-Connection: close\r\n"),
            ("Cache-Control", "Cache-Control: no-cache\r\n"),
            ("Pragma", "Pragma: no-cache\r\n"),
            ("Proxy-Support", "Proxy-Support: Session-Based-Authentication\r\n"),
            ("Len", "Content-Length: 0\r\n"),
            ("CRLF", "\r\n"),
        ]
    )


class WPAD_NTLM_Challenge_Ans(Packet):
    fields = OrderedDict(
        [
            ("Code", "HTTP/1.1 407 Unauthorized\r\n"),
            ("ServerType", "Server: Microsoft-IIS/10.0\r\n"),
            ("Date", "Date: " + HTTPCurrentDate() + "\r\n"),
            ("Type", "Content-Type: text/html\r\n"),
            ("WWWAuth", "Proxy-Authenticate: NTLM "),
            ("Payload", ""),
            ("Payload-CRLF", "\r\n"),
            ("Len", "Content-Length: 0\r\n"),
            ("CRLF", "\r\n"),
        ]
    )

    def calculate(self, payload):
        self.fields["Payload"] = b64encode(payload)


class WPAD_Basic_407_Ans(Packet):
    fields = OrderedDict(
        [
            ("Code", "HTTP/1.1 407 Unauthorized\r\n"),
            ("ServerType", "Server: Microsoft-IIS/10.0\r\n"),
            ("Date", "Date: " + HTTPCurrentDate() + "\r\n"),
            ("Type", "Content-Type: text/html\r\n"),
            (
                "WWW-Auth",
                'Proxy-Authenticate: Basic realm="Authentication Required"\r\n',
            ),
            ("Connection", "Proxy-Connection: close\r\n"),
            ("Cache-Control", "Cache-Control: no-cache\r\n"),
            ("Pragma", "Pragma: no-cache\r\n"),
            ("Proxy-Support", "Proxy-Support: Session-Based-Authentication\r\n"),
            ("Len", "Content-Length: 0\r\n"),
            ("CRLF", "\r\n"),
        ]
    )


##### WEB Dav Stuff #####
class WEBDAV_Options_Answer(Packet):
    fields = OrderedDict(
        [
            ("Code", "HTTP/1.1 200 OK\r\n"),
            ("Date", "Date: " + HTTPCurrentDate() + "\r\n"),
            ("ServerType", "Server: Microsoft-IIS/10.0\r\n"),
            ("Allow", "Allow: GET,HEAD,POST,OPTIONS,TRACE\r\n"),
            ("Len", "Content-Length: 0\r\n"),
            ("Keep-Alive:", "Keep-Alive: timeout=5, max=100\r\n"),
            ("Connection", "Connection: Keep-Alive\r\n"),
            ("Content-Type", "Content-Type: text/html\r\n"),
            ("CRLF", "\r\n"),
        ]
    )


##### FTP Packets #####
class FTPPacket(Packet):
    fields = OrderedDict(
        [
            ("Code", "220"),
            ("Separator", "\x20"),
            ("Message", "Welcome"),
            ("Terminator", "\x0d\x0a"),
        ]
    )


##### SQL Packets #####
class MSSQLPreLoginAnswer(Packet):
    fields = OrderedDict(
        [
            ("PacketType", "\x04"),
            ("Status", "\x01"),
            ("Len", "\x00\x25"),
            ("SPID", "\x00\x00"),
            ("PacketID", "\x01"),
            ("Window", "\x00"),
            ("TokenType", "\x00"),
            ("VersionOffset", "\x00\x15"),
            ("VersionLen", "\x00\x06"),
            ("TokenType1", "\x01"),
            ("EncryptionOffset", "\x00\x1b"),
            ("EncryptionLen", "\x00\x01"),
            ("TokenType2", "\x02"),
            ("InstOptOffset", "\x00\x1c"),
            ("InstOptLen", "\x00\x01"),
            ("TokenTypeThrdID", "\x03"),
            ("ThrdIDOffset", "\x00\x1d"),
            ("ThrdIDLen", "\x00\x00"),
            ("ThrdIDTerminator", "\xff"),
            ("VersionStr", "\x09\x00\x0f\xc3"),
            ("SubBuild", "\x00\x00"),
            ("EncryptionStr", "\x02"),
            ("InstOptStr", "\x00"),
        ]
    )

    def calculate(self):
        CalculateCompletePacket = (
            str(self.fields["PacketType"])
            + str(self.fields["Status"])
            + str(self.fields["Len"])
            + str(self.fields["SPID"])
            + str(self.fields["PacketID"])
            + str(self.fields["Window"])
            + str(self.fields["TokenType"])
            + str(self.fields["VersionOffset"])
            + str(self.fields["VersionLen"])
            + str(self.fields["TokenType1"])
            + str(self.fields["EncryptionOffset"])
            + str(self.fields["EncryptionLen"])
            + str(self.fields["TokenType2"])
            + str(self.fields["InstOptOffset"])
            + str(self.fields["InstOptLen"])
            + str(self.fields["TokenTypeThrdID"])
            + str(self.fields["ThrdIDOffset"])
            + str(self.fields["ThrdIDLen"])
            + str(self.fields["ThrdIDTerminator"])
            + str(self.fields["VersionStr"])
            + str(self.fields["SubBuild"])
            + str(self.fields["EncryptionStr"])
            + str(self.fields["InstOptStr"])
        )
        VersionOffset = (
            str(self.fields["TokenType"])
            + str(self.fields["VersionOffset"])
            + str(self.fields["VersionLen"])
            + str(self.fields["TokenType1"])
            + str(self.fields["EncryptionOffset"])
            + str(self.fields["EncryptionLen"])
            + str(self.fields["TokenType2"])
            + str(self.fields["InstOptOffset"])
            + str(self.fields["InstOptLen"])
            + str(self.fields["TokenTypeThrdID"])
            + str(self.fields["ThrdIDOffset"])
            + str(self.fields["ThrdIDLen"])
            + str(self.fields["ThrdIDTerminator"])
        )
        EncryptionOffset = (
            VersionOffset
            + str(self.fields["VersionStr"])
            + str(self.fields["SubBuild"])
        )
        InstOpOffset = EncryptionOffset + str(self.fields["EncryptionStr"])
        ThrdIDOffset = InstOpOffset + str(self.fields["InstOptStr"])

        self.fields["Len"] = StructWithLenPython2or3(">h", len(CalculateCompletePacket))
        # Version
        self.fields["VersionLen"] = StructWithLenPython2or3(
            ">h", len(self.fields["VersionStr"] + self.fields["SubBuild"])
        )
        self.fields["VersionOffset"] = StructWithLenPython2or3(">h", len(VersionOffset))
        # Encryption
        self.fields["EncryptionLen"] = StructWithLenPython2or3(
            ">h", len(self.fields["EncryptionStr"])
        )
        self.fields["EncryptionOffset"] = StructWithLenPython2or3(
            ">h", len(EncryptionOffset)
        )
        # InstOpt
        self.fields["InstOptLen"] = StructWithLenPython2or3(
            ">h", len(self.fields["InstOptStr"])
        )
        self.fields["EncryptionOffset"] = StructWithLenPython2or3(
            ">h", len(InstOpOffset)
        )
        # ThrdIDOffset
        self.fields["ThrdIDOffset"] = StructWithLenPython2or3(">h", len(ThrdIDOffset))


class MSSQLNTLMChallengeAnswer(Packet):
    fields = OrderedDict(
        [
            ("PacketType", "\x04"),
            ("Status", "\x01"),
            ("Len", "\x00\xc7"),
            ("SPID", "\x00\x00"),
            ("PacketID", "\x01"),
            ("Window", "\x00"),
            ("TokenType", "\xed"),
            ("SSPIBuffLen", "\xbc\x00"),
            ("Signature", "NTLMSSP"),
            ("SignatureNull", "\x00"),
            ("MessageType", "\x02\x00\x00\x00"),
            ("TargetNameLen", "\x06\x00"),
            ("TargetNameMaxLen", "\x06\x00"),
            ("TargetNameOffset", "\x38\x00\x00\x00"),
            ("NegoFlags", "\x05\x02\x89\xa2"),
            ("ServerChallenge", ""),
            ("Reserved", "\x00\x00\x00\x00\x00\x00\x00\x00"),
            ("TargetInfoLen", "\x7e\x00"),
            ("TargetInfoMaxLen", "\x7e\x00"),
            ("TargetInfoOffset", "\x3e\x00\x00\x00"),
            ("NTLMOsVersion", "\x0a\x00\x7c\x4f\x00\x00\x00\x0f"),
            ("TargetNameStr", settings.Config.Domain),
            ("Av1", "\x02\x00"),  # nbt name
            ("Av1Len", "\x06\x00"),
            ("Av1Str", settings.Config.Domain),
            ("Av2", "\x01\x00"),  # Server name
            ("Av2Len", "\x14\x00"),
            ("Av2Str", settings.Config.MachineName),
            ("Av3", "\x04\x00"),  # Full Domain name
            ("Av3Len", "\x12\x00"),
            ("Av3Str", settings.Config.DomainName),
            ("Av4", "\x03\x00"),  # Full machine domain name
            ("Av4Len", "\x28\x00"),
            ("Av4Str", settings.Config.MachineName + "." + settings.Config.DomainName),
            ("Av5", "\x05\x00"),  # Domain Forest Name
            ("Av5Len", "\x12\x00"),
            ("Av5Str", settings.Config.DomainName),
            ("Av6", "\x00\x00"),  # AvPairs Terminator
            ("Av6Len", "\x00\x00"),
        ]
    )

    def calculate(self):
        # First convert to unicode
        self.fields["TargetNameStr"] = (
            self.fields["TargetNameStr"].encode("utf-16le").decode("latin-1")
        )
        self.fields["Av1Str"] = (
            self.fields["Av1Str"].encode("utf-16le").decode("latin-1")
        )
        self.fields["Av2Str"] = (
            self.fields["Av2Str"].encode("utf-16le").decode("latin-1")
        )
        self.fields["Av3Str"] = (
            self.fields["Av3Str"].encode("utf-16le").decode("latin-1")
        )
        self.fields["Av4Str"] = (
            self.fields["Av4Str"].encode("utf-16le").decode("latin-1")
        )
        self.fields["Av5Str"] = (
            self.fields["Av5Str"].encode("utf-16le").decode("latin-1")
        )

        # Then calculate
        CalculateCompletePacket = (
            str(self.fields["PacketType"])
            + str(self.fields["Status"])
            + str(self.fields["Len"])
            + str(self.fields["SPID"])
            + str(self.fields["PacketID"])
            + str(self.fields["Window"])
            + str(self.fields["TokenType"])
            + str(self.fields["SSPIBuffLen"])
            + str(self.fields["Signature"])
            + str(self.fields["SignatureNull"])
            + str(self.fields["MessageType"])
            + str(self.fields["TargetNameLen"])
            + str(self.fields["TargetNameMaxLen"])
            + str(self.fields["TargetNameOffset"])
            + str(self.fields["NegoFlags"])
            + str(self.fields["ServerChallenge"])
            + str(self.fields["Reserved"])
            + str(self.fields["TargetInfoLen"])
            + str(self.fields["TargetInfoMaxLen"])
            + str(self.fields["TargetInfoOffset"])
            + str(self.fields["NTLMOsVersion"])
            + str(self.fields["TargetNameStr"])
            + str(self.fields["Av1"])
            + str(self.fields["Av1Len"])
            + str(self.fields["Av1Str"])
            + str(self.fields["Av2"])
            + str(self.fields["Av2Len"])
            + str(self.fields["Av2Str"])
            + str(self.fields["Av3"])
            + str(self.fields["Av3Len"])
            + str(self.fields["Av3Str"])
            + str(self.fields["Av4"])
            + str(self.fields["Av4Len"])
            + str(self.fields["Av4Str"])
            + str(self.fields["Av5"])
            + str(self.fields["Av5Len"])
            + str(self.fields["Av5Str"])
            + str(self.fields["Av6"])
            + str(self.fields["Av6Len"])
        )
        CalculateSSPI = (
            str(self.fields["Signature"])
            + str(self.fields["SignatureNull"])
            + str(self.fields["MessageType"])
            + str(self.fields["TargetNameLen"])
            + str(self.fields["TargetNameMaxLen"])
            + str(self.fields["TargetNameOffset"])
            + str(self.fields["NegoFlags"])
            + str(self.fields["ServerChallenge"])
            + str(self.fields["Reserved"])
            + str(self.fields["TargetInfoLen"])
            + str(self.fields["TargetInfoMaxLen"])
            + str(self.fields["TargetInfoOffset"])
            + str(self.fields["NTLMOsVersion"])
            + str(self.fields["TargetNameStr"])
            + str(self.fields["Av1"])
            + str(self.fields["Av1Len"])
            + str(self.fields["Av1Str"])
            + str(self.fields["Av2"])
            + str(self.fields["Av2Len"])
            + str(self.fields["Av2Str"])
            + str(self.fields["Av3"])
            + str(self.fields["Av3Len"])
            + str(self.fields["Av3Str"])
            + str(self.fields["Av4"])
            + str(self.fields["Av4Len"])
            + str(self.fields["Av4Str"])
            + str(self.fields["Av5"])
            + str(self.fields["Av5Len"])
            + str(self.fields["Av5Str"])
            + str(self.fields["Av6"])
            + str(self.fields["Av6Len"])
        )
        CalculateNameOffset = (
            str(self.fields["Signature"])
            + str(self.fields["SignatureNull"])
            + str(self.fields["MessageType"])
            + str(self.fields["TargetNameLen"])
            + str(self.fields["TargetNameMaxLen"])
            + str(self.fields["TargetNameOffset"])
            + str(self.fields["NegoFlags"])
            + str(self.fields["ServerChallenge"])
            + str(self.fields["Reserved"])
            + str(self.fields["TargetInfoLen"])
            + str(self.fields["TargetInfoMaxLen"])
            + str(self.fields["TargetInfoOffset"])
            + str(self.fields["NTLMOsVersion"])
        )
        CalculateAvPairsOffset = CalculateNameOffset + str(self.fields["TargetNameStr"])
        CalculateAvPairsLen = (
            str(self.fields["Av1"])
            + str(self.fields["Av1Len"])
            + str(self.fields["Av1Str"])
            + str(self.fields["Av2"])
            + str(self.fields["Av2Len"])
            + str(self.fields["Av2Str"])
            + str(self.fields["Av3"])
            + str(self.fields["Av3Len"])
            + str(self.fields["Av3Str"])
            + str(self.fields["Av4"])
            + str(self.fields["Av4Len"])
            + str(self.fields["Av4Str"])
            + str(self.fields["Av5"])
            + str(self.fields["Av5Len"])
            + str(self.fields["Av5Str"])
            + str(self.fields["Av6"])
            + str(self.fields["Av6Len"])
        )

        self.fields["Len"] = StructWithLenPython2or3(">h", len(CalculateCompletePacket))
        self.fields["SSPIBuffLen"] = StructWithLenPython2or3("<i", len(CalculateSSPI))[
            :2
        ]
        # Target Name Offsets
        self.fields["TargetNameOffset"] = StructWithLenPython2or3(
            "<i", len(CalculateNameOffset)
        )
        self.fields["TargetNameLen"] = StructWithLenPython2or3(
            "<i", len(self.fields["TargetNameStr"])
        )[:2]
        self.fields["TargetNameMaxLen"] = StructWithLenPython2or3(
            "<i", len(self.fields["TargetNameStr"])
        )[:2]
        # AvPairs Offsets
        self.fields["TargetInfoOffset"] = StructWithLenPython2or3(
            "<i", len(CalculateAvPairsOffset)
        )
        self.fields["TargetInfoLen"] = StructWithLenPython2or3(
            "<i", len(CalculateAvPairsLen)
        )[:2]
        self.fields["TargetInfoMaxLen"] = StructWithLenPython2or3(
            "<i", len(CalculateAvPairsLen)
        )[:2]
        # AvPairs StrLen
        self.fields["Av1Len"] = StructWithLenPython2or3(
            "<i", len(str(self.fields["Av1Str"]))
        )[:2]
        self.fields["Av2Len"] = StructWithLenPython2or3(
            "<i", len(str(self.fields["Av2Str"]))
        )[:2]
        self.fields["Av3Len"] = StructWithLenPython2or3(
            "<i", len(str(self.fields["Av3Str"]))
        )[:2]
        self.fields["Av4Len"] = StructWithLenPython2or3(
            "<i", len(str(self.fields["Av4Str"]))
        )[:2]
        self.fields["Av5Len"] = StructWithLenPython2or3(
            "<i", len(str(self.fields["Av5Str"]))
        )[:2]


##### SMTP Packets #####
class SMTPGreeting(Packet):
    fields = OrderedDict(
        [
            ("Code", "220"),
            ("Separator", "\x20"),
            ("Message", settings.Config.DomainName + " ESMTP"),
            ("CRLF", "\x0d\x0a"),
        ]
    )


class SMTPAUTH(Packet):
    fields = OrderedDict(
        [
            ("Code0", "250"),
            ("Separator0", "\x2d"),
            ("Message0", settings.Config.DomainName),
            ("CRLF0", "\x0d\x0a"),
            ("Code", "250"),
            ("Separator", "\x20"),
            ("Message", "AUTH LOGIN PLAIN XYMCOOKIE"),
            ("CRLF", "\x0d\x0a"),
        ]
    )


class SMTPAUTH1(Packet):
    fields = OrderedDict(
        [
            ("Code", "334"),
            ("Separator", "\x20"),
            ("Message", "VXNlcm5hbWU6"),  # Username
            ("CRLF", "\x0d\x0a"),
        ]
    )


class SMTPAUTH2(Packet):
    fields = OrderedDict(
        [
            ("Code", "334"),
            ("Separator", "\x20"),
            ("Message", "UGFzc3dvcmQ6"),  # Password
            ("CRLF", "\x0d\x0a"),
        ]
    )


##### IMAP Packets #####
class IMAPGreeting(Packet):
    fields = OrderedDict(
        [
            ("Code", "* OK IMAP4 service is ready."),
            ("CRLF", "\r\n"),
        ]
    )


class IMAPCapability(Packet):
    fields = OrderedDict(
        [
            ("Code", "* CAPABILITY IMAP4 IMAP4rev1 AUTH=PLAIN"),
            ("CRLF", "\r\n"),
        ]
    )


class IMAPCapabilityEnd(Packet):
    fields = OrderedDict(
        [
            ("Tag", ""),
            ("Message", " OK CAPABILITY completed."),
            ("CRLF", "\r\n"),
        ]
    )


##### MQTT Packets #####
class MQTTv3v4ResponsePacket(Packet):
    fields = OrderedDict(
        [
            ("Type", "\x20"),
            ("Len", "\x02"),
            ("Session", "\x00"),
            ("Code", "\x04"),
        ]
    )


class MQTTv5ResponsePacket(Packet):
    fields = OrderedDict(
        [
            ("Type", "\x20"),
            ("Len", "\x03"),
            ("Session", "\x00"),
            ("Code", "\x86"),
            ("Prop", "\x00"),
        ]
    )


##### POP3 Packets #####
class POPOKPacket(Packet):
    fields = OrderedDict(
        [
            ("Code", "+OK"),
            ("CRLF", "\r\n"),
        ]
    )


class POPNotOKPacket(Packet):
    fields = OrderedDict(
        [
            ("Code", "-ERR"),
            ("CRLF", "\r\n"),
        ]
    )


##### LDAP Packets #####
class LDAPSearchDefaultPacket(Packet):
    fields = OrderedDict(
        [
            ("ParserHeadASNID", "\x30"),
            ("ParserHeadASNLen", "\x0c"),
            ("MessageIDASNID", "\x02"),
            ("MessageIDASNLen", "\x01"),
            ("MessageIDASNStr", "\x0f"),
            ("OpHeadASNID", "\x65"),
            ("OpHeadASNIDLen", "\x07"),
            ("SearchDoneSuccess", "\x0a\x01\x00\x04\x00\x04\x00"),  # No Results.
        ]
    )


class LDAPSearchSupportedCapabilitiesPacket(Packet):
    fields = OrderedDict(
        [
            ("ParserHeadASNID", "\x30"),
            ("ParserHeadASNLenOfLen", "\x84"),
            ("ParserHeadASNLen", "\x00\x00\x00\x7e"),  # 126
            ("MessageIDASNID", "\x02"),
            ("MessageIDASNLen", "\x01"),
            ("MessageIDASNStr", "\x02"),
            ("OpHeadASNID", "\x64"),
            ("OpHeadASNIDLenOfLen", "\x84"),
            ("OpHeadASNIDLen", "\x00\x00\x00\x75"),  # 117
            ("ObjectName", "\x04\x00"),
            ("SearchAttribASNID", "\x30"),
            ("SearchAttribASNLenOfLen", "\x84"),
            ("SearchAttribASNLen", "\x00\x00\x00\x6d"),  # 109
            ("SearchAttribASNID1", "\x30"),
            ("SearchAttribASN1LenOfLen", "\x84"),
            ("SearchAttribASN1Len", "\x00\x00\x00\x67"),  # 103
            ("SearchAttribASN2ID", "\x04"),
            ("SearchAttribASN2Len", "\x15"),  # 21
            ("SearchAttribASN2Str", "supportedCapabilities"),
            ("SearchAttribASN3ID", "\x31"),
            ("SearchAttribASN3LenOfLen", "\x84"),
            ("SearchAttribASN3Len", "\x00\x00\x00\x4a"),
            ("SearchAttrib1ASNID", "\x04"),
            ("SearchAttrib1ASNLen", "\x16"),  # 22
            ("SearchAttrib1ASNStr", "1.2.840.113556.1.4.800"),
            ("SearchAttrib2ASNID", "\x04"),
            ("SearchAttrib2ASNLen", "\x17"),  # 23
            ("SearchAttrib2ASNStr", "1.2.840.113556.1.4.1670"),
            ("SearchAttrib3ASNID", "\x04"),
            ("SearchAttrib3ASNLen", "\x17"),  # 23
            ("SearchAttrib3ASNStr", "1.2.840.113556.1.4.1791"),
            ("SearchDoneASNID", "\x30"),
            ("SearchDoneASNLenOfLen", "\x84"),
            ("SearchDoneASNLen", "\x00\x00\x00\x10"),  # 16
            ("MessageIDASN2ID", "\x02"),
            ("MessageIDASN2Len", "\x01"),
            ("MessageIDASN2Str", "\x02"),
            ("SearchDoneStr", "\x65\x84\x00\x00\x00\x07\x0a\x01\x00\x04\x00\x04\x00"),
            ## No need to calculate anything this time, this packet is generic.
        ]
    )


class LDAPSearchSupportedMechanismsPacket(Packet):
    fields = OrderedDict(
        [
            ("ParserHeadASNID", "\x30"),
            ("ParserHeadASNLenOfLen", "\x84"),
            ("ParserHeadASNLen", "\x00\x00\x00\x60"),  # 96
            ("MessageIDASNID", "\x02"),
            ("MessageIDASNLen", "\x01"),
            ("MessageIDASNStr", "\x02"),
            ("OpHeadASNID", "\x64"),
            ("OpHeadASNIDLenOfLen", "\x84"),
            ("OpHeadASNIDLen", "\x00\x00\x00\x57"),  # 87
            ("ObjectName", "\x04\x00"),
            ("SearchAttribASNID", "\x30"),
            ("SearchAttribASNLenOfLen", "\x84"),
            ("SearchAttribASNLen", "\x00\x00\x00\x4f"),  # 79
            ("SearchAttribASNID1", "\x30"),
            ("SearchAttribASN1LenOfLen", "\x84"),
            ("SearchAttribASN1Len", "\x00\x00\x00\x49"),  # 73
            ("SearchAttribASN2ID", "\x04"),
            ("SearchAttribASN2Len", "\x17"),  # 23
            ("SearchAttribASN2Str", "supportedSASLMechanisms"),
            ("SearchAttribASN3ID", "\x31"),
            ("SearchAttribASN3LenOfLen", "\x84"),
            ("SearchAttribASN3Len", "\x00\x00\x00\x2a"),  # 42
            ("SearchAttrib1ASNID", "\x04"),
            ("SearchAttrib1ASNLen", "\x06"),  # 6
            ("SearchAttrib1ASNStr", "GSSAPI"),
            ("SearchAttrib2ASNID", "\x04"),
            ("SearchAttrib2ASNLen", "\x0a"),  # 10
            ("SearchAttrib2ASNStr", "GSS-SPNEGO"),
            ("SearchAttrib3ASNID", "\x04"),
            ("SearchAttrib3ASNLen", "\x08"),  # 8
            ("SearchAttrib3ASNStr", "EXTERNAL"),
            ("SearchAttrib4ASNID", "\x04"),
            ("SearchAttrib4ASNLen", "\x0a"),  # 10
            ("SearchAttrib4ASNStr", "DIGEST-MD5"),
            ("SearchDoneASNID", "\x30"),
            ("SearchDoneASNLenOfLen", "\x84"),
            ("SearchDoneASNLen", "\x00\x00\x00\x10"),  # 16
            ("MessageIDASN2ID", "\x02"),
            ("MessageIDASN2Len", "\x01"),
            ("MessageIDASN2Str", "\x02"),
            ("SearchDoneStr", "\x65\x84\x00\x00\x00\x07\x0a\x01\x00\x04\x00\x04\x00"),
            ## No need to calculate anything this time, this packet is generic.
        ]
    )


class LDAPNTLMChallenge(Packet):
    fields = OrderedDict(
        [
            ("ParserHeadASNID", "\x30"),
            ("ParserHeadASNLenOfLen", "\x84"),
            ("ParserHeadASNLen", "\x00\x00\x00\xd0"),  # 208
            ("MessageIDASNID", "\x02"),
            ("MessageIDASNLen", "\x01"),
            ("MessageIDASNStr", "\x02"),
            ("OpHeadASNID", "\x61"),
            ("OpHeadASNIDLenOfLen", "\x84"),
            ("OpHeadASNIDLen", "\x00\x00\x00\xc7"),  # 199
            ("Status", "\x0a"),
            ("StatusASNLen", "\x01"),
            ("StatusASNStr", "\x0e"),  # In Progress.
            ("MatchedDN", "\x04\x00"),  # Null
            ("ErrorMessage", "\x04\x00"),  # Null
            ("SequenceHeader", "\x87"),
            ("SequenceHeaderLenOfLen", "\x81"),
            ("SequenceHeaderLen", "\x82"),  # 188
            ("NTLMSSPSignature", "NTLMSSP"),
            ("NTLMSSPSignatureNull", "\x00"),
            ("NTLMSSPMessageType", "\x02\x00\x00\x00"),
            ("NTLMSSPNtWorkstationLen", "\x1e\x00"),
            ("NTLMSSPNtWorkstationMaxLen", "\x1e\x00"),
            ("NTLMSSPNtWorkstationBuffOffset", "\x38\x00\x00\x00"),
            (
                "NTLMSSPNtNegotiateFlags",
                (
                    "\x15\x82\x81\xe2"
                    if settings.Config.NOESS_On_Off
                    else "\x15\x82\x89\xe2"
                ),
            ),
            ("NTLMSSPNtServerChallenge", "\x81\x22\x33\x34\x55\x46\xe7\x88"),
            ("NTLMSSPNtReserved", "\x00\x00\x00\x00\x00\x00\x00\x00"),
            ("NTLMSSPNtTargetInfoLen", "\x94\x00"),
            ("NTLMSSPNtTargetInfoMaxLen", "\x94\x00"),
            ("NTLMSSPNtTargetInfoBuffOffset", "\x56\x00\x00\x00"),
            ("NegTokenInitSeqMechMessageVersionHigh", "\x0a"),
            ("NegTokenInitSeqMechMessageVersionLow", "\x00"),
            ("NegTokenInitSeqMechMessageVersionBuilt", "\x7c\x4f"),
            ("NegTokenInitSeqMechMessageVersionReserved", "\x00\x00\x00"),
            ("NegTokenInitSeqMechMessageVersionNTLMType", "\x0f"),
            ("NTLMSSPNtWorkstationName", settings.Config.Domain),
            ("NTLMSSPNTLMChallengeAVPairsId", "\x02\x00"),
            ("NTLMSSPNTLMChallengeAVPairsLen", "\x0a\x00"),
            ("NTLMSSPNTLMChallengeAVPairsUnicodeStr", settings.Config.Domain),
            ("NTLMSSPNTLMChallengeAVPairs1Id", "\x01\x00"),
            ("NTLMSSPNTLMChallengeAVPairs1Len", "\x1e\x00"),
            ("NTLMSSPNTLMChallengeAVPairs1UnicodeStr", settings.Config.MachineName),
            ("NTLMSSPNTLMChallengeAVPairs2Id", "\x04\x00"),
            ("NTLMSSPNTLMChallengeAVPairs2Len", "\x1e\x00"),
            (
                "NTLMSSPNTLMChallengeAVPairs2UnicodeStr",
                settings.Config.MachineName + "." + settings.Config.DomainName,
            ),
            ("NTLMSSPNTLMChallengeAVPairs3Id", "\x03\x00"),
            ("NTLMSSPNTLMChallengeAVPairs3Len", "\x1e\x00"),
            ("NTLMSSPNTLMChallengeAVPairs3UnicodeStr", settings.Config.DomainName),
            ("NTLMSSPNTLMChallengeAVPairs5Id", "\x05\x00"),
            ("NTLMSSPNTLMChallengeAVPairs5Len", "\x04\x00"),
            ("NTLMSSPNTLMChallengeAVPairs5UnicodeStr", settings.Config.DomainName),
            ("NTLMSSPNTLMChallengeAVPairs6Id", "\x00\x00"),
            ("NTLMSSPNTLMChallengeAVPairs6Len", "\x00\x00"),
        ]
    )

    def calculate(self):

        ###### Convert strings to Unicode first
        self.fields["NTLMSSPNtWorkstationName"] = (
            self.fields["NTLMSSPNtWorkstationName"].encode("utf-16le").decode("latin-1")
        )
        self.fields["NTLMSSPNTLMChallengeAVPairsUnicodeStr"] = (
            self.fields["NTLMSSPNTLMChallengeAVPairsUnicodeStr"]
            .encode("utf-16le")
            .decode("latin-1")
        )
        self.fields["NTLMSSPNTLMChallengeAVPairs1UnicodeStr"] = (
            self.fields["NTLMSSPNTLMChallengeAVPairs1UnicodeStr"]
            .encode("utf-16le")
            .decode("latin-1")
        )
        self.fields["NTLMSSPNTLMChallengeAVPairs2UnicodeStr"] = (
            self.fields["NTLMSSPNTLMChallengeAVPairs2UnicodeStr"]
            .encode("utf-16le")
            .decode("latin-1")
        )
        self.fields["NTLMSSPNTLMChallengeAVPairs3UnicodeStr"] = (
            self.fields["NTLMSSPNTLMChallengeAVPairs3UnicodeStr"]
            .encode("utf-16le")
            .decode("latin-1")
        )
        self.fields["NTLMSSPNTLMChallengeAVPairs5UnicodeStr"] = (
            self.fields["NTLMSSPNTLMChallengeAVPairs5UnicodeStr"]
            .encode("utf-16le")
            .decode("latin-1")
        )

        ###### Workstation Offset
        CalculateOffsetWorkstation = (
            str(self.fields["NTLMSSPSignature"])
            + str(self.fields["NTLMSSPSignatureNull"])
            + str(self.fields["NTLMSSPMessageType"])
            + str(self.fields["NTLMSSPNtWorkstationLen"])
            + str(self.fields["NTLMSSPNtWorkstationMaxLen"])
            + str(self.fields["NTLMSSPNtWorkstationBuffOffset"])
            + str(self.fields["NTLMSSPNtNegotiateFlags"])
            + str(self.fields["NTLMSSPNtServerChallenge"])
            + str(self.fields["NTLMSSPNtReserved"])
            + str(self.fields["NTLMSSPNtTargetInfoLen"])
            + str(self.fields["NTLMSSPNtTargetInfoMaxLen"])
            + str(self.fields["NTLMSSPNtTargetInfoBuffOffset"])
            + str(self.fields["NegTokenInitSeqMechMessageVersionHigh"])
            + str(self.fields["NegTokenInitSeqMechMessageVersionLow"])
            + str(self.fields["NegTokenInitSeqMechMessageVersionBuilt"])
            + str(self.fields["NegTokenInitSeqMechMessageVersionReserved"])
            + str(self.fields["NegTokenInitSeqMechMessageVersionNTLMType"])
        )
        ###### AvPairs Offset
        CalculateLenAvpairs = (
            str(self.fields["NTLMSSPNTLMChallengeAVPairsId"])
            + str(self.fields["NTLMSSPNTLMChallengeAVPairsLen"])
            + str(self.fields["NTLMSSPNTLMChallengeAVPairsUnicodeStr"])
            + str(self.fields["NTLMSSPNTLMChallengeAVPairs1Id"])
            + str(self.fields["NTLMSSPNTLMChallengeAVPairs1Len"])
            + str(self.fields["NTLMSSPNTLMChallengeAVPairs1UnicodeStr"])
            + (self.fields["NTLMSSPNTLMChallengeAVPairs2Id"])
            + str(self.fields["NTLMSSPNTLMChallengeAVPairs2Len"])
            + str(self.fields["NTLMSSPNTLMChallengeAVPairs2UnicodeStr"])
            + (self.fields["NTLMSSPNTLMChallengeAVPairs3Id"])
            + str(self.fields["NTLMSSPNTLMChallengeAVPairs3Len"])
            + str(self.fields["NTLMSSPNTLMChallengeAVPairs3UnicodeStr"])
            + (self.fields["NTLMSSPNTLMChallengeAVPairs5Id"])
            + str(self.fields["NTLMSSPNTLMChallengeAVPairs5Len"])
            + str(self.fields["NTLMSSPNTLMChallengeAVPairs5UnicodeStr"])
            + (self.fields["NTLMSSPNTLMChallengeAVPairs6Id"])
            + str(self.fields["NTLMSSPNTLMChallengeAVPairs6Len"])
        )
        ###### LDAP Packet Len
        CalculatePacketLen = (
            str(self.fields["MessageIDASNID"])
            + str(self.fields["MessageIDASNLen"])
            + str(self.fields["MessageIDASNStr"])
            + str(self.fields["OpHeadASNID"])
            + str(self.fields["OpHeadASNIDLenOfLen"])
            + str(self.fields["OpHeadASNIDLen"])
            + str(self.fields["Status"])
            + str(self.fields["StatusASNLen"])
            + str(self.fields["StatusASNStr"])
            + str(self.fields["MatchedDN"])
            + str(self.fields["ErrorMessage"])
            + str(self.fields["SequenceHeader"])
            + str(self.fields["SequenceHeaderLen"])
            + str(self.fields["SequenceHeaderLenOfLen"])
            + CalculateOffsetWorkstation
            + str(self.fields["NTLMSSPNtWorkstationName"])
            + CalculateLenAvpairs
        )
        OperationPacketLen = (
            str(self.fields["Status"])
            + str(self.fields["StatusASNLen"])
            + str(self.fields["StatusASNStr"])
            + str(self.fields["MatchedDN"])
            + str(self.fields["ErrorMessage"])
            + str(self.fields["SequenceHeader"])
            + str(self.fields["SequenceHeaderLen"])
            + str(self.fields["SequenceHeaderLenOfLen"])
            + CalculateOffsetWorkstation
            + str(self.fields["NTLMSSPNtWorkstationName"])
            + CalculateLenAvpairs
        )
        NTLMMessageLen = (
            CalculateOffsetWorkstation
            + str(self.fields["NTLMSSPNtWorkstationName"])
            + CalculateLenAvpairs
        )

        ##### LDAP Len Calculation:
        self.fields["ParserHeadASNLen"] = StructWithLenPython2or3(
            ">i", len(CalculatePacketLen)
        )
        self.fields["OpHeadASNIDLen"] = StructWithLenPython2or3(
            ">i", len(OperationPacketLen)
        )
        self.fields["SequenceHeaderLen"] = StructWithLenPython2or3(
            ">B", len(NTLMMessageLen)
        )
        ##### Workstation Offset Calculation:
        self.fields["NTLMSSPNtWorkstationBuffOffset"] = StructWithLenPython2or3(
            "<i", len(CalculateOffsetWorkstation)
        )
        self.fields["NTLMSSPNtWorkstationLen"] = StructWithLenPython2or3(
            "<h", len(str(self.fields["NTLMSSPNtWorkstationName"]))
        )
        self.fields["NTLMSSPNtWorkstationMaxLen"] = StructWithLenPython2or3(
            "<h", len(str(self.fields["NTLMSSPNtWorkstationName"]))
        )
        ##### IvPairs Offset Calculation:
        self.fields["NTLMSSPNtTargetInfoBuffOffset"] = StructWithLenPython2or3(
            "<i",
            len(
                CalculateOffsetWorkstation
                + str(self.fields["NTLMSSPNtWorkstationName"])
            ),
        )
        self.fields["NTLMSSPNtTargetInfoLen"] = StructWithLenPython2or3(
            "<h", len(CalculateLenAvpairs)
        )
        self.fields["NTLMSSPNtTargetInfoMaxLen"] = StructWithLenPython2or3(
            "<h", len(CalculateLenAvpairs)
        )
        ##### IvPair Calculation:
        self.fields["NTLMSSPNTLMChallengeAVPairs5Len"] = StructWithLenPython2or3(
            "<h", len(str(self.fields["NTLMSSPNTLMChallengeAVPairs5UnicodeStr"]))
        )
        self.fields["NTLMSSPNTLMChallengeAVPairs3Len"] = StructWithLenPython2or3(
            "<h", len(str(self.fields["NTLMSSPNTLMChallengeAVPairs3UnicodeStr"]))
        )
        self.fields["NTLMSSPNTLMChallengeAVPairs2Len"] = StructWithLenPython2or3(
            "<h", len(str(self.fields["NTLMSSPNTLMChallengeAVPairs2UnicodeStr"]))
        )
        self.fields["NTLMSSPNTLMChallengeAVPairs1Len"] = StructWithLenPython2or3(
            "<h", len(str(self.fields["NTLMSSPNTLMChallengeAVPairs1UnicodeStr"]))
        )
        self.fields["NTLMSSPNTLMChallengeAVPairsLen"] = StructWithLenPython2or3(
            "<h", len(str(self.fields["NTLMSSPNTLMChallengeAVPairsUnicodeStr"]))
        )


##cldap
class CLDAPNetlogon(Packet):
    fields = OrderedDict(
        [
            ("ParserHeadASNID", "\x30"),
            ("ParserHeadASNLenOfLen", "\x84"),
            ("ParserHeadASNLen", "\x00\x00\x00\x9d"),
            ("MessageIDASNID", "\x02"),
            ("MessageIDASNLen", "\x02"),
            ("MessageIDASNStr", "\x00\xc4"),  # First MsgID
            ("OpHeadASNID", "\x64"),
            ("OpHeadASNIDLenOfLen", "\x84"),
            ("OpHeadASNIDLen", "\x00\x00\x00\xc7"),
            ("Status", "\x04"),
            ("StatusASNLen", "\x00"),
            ("StatusASNStr", ""),
            ("SequenceHeader", "\x30"),
            ("SequenceHeaderLenOfLen", "\x84"),
            ("SequenceHeaderLen", "\x00\x00\x00\x8b"),
            # Netlogon packet starts here....
            ("PartAttribHead", "\x30"),
            ("PartAttribHeadLenofLen", "\x84"),
            ("PartAttribHeadLen", "\x00\x00\x00\x85"),
            ("NetlogonHead", "\x04"),
            ("NetlogonLen", "\x08"),
            ("NetlogonStr", "Netlogon"),
            ("NetAttribHead", "\x31"),
            ("NetAttribLenOfLen", "\x84"),
            ("NetAttribLen", "\x00\x00\x00\x75"),
            ("NetAttrib1Head", "\x04"),
            ("NetAttrib1Len", "\x73"),
            ("NTLogonOpcode", "\x17\x00"),  # SamLogonRespEx opcode
            ("NTLogonSbz", "\x00\x00"),
            ("NTLogonFlags", "\xfd\xf3\x03\x00"),
            (
                "NTLogonDomainGUID",
                "\x3e\xde\x55\x61\xf0\x79\x8f\x44\x83\x10\x83\x63\x08\xd4\xbb\x26",
            ),
            ("NTLogonForestName", "\x04\x73\x6d\x62\x33\x05\x6c\x6f\x63\x61\x6c"),
            ("NTLogonForestNameNull", "\x00"),
            ("NTLogonDomainNamePtr", "\xc0"),
            ("NTLogonDomainNamePtrOffset", "\x18"),
            (
                "NTLogonPDCNBTName",
                "\x0f\x57\x49\x4e\x2d\x48\x51\x46\x42\x34\x4f\x52\x34\x4b\x49\x4d",
            ),
            ("NTLogonPDCNBTTLDPtr", "\xc0\x18"),
            ("NTLogonDomainNameShort", "\x04\x53\x4d\x42\x33"),
            ("NTLogonDomainNameShortNull", "\x00"),
            (
                "NTLogonDomainNBTName",
                "\x0f\x57\x49\x4e\x2d\x48\x51\x46\x42\x34\x4f\x52\x34\x4b\x49\x4d",
            ),
            ("NTLogonDomainNBTNameNull", "\x00"),
            ("NTLogonUsername", "\x00"),
            (
                "DCSiteName",
                "\x17\x44\x65\x66\x61\x75\x6c\x74\x2d\x46\x69\x72\x73\x74\x2d\x53\x69\x74\x65\x2d\x4e\x61\x6d\x65\x00",
            ),  # static 95% PDC use this.
            ("ClientSiteNamePtr", "\xc0"),
            ("ClientSiteNamePtrOffset", "\x50"),
            ("NTLogonVersion", "\x05\x00\x00\x00"),
            ("LMNTToken", "\xff\xff"),
            ("LM2Token", "\xff\xff"),  # End netlogon.
            ("CLDAPMessageIDHeader", "\x30\x84\x00\x00\x00\x11"),
            ("CLDAPMessageIDInt", "\x02"),
            ("CLDAPMessageIDlen", "\x02"),
            ("CLDAPMessageIDStr", "\x00\xc4"),  # Second MsgID
            ("SearchDone", "\x65\x84\x00\x00\x00\x07"),
            ("SearchDoneMatched", "\x0a\x01\x00\x04\x00\x04\x00"),
        ]
    )

    def calculate(self):
        ###### LDAP Packet Len
        CalculatePacketLen = (
            str(self.fields["MessageIDASNID"])
            + str(self.fields["MessageIDASNLen"])
            + str(self.fields["MessageIDASNStr"])
            + str(self.fields["OpHeadASNID"])
            + str(self.fields["OpHeadASNIDLenOfLen"])
            + str(self.fields["OpHeadASNIDLen"])
            + str(self.fields["Status"])
            + str(self.fields["StatusASNLen"])
            + str(self.fields["StatusASNStr"])
            + str(self.fields["SequenceHeader"])
            + str(self.fields["SequenceHeaderLen"])
            + str(self.fields["SequenceHeaderLenOfLen"])
        )
        OperationPacketLen = (
            str(self.fields["Status"])
            + str(self.fields["StatusASNLen"])
            + str(self.fields["StatusASNStr"])
            + str(self.fields["SequenceHeader"])
            + str(self.fields["SequenceHeaderLen"])
            + str(self.fields["SequenceHeaderLenOfLen"])
        )

        ###### Netlogon + Search Successfull Len
        CalculateNetlogonLen = (
            str(self.fields["NTLogonOpcode"])
            + str(self.fields["NTLogonSbz"])
            + str(self.fields["NTLogonFlags"])
            + str(self.fields["NTLogonDomainGUID"])
            + str(self.fields["NTLogonForestName"])
            + str(self.fields["NTLogonForestNameNull"])
            + str(self.fields["NTLogonDomainNamePtr"])
            + str(self.fields["NTLogonDomainNamePtrOffset"])
            + str(self.fields["NTLogonPDCNBTName"])
            + str(self.fields["NTLogonPDCNBTTLDPtr"])
            + str(self.fields["NTLogonDomainNameShort"])
            + str(self.fields["NTLogonDomainNameShortNull"])
            + str(self.fields["NTLogonDomainNBTName"])
            + str(self.fields["NTLogonDomainNBTNameNull"])
            + str(self.fields["NTLogonUsername"])
            + str(self.fields["DCSiteName"])
            + str(self.fields["ClientSiteNamePtr"])
            + str(self.fields["ClientSiteNamePtrOffset"])
            + str(self.fields["NTLogonVersion"])
            + str(self.fields["LMNTToken"])
            + str(self.fields["LM2Token"])
        )  # 115 now.

        CalculateNetlogonOffset = (
            str(self.fields["NTLogonForestName"])
            + str(self.fields["NTLogonForestNameNull"])
            + str(self.fields["NTLogonDomainNamePtr"])
            + str(self.fields["NTLogonDomainNamePtrOffset"])
            + str(self.fields["NTLogonPDCNBTName"])
            + str(self.fields["NTLogonPDCNBTTLDPtr"])
            + str(self.fields["NTLogonDomainNameShort"])
            + str(self.fields["NTLogonDomainNameShortNull"])
            + str(self.fields["NTLogonDomainNBTName"])
            + str(self.fields["NTLogonDomainNBTNameNull"])
            + str(self.fields["NTLogonUsername"])
            + str(self.fields["DCSiteName"])
        )

        ##### LDAP ASN Len Calculation:
        self.fields["NetAttrib1Len"] = StructWithLenPython2or3(
            ">B", len(CalculateNetlogonLen)
        )
        self.fields["NetAttribLen"] = StructWithLenPython2or3(
            ">L", len(CalculateNetlogonLen) + 2
        )
        self.fields["PartAttribHeadLen"] = StructWithLenPython2or3(
            ">L", len(CalculateNetlogonLen) + 18
        )
        self.fields["SequenceHeaderLen"] = StructWithLenPython2or3(
            ">L", len(CalculateNetlogonLen) + 24
        )
        self.fields["OpHeadASNIDLen"] = StructWithLenPython2or3(
            ">L", len(CalculateNetlogonLen) + 32
        )
        self.fields["ParserHeadASNLen"] = StructWithLenPython2or3(
            ">L", len(CalculateNetlogonLen) + 42
        )
        ######
        self.fields["ClientSiteNamePtrOffset"] = StructWithLenPython2or3(
            ">B", len(CalculateNetlogonOffset) - 1
        )


##### SMB Packets #####
class SMBHeader(Packet):
    fields = OrderedDict(
        [
            ("proto", "\xff\x53\x4d\x42"),
            ("cmd", "\x72"),
            ("errorcode", "\x00\x00\x00\x00"),
            ("flag1", "\x00"),
            ("flag2", "\x00\x00"),
            ("pidhigh", "\x00\x00"),
            ("signature", "\x00\x00\x00\x00\x00\x00\x00\x00"),
            ("reserved", "\x00\x00"),
            ("tid", "\x00\x00"),
            ("pid", "\x00\x00"),
            ("uid", "\x00\x00"),
            ("mid", "\x00\x00"),
        ]
    )


class SMBNego(Packet):
    fields = OrderedDict([("wordcount", "\x00"), ("bcc", "\x62\x00"), ("data", "")])

    def calculate(self):
        self.fields["bcc"] = StructPython2or3("<h", self.fields["data"])


class SMBNegoData(Packet):
    fields = OrderedDict(
        [
            ("wordcount", "\x00"),
            ("bcc", "\x54\x00"),
            ("separator1", "\x02"),
            (
                "dialect1",
                "\x50\x43\x20\x4e\x45\x54\x57\x4f\x52\x4b\x20\x50\x52\x4f\x47\x52\x41\x4d\x20\x31\x2e\x30\x00",
            ),
            ("separator2", "\x02"),
            ("dialect2", "\x4c\x41\x4e\x4d\x41\x4e\x31\x2e\x30\x00"),
        ]
    )

    def calculate(self):
        CalculateBCC = str(self.fields["separator1"]) + str(self.fields["dialect1"])
        CalculateBCC += str(self.fields["separator2"]) + str(self.fields["dialect2"])
        self.fields["bcc"] = StructWithLenPython2or3("<h", len(CalculateBCC))


class SMBSessionData(Packet):
    fields = OrderedDict(
        [
            ("wordcount", "\x0a"),
            ("AndXCommand", "\xff"),
            ("reserved", "\x00"),
            ("andxoffset", "\x00\x00"),
            ("maxbuff", "\xff\xff"),
            ("maxmpx", "\x02\x00"),
            ("vcnum", "\x01\x00"),
            ("sessionkey", "\x00\x00\x00\x00"),
            ("PasswordLen", "\x18\x00"),
            ("reserved2", "\x00\x00\x00\x00"),
            ("bcc", "\x3b\x00"),
            ("AccountPassword", ""),
            ("AccountName", ""),
            ("AccountNameTerminator", "\x00"),
            ("PrimaryDomain", "WORKGROUP"),
            ("PrimaryDomainTerminator", "\x00"),
            ("NativeOs", "Unix"),
            ("NativeOsTerminator", "\x00"),
            ("NativeLanman", "Samba"),
            ("NativeLanmanTerminator", "\x00"),
        ]
    )

    def calculate(self):
        CompleteBCC = (
            str(self.fields["AccountPassword"])
            + str(self.fields["AccountName"])
            + str(self.fields["AccountNameTerminator"])
            + str(self.fields["PrimaryDomain"])
            + str(self.fields["PrimaryDomainTerminator"])
            + str(self.fields["NativeOs"])
            + str(self.fields["NativeOsTerminator"])
            + str(self.fields["NativeLanman"])
            + str(self.fields["NativeLanmanTerminator"])
        )
        self.fields["bcc"] = StructWithLenPython2or3("<h", len(CompleteBCC))
        self.fields["PasswordLen"] = StructWithLenPython2or3(
            "<h", len(str(self.fields["AccountPassword"]))
        )


class SMBNegoFingerData(Packet):
    fields = OrderedDict(
        [
            ("separator1", "\x02"),
            (
                "dialect1",
                "\x50\x43\x20\x4e\x45\x54\x57\x4f\x52\x4b\x20\x50\x52\x4f\x47\x52\x41\x4d\x20\x31\x2e\x30\x00",
            ),
            ("separator2", "\x02"),
            ("dialect2", "\x4c\x41\x4e\x4d\x41\x4e\x31\x2e\x30\x00"),
            ("separator3", "\x02"),
            (
                "dialect3",
                "\x57\x69\x6e\x64\x6f\x77\x73\x20\x66\x6f\x72\x20\x57\x6f\x72\x6b\x67\x72\x6f\x75\x70\x73\x20\x33\x2e\x31\x61\x00",
            ),
            ("separator4", "\x02"),
            ("dialect4", "\x4c\x4d\x31\x2e\x32\x58\x30\x30\x32\x00"),
            ("separator5", "\x02"),
            ("dialect5", "\x4c\x41\x4e\x4d\x41\x4e\x32\x2e\x31\x00"),
            ("separator6", "\x02"),
            ("dialect6", "\x4e\x54\x20\x4c\x4d\x20\x30\x2e\x31\x32\x00"),
        ]
    )


class SMBSessionFingerData(Packet):
    fields = OrderedDict(
        [
            ("wordcount", "\x0c"),
            ("AndXCommand", "\xff"),
            ("reserved", "\x00"),
            ("andxoffset", "\x00\x00"),
            ("maxbuff", "\x04\x11"),
            ("maxmpx", "\x32\x00"),
            ("vcnum", "\x00\x00"),
            ("sessionkey", "\x00\x00\x00\x00"),
            ("securitybloblength", "\x4a\x00"),
            ("reserved2", "\x00\x00\x00\x00"),
            ("capabilities", "\xd4\x00\x00\xa0"),
            ("bcc1", ""),
            (
                "Data",
                "\x60\x48\x06\x06\x2b\x06\x01\x05\x05\x02\xa0\x3e\x30\x3c\xa0\x0e\x30\x0c\x06\x0a\x2b\x06\x01\x04\x01\x82\x37\x02\x02\x0a\xa2\x2a\x04\x28\x4e\x54\x4c\x4d\x53\x53\x50\x00\x01\x00\x00\x00\x07\x82\x08\xa2\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x05\x01\x28\x0a\x00\x00\x00\x0f\x00\x57\x00\x69\x00\x6e\x00\x64\x00\x6f\x00\x77\x00\x73\x00\x20\x00\x32\x00\x30\x00\x30\x00\x32\x00\x20\x00\x53\x00\x65\x00\x72\x00\x76\x00\x69\x00\x63\x00\x65\x00\x20\x00\x50\x00\x61\x00\x63\x00\x6b\x00\x20\x00\x33\x00\x20\x00\x32\x00\x36\x00\x30\x00\x30\x00\x00\x00\x57\x00\x69\x00\x6e\x00\x64\x00\x6f\x00\x77\x00\x73\x00\x20\x00\x32\x00\x30\x00\x30\x00\x32\x00\x20\x00\x35\x00\x2e\x00\x31\x00\x00\x00\x00\x00",
            ),
        ]
    )

    def calculate(self):
        self.fields["bcc1"] = StructPython2or3("<h", self.fields["Data"])


class SMBTreeConnectData(Packet):
    fields = OrderedDict(
        [
            ("Wordcount", "\x04"),
            ("AndXCommand", "\xff"),
            ("Reserved", "\x00"),
            ("Andxoffset", "\x00\x00"),
            ("Flags", "\x08\x00"),
            ("PasswdLen", "\x01\x00"),
            ("Bcc", "\x1b\x00"),
            ("Passwd", "\x00"),
            ("Path", ""),
            ("PathTerminator", "\x00"),
            ("Service", "?????"),
            ("Terminator", "\x00"),
        ]
    )

    def calculate(self):
        self.fields["PasswdLen"] = StructWithLenPython2or3(
            "<h", len(str(self.fields["Passwd"]))
        )[:2]
        BccComplete = (
            str(self.fields["Passwd"])
            + str(self.fields["Path"])
            + str(self.fields["PathTerminator"])
            + str(self.fields["Service"])
            + str(self.fields["Terminator"])
        )
        self.fields["Bcc"] = StructWithLenPython2or3("<h", len(BccComplete))


class RAPNetServerEnum3Data(Packet):
    fields = OrderedDict(
        [
            ("Command", "\xd7\x00"),
            ("ParamDescriptor", "WrLehDzz"),
            ("ParamDescriptorTerminator", "\x00"),
            ("ReturnDescriptor", "B16BBDz"),
            ("ReturnDescriptorTerminator", "\x00"),
            ("DetailLevel", "\x01\x00"),
            ("RecvBuff", "\xff\xff"),
            ("ServerType", "\x00\x00\x00\x80"),
            ("TargetDomain", "SMB"),
            ("RapTerminator", "\x00"),
            ("TargetName", "ABCD"),
            ("RapTerminator2", "\x00"),
        ]
    )


class SMBTransRAPData(Packet):
    fields = OrderedDict(
        [
            ("Wordcount", "\x0e"),
            ("TotalParamCount", "\x24\x00"),
            ("TotalDataCount", "\x00\x00"),
            ("MaxParamCount", "\x08\x00"),
            ("MaxDataCount", "\xff\xff"),
            ("MaxSetupCount", "\x00"),
            ("Reserved", "\x00\x00"),
            ("Flags", "\x00"),
            ("Timeout", "\x00\x00\x00\x00"),
            ("Reserved1", "\x00\x00"),
            ("ParamCount", "\x24\x00"),
            ("ParamOffset", "\x5a\x00"),
            ("DataCount", "\x00\x00"),
            ("DataOffset", "\x7e\x00"),
            ("SetupCount", "\x00"),
            ("Reserved2", "\x00"),
            ("Bcc", "\x3f\x00"),
            ("Terminator", "\x00"),
            ("PipeName", "\\PIPE\\LANMAN"),
            ("PipeTerminator", "\x00\x00"),
            ("Data", ""),
        ]
    )

    def calculate(self):
        # Padding
        if len(str(self.fields["Data"])) % 2 == 0:
            self.fields["PipeTerminator"] = "\x00\x00\x00\x00"
        else:
            self.fields["PipeTerminator"] = "\x00\x00\x00"
        ##Convert Path to Unicode first before any Len calc.
        self.fields["PipeName"] = (
            self.fields["PipeName"].encode("utf-16le").decode("latin-1")
        )
        ##Data Len
        self.fields["TotalParamCount"] = StructWithLenPython2or3(
            "<i", len(str(self.fields["Data"]))
        )[:2]
        self.fields["ParamCount"] = StructWithLenPython2or3(
            "<i", len(str(self.fields["Data"]))
        )[:2]
        ##Packet len
        FindRAPOffset = (
            str(self.fields["Wordcount"])
            + str(self.fields["TotalParamCount"])
            + str(self.fields["TotalDataCount"])
            + str(self.fields["MaxParamCount"])
            + str(self.fields["MaxDataCount"])
            + str(self.fields["MaxSetupCount"])
            + str(self.fields["Reserved"])
            + str(self.fields["Flags"])
            + str(self.fields["Timeout"])
            + str(self.fields["Reserved1"])
            + str(self.fields["ParamCount"])
            + str(self.fields["ParamOffset"])
            + str(self.fields["DataCount"])
            + str(self.fields["DataOffset"])
            + str(self.fields["SetupCount"])
            + str(self.fields["Reserved2"])
            + str(self.fields["Bcc"])
            + str(self.fields["Terminator"])
            + str(self.fields["PipeName"])
            + str(self.fields["PipeTerminator"])
        )
        self.fields["ParamOffset"] = StructWithLenPython2or3(
            "<i", len(FindRAPOffset) + 32
        )[:2]
        ##Bcc Buff Len
        BccComplete = (
            str(self.fields["Terminator"])
            + str(self.fields["PipeName"])
            + str(self.fields["PipeTerminator"])
            + str(self.fields["Data"])
        )
        self.fields["Bcc"] = StructWithLenPython2or3("<i", len(BccComplete))[:2]


class SMBNegoAnsLM(Packet):
    fields = OrderedDict(
        [
            ("Wordcount", "\x11"),
            ("Dialect", ""),
            ("Securitymode", "\x03"),
            ("MaxMpx", "\x32\x00"),
            ("MaxVc", "\x01\x00"),
            ("Maxbuffsize", "\x04\x41\x00\x00"),
            ("Maxrawbuff", "\x00\x00\x01\x00"),
            ("Sessionkey", "\x00\x00\x00\x00"),
            ("Capabilities", "\xfc\x3e\x01\x00"),
            ("Systemtime", SMBTime()),
            ("Srvtimezone", "\x2c\x01"),
            ("Keylength", "\x08"),
            ("Bcc", "\x10\x00"),
            ("Key", ""),
            ("Domain", settings.Config.Domain),
            ("DomainNull", "\x00\x00"),
            ("Server", settings.Config.MachineName),
            ("ServerNull", "\x00\x00"),
        ]
    )

    def calculate(self):
        self.fields["Domain"] = (
            self.fields["Domain"].encode("utf-16le").decode("latin-1")
        )
        self.fields["Server"] = (
            self.fields["Server"].encode("utf-16le").decode("latin-1")
        )
        CompleteBCCLen = (
            str(self.fields["Key"])
            + str(self.fields["Domain"])
            + str(self.fields["DomainNull"])
            + str(self.fields["Server"])
            + str(self.fields["ServerNull"])
        )
        self.fields["Bcc"] = StructWithLenPython2or3("<h", len(CompleteBCCLen))
        self.fields["Keylength"] = StructWithLenPython2or3(
            "<h", len(self.fields["Key"])
        )[0]


class SMBNegoAns(Packet):
    fields = OrderedDict(
        [
            ("Wordcount", "\x11"),
            ("Dialect", ""),
            ("Securitymode", "\x03"),
            ("MaxMpx", "\x32\x00"),
            ("MaxVc", "\x01\x00"),
            ("MaxBuffSize", "\x04\x41\x00\x00"),
            ("MaxRawBuff", "\x00\x00\x01\x00"),
            ("SessionKey", "\x00\x00\x00\x00"),
            ("Capabilities", "\xfd\xf3\x01\x80"),
            ("SystemTime", SMBTime()),
            ("SrvTimeZone", "\xf0\x00"),
            ("KeyLen", "\x00"),
            ("Bcc", "\x57\x00"),
            ("Guid", urandom(16).decode("latin-1")),
            ("InitContextTokenASNId", "\x60"),
            ("InitContextTokenASNLen", "\x5b"),
            ("ThisMechASNId", "\x06"),
            ("ThisMechASNLen", "\x06"),
            ("ThisMechASNStr", "\x2b\x06\x01\x05\x05\x02"),
            ("SpNegoTokenASNId", "\xa0"),
            ("SpNegoTokenASNLen", "\x51"),
            ("NegTokenASNId", "\x30"),
            ("NegTokenASNLen", "\x4f"),
            ("NegTokenTag0ASNId", "\xa0"),
            ("NegTokenTag0ASNLen", "\x30"),
            ("NegThisMechASNId", "\x30"),
            ("NegThisMechASNLen", "\x2e"),
            ("NegThisMech4ASNId", "\x06"),
            ("NegThisMech4ASNLen", "\x09"),
            ("NegThisMech4ASNStr", "\x2b\x06\x01\x04\x01\x82\x37\x02\x02\x0a"),
            ("NegTokenTag3ASNId", "\xa3"),
            ("NegTokenTag3ASNLen", "\x1b"),
            ("NegHintASNId", "\x30"),
            ("NegHintASNLen", "\x19"),
            ("NegHintTag0ASNId", "\xa0"),
            ("NegHintTag0ASNLen", "\x17"),
            ("NegHintFinalASNId", "\x1b"),
            ("NegHintFinalASNLen", "\x15"),
            ("NegHintFinalASNStr", "not_defined_in_RFC4178@please_ignore"),
        ]
    )

    def calculate(self):
        CompleteBCCLen1 = (
            str(self.fields["Guid"])
            + str(self.fields["InitContextTokenASNId"])
            + str(self.fields["InitContextTokenASNLen"])
            + str(self.fields["ThisMechASNId"])
            + str(self.fields["ThisMechASNLen"])
            + str(self.fields["ThisMechASNStr"])
            + str(self.fields["SpNegoTokenASNId"])
            + str(self.fields["SpNegoTokenASNLen"])
            + str(self.fields["NegTokenASNId"])
            + str(self.fields["NegTokenASNLen"])
            + str(self.fields["NegTokenTag0ASNId"])
            + str(self.fields["NegTokenTag0ASNLen"])
            + str(self.fields["NegThisMechASNId"])
            + str(self.fields["NegThisMechASNLen"])
            + str(self.fields["NegThisMech4ASNId"])
            + str(self.fields["NegThisMech4ASNLen"])
            + str(self.fields["NegThisMech4ASNStr"])
            + str(self.fields["NegTokenTag3ASNId"])
            + str(self.fields["NegTokenTag3ASNLen"])
            + str(self.fields["NegHintASNId"])
            + str(self.fields["NegHintASNLen"])
            + str(self.fields["NegHintTag0ASNId"])
            + str(self.fields["NegHintTag0ASNLen"])
            + str(self.fields["NegHintFinalASNId"])
            + str(self.fields["NegHintFinalASNLen"])
            + str(self.fields["NegHintFinalASNStr"])
        )
        AsnLenStart = (
            str(self.fields["ThisMechASNId"])
            + str(self.fields["ThisMechASNLen"])
            + str(self.fields["ThisMechASNStr"])
            + str(self.fields["SpNegoTokenASNId"])
            + str(self.fields["SpNegoTokenASNLen"])
            + str(self.fields["NegTokenASNId"])
            + str(self.fields["NegTokenASNLen"])
            + str(self.fields["NegTokenTag0ASNId"])
            + str(self.fields["NegTokenTag0ASNLen"])
            + str(self.fields["NegThisMechASNId"])
            + str(self.fields["NegThisMechASNLen"])
            + str(self.fields["NegThisMech4ASNId"])
            + str(self.fields["NegThisMech4ASNLen"])
            + str(self.fields["NegThisMech4ASNStr"])
            + str(self.fields["NegTokenTag3ASNId"])
            + str(self.fields["NegTokenTag3ASNLen"])
            + str(self.fields["NegHintASNId"])
            + str(self.fields["NegHintASNLen"])
            + str(self.fields["NegHintTag0ASNId"])
            + str(self.fields["NegHintTag0ASNLen"])
            + str(self.fields["NegHintFinalASNId"])
            + str(self.fields["NegHintFinalASNLen"])
            + str(self.fields["NegHintFinalASNStr"])
        )
        AsnLen2 = (
            str(self.fields["NegTokenASNId"])
            + str(self.fields["NegTokenASNLen"])
            + str(self.fields["NegTokenTag0ASNId"])
            + str(self.fields["NegTokenTag0ASNLen"])
            + str(self.fields["NegThisMechASNId"])
            + str(self.fields["NegThisMechASNLen"])
            + str(self.fields["NegThisMech4ASNId"])
            + str(self.fields["NegThisMech4ASNLen"])
            + str(self.fields["NegThisMech4ASNStr"])
            + str(self.fields["NegTokenTag3ASNId"])
            + str(self.fields["NegTokenTag3ASNLen"])
            + str(self.fields["NegHintASNId"])
            + str(self.fields["NegHintASNLen"])
            + str(self.fields["NegHintTag0ASNId"])
            + str(self.fields["NegHintTag0ASNLen"])
            + str(self.fields["NegHintFinalASNId"])
            + str(self.fields["NegHintFinalASNLen"])
            + str(self.fields["NegHintFinalASNStr"])
        )
        MechTypeLen = (
            str(self.fields["NegThisMechASNId"])
            + str(self.fields["NegThisMechASNLen"])
            + str(self.fields["NegThisMech4ASNId"])
            + str(self.fields["NegThisMech4ASNLen"])
            + str(self.fields["NegThisMech4ASNStr"])
        )
        Tag3Len = (
            str(self.fields["NegHintASNId"])
            + str(self.fields["NegHintASNLen"])
            + str(self.fields["NegHintTag0ASNId"])
            + str(self.fields["NegHintTag0ASNLen"])
            + str(self.fields["NegHintFinalASNId"])
            + str(self.fields["NegHintFinalASNLen"])
            + str(self.fields["NegHintFinalASNStr"])
        )

        self.fields["Bcc"] = StructWithLenPython2or3("<h", len(CompleteBCCLen1))
        self.fields["InitContextTokenASNLen"] = StructWithLenPython2or3(
            "<B", len(AsnLenStart)
        )
        self.fields["ThisMechASNLen"] = StructWithLenPython2or3(
            "<B", len(str(self.fields["ThisMechASNStr"]))
        )
        self.fields["SpNegoTokenASNLen"] = StructWithLenPython2or3("<B", len(AsnLen2))
        self.fields["NegTokenASNLen"] = StructWithLenPython2or3("<B", len(AsnLen2) - 2)
        self.fields["NegTokenTag0ASNLen"] = StructWithLenPython2or3(
            "<B", len(MechTypeLen)
        )
        self.fields["NegThisMechASNLen"] = StructWithLenPython2or3(
            "<B", len(MechTypeLen) - 2
        )
        self.fields["NegThisMech4ASNLen"] = StructWithLenPython2or3(
            "<B", len(str(self.fields["NegThisMech4ASNStr"]))
        )
        self.fields["NegTokenTag3ASNLen"] = StructWithLenPython2or3("<B", len(Tag3Len))
        self.fields["NegHintASNLen"] = StructWithLenPython2or3("<B", len(Tag3Len) - 2)
        self.fields["NegHintTag0ASNLen"] = StructWithLenPython2or3(
            "<B", len(Tag3Len) - 4
        )
        self.fields["NegHintFinalASNLen"] = StructWithLenPython2or3(
            "<B", len(str(self.fields["NegHintFinalASNStr"]))
        )


class SMBNegoKerbAns(Packet):
    fields = OrderedDict(
        [
            ("Wordcount", "\x11"),
            ("Dialect", ""),
            ("Securitymode", "\x03"),
            ("MaxMpx", "\x32\x00"),
            ("MaxVc", "\x01\x00"),
            ("MaxBuffSize", "\x04\x41\x00\x00"),
            ("MaxRawBuff", "\x00\x00\x01\x00"),
            ("SessionKey", "\x00\x00\x00\x00"),
            ("Capabilities", "\xfd\xf3\x01\x80"),
            ("SystemTime", "\x84\xd6\xfb\xa3\x01\x35\xcd\x01"),
            ("SrvTimeZone", "\xf0\x00"),
            ("KeyLen", "\x00"),
            ("Bcc", "\x57\x00"),
            ("Guid", urandom(16).decode("latin-1")),
            ("InitContextTokenASNId", "\x60"),
            ("InitContextTokenASNLen", "\x5b"),
            ("ThisMechASNId", "\x06"),
            ("ThisMechASNLen", "\x06"),
            ("ThisMechASNStr", "\x2b\x06\x01\x05\x05\x02"),
            ("SpNegoTokenASNId", "\xa0"),
            ("SpNegoTokenASNLen", "\x51"),
            ("NegTokenASNId", "\x30"),
            ("NegTokenASNLen", "\x4f"),
            ("NegTokenTag0ASNId", "\xa0"),
            ("NegTokenTag0ASNLen", "\x30"),
            ("NegThisMechASNId", "\x30"),
            ("NegThisMechASNLen", "\x2e"),
            ("NegThisMech1ASNId", "\x06"),
            ("NegThisMech1ASNLen", "\x09"),
            ("NegThisMech1ASNStr", "\x2a\x86\x48\x82\xf7\x12\x01\x02\x02"),
            ("NegThisMech2ASNId", "\x06"),
            ("NegThisMech2ASNLen", "\x09"),
            ("NegThisMech2ASNStr", "\x2a\x86\x48\x86\xf7\x12\x01\x02\x02"),
            ("NegThisMech3ASNId", "\x06"),
            ("NegThisMech3ASNLen", "\x0a"),
            ("NegThisMech3ASNStr", "\x2a\x86\x48\x86\xf7\x12\x01\x02\x02\x03"),
            ("NegThisMech4ASNId", "\x06"),
            ("NegThisMech4ASNLen", "\x09"),
            ("NegThisMech4ASNStr", "\x2b\x06\x01\x04\x01\x82\x37\x02\x02\x0a"),
            ("NegTokenTag3ASNId", "\xa3"),
            ("NegTokenTag3ASNLen", "\x1b"),
            ("NegHintASNId", "\x30"),
            ("NegHintASNLen", "\x19"),
            ("NegHintTag0ASNId", "\xa0"),
            ("NegHintTag0ASNLen", "\x17"),
            ("NegHintFinalASNId", "\x1b"),
            ("NegHintFinalASNLen", "\x15"),
            ("NegHintFinalASNStr", settings.Config.MachineNego),
        ]
    )

    def calculate(self):
        CompleteBCCLen1 = (
            str(self.fields["Guid"])
            + str(self.fields["InitContextTokenASNId"])
            + str(self.fields["InitContextTokenASNLen"])
            + str(self.fields["ThisMechASNId"])
            + str(self.fields["ThisMechASNLen"])
            + str(self.fields["ThisMechASNStr"])
            + str(self.fields["SpNegoTokenASNId"])
            + str(self.fields["SpNegoTokenASNLen"])
            + str(self.fields["NegTokenASNId"])
            + str(self.fields["NegTokenASNLen"])
            + str(self.fields["NegTokenTag0ASNId"])
            + str(self.fields["NegTokenTag0ASNLen"])
            + str(self.fields["NegThisMechASNId"])
            + str(self.fields["NegThisMechASNLen"])
            + str(self.fields["NegThisMech1ASNId"])
            + str(self.fields["NegThisMech1ASNLen"])
            + str(self.fields["NegThisMech1ASNStr"])
            + str(self.fields["NegThisMech2ASNId"])
            + str(self.fields["NegThisMech2ASNLen"])
            + str(self.fields["NegThisMech2ASNStr"])
            + str(self.fields["NegThisMech3ASNId"])
            + str(self.fields["NegThisMech3ASNLen"])
            + str(self.fields["NegThisMech3ASNStr"])
            + str(self.fields["NegThisMech4ASNId"])
            + str(self.fields["NegThisMech4ASNLen"])
            + str(self.fields["NegThisMech4ASNStr"])
            + str(self.fields["NegTokenTag3ASNId"])
            + str(self.fields["NegTokenTag3ASNLen"])
            + str(self.fields["NegHintASNId"])
            + str(self.fields["NegHintASNLen"])
            + str(self.fields["NegHintTag0ASNId"])
            + str(self.fields["NegHintTag0ASNLen"])
            + str(self.fields["NegHintFinalASNId"])
            + str(self.fields["NegHintFinalASNLen"])
            + str(self.fields["NegHintFinalASNStr"])
        )
        AsnLenStart = (
            str(self.fields["ThisMechASNId"])
            + str(self.fields["ThisMechASNLen"])
            + str(self.fields["ThisMechASNStr"])
            + str(self.fields["SpNegoTokenASNId"])
            + str(self.fields["SpNegoTokenASNLen"])
            + str(self.fields["NegTokenASNId"])
            + str(self.fields["NegTokenASNLen"])
            + str(self.fields["NegTokenTag0ASNId"])
            + str(self.fields["NegTokenTag0ASNLen"])
            + str(self.fields["NegThisMechASNId"])
            + str(self.fields["NegThisMechASNLen"])
            + str(self.fields["NegThisMech1ASNId"])
            + str(self.fields["NegThisMech1ASNLen"])
            + str(self.fields["NegThisMech1ASNStr"])
            + str(self.fields["NegThisMech2ASNId"])
            + str(self.fields["NegThisMech2ASNLen"])
            + str(self.fields["NegThisMech2ASNStr"])
            + str(self.fields["NegThisMech3ASNId"])
            + str(self.fields["NegThisMech3ASNLen"])
            + str(self.fields["NegThisMech3ASNStr"])
            + str(self.fields["NegThisMech4ASNId"])
            + str(self.fields["NegThisMech4ASNLen"])
            + str(self.fields["NegThisMech4ASNStr"])
            + str(self.fields["NegTokenTag3ASNId"])
            + str(self.fields["NegTokenTag3ASNLen"])
            + str(self.fields["NegHintASNId"])
            + str(self.fields["NegHintASNLen"])
            + str(self.fields["NegHintTag0ASNId"])
            + str(self.fields["NegHintTag0ASNLen"])
            + str(self.fields["NegHintFinalASNId"])
            + str(self.fields["NegHintFinalASNLen"])
            + str(self.fields["NegHintFinalASNStr"])
        )
        AsnLen2 = (
            str(self.fields["NegTokenASNId"])
            + str(self.fields["NegTokenASNLen"])
            + str(self.fields["NegTokenTag0ASNId"])
            + str(self.fields["NegTokenTag0ASNLen"])
            + str(self.fields["NegThisMechASNId"])
            + str(self.fields["NegThisMechASNLen"])
            + str(self.fields["NegThisMech1ASNId"])
            + str(self.fields["NegThisMech1ASNLen"])
            + str(self.fields["NegThisMech1ASNStr"])
            + str(self.fields["NegThisMech2ASNId"])
            + str(self.fields["NegThisMech2ASNLen"])
            + str(self.fields["NegThisMech2ASNStr"])
            + str(self.fields["NegThisMech3ASNId"])
            + str(self.fields["NegThisMech3ASNLen"])
            + str(self.fields["NegThisMech3ASNStr"])
            + str(self.fields["NegThisMech4ASNId"])
            + str(self.fields["NegThisMech4ASNLen"])
            + str(self.fields["NegThisMech4ASNStr"])
            + str(self.fields["NegTokenTag3ASNId"])
            + str(self.fields["NegTokenTag3ASNLen"])
            + str(self.fields["NegHintASNId"])
            + str(self.fields["NegHintASNLen"])
            + str(self.fields["NegHintTag0ASNId"])
            + str(self.fields["NegHintTag0ASNLen"])
            + str(self.fields["NegHintFinalASNId"])
            + str(self.fields["NegHintFinalASNLen"])
            + str(self.fields["NegHintFinalASNStr"])
        )
        MechTypeLen = (
            str(self.fields["NegThisMechASNId"])
            + str(self.fields["NegThisMechASNLen"])
            + str(self.fields["NegThisMech1ASNId"])
            + str(self.fields["NegThisMech1ASNLen"])
            + str(self.fields["NegThisMech1ASNStr"])
            + str(self.fields["NegThisMech2ASNId"])
            + str(self.fields["NegThisMech2ASNLen"])
            + str(self.fields["NegThisMech2ASNStr"])
            + str(self.fields["NegThisMech3ASNId"])
            + str(self.fields["NegThisMech3ASNLen"])
            + str(self.fields["NegThisMech3ASNStr"])
            + str(self.fields["NegThisMech4ASNId"])
            + str(self.fields["NegThisMech4ASNLen"])
            + str(self.fields["NegThisMech4ASNStr"])
        )
        Tag3Len = (
            str(self.fields["NegHintASNId"])
            + str(self.fields["NegHintASNLen"])
            + str(self.fields["NegHintTag0ASNId"])
            + str(self.fields["NegHintTag0ASNLen"])
            + str(self.fields["NegHintFinalASNId"])
            + str(self.fields["NegHintFinalASNLen"])
            + str(self.fields["NegHintFinalASNStr"])
        )

        self.fields["Bcc"] = StructWithLenPython2or3("<h", len(CompleteBCCLen1))
        self.fields["InitContextTokenASNLen"] = StructWithLenPython2or3(
            "<B", len(AsnLenStart)
        )
        self.fields["ThisMechASNLen"] = StructWithLenPython2or3(
            "<B", len(str(self.fields["ThisMechASNStr"]))
        )
        self.fields["SpNegoTokenASNLen"] = StructWithLenPython2or3("<B", len(AsnLen2))
        self.fields["NegTokenASNLen"] = StructWithLenPython2or3("<B", len(AsnLen2) - 2)
        self.fields["NegTokenTag0ASNLen"] = StructWithLenPython2or3(
            "<B", len(MechTypeLen)
        )
        self.fields["NegThisMechASNLen"] = StructWithLenPython2or3(
            "<B", len(MechTypeLen) - 2
        )
        self.fields["NegThisMech1ASNLen"] = StructWithLenPython2or3(
            "<B", len(str(self.fields["NegThisMech1ASNStr"]))
        )
        self.fields["NegThisMech2ASNLen"] = StructWithLenPython2or3(
            "<B", len(str(self.fields["NegThisMech2ASNStr"]))
        )
        self.fields["NegThisMech3ASNLen"] = StructWithLenPython2or3(
            "<B", len(str(self.fields["NegThisMech3ASNStr"]))
        )
        self.fields["NegThisMech4ASNLen"] = StructWithLenPython2or3(
            "<B", len(str(self.fields["NegThisMech4ASNStr"]))
        )
        self.fields["NegTokenTag3ASNLen"] = StructWithLenPython2or3("<B", len(Tag3Len))
        self.fields["NegHintASNLen"] = StructWithLenPython2or3("<B", len(Tag3Len) - 2)
        self.fields["NegHintFinalASNLen"] = StructWithLenPython2or3(
            "<B", len(str(self.fields["NegHintFinalASNStr"]))
        )


class SMBSession1Data(Packet):
    fields = OrderedDict(
        [
            ("Wordcount", "\x04"),
            ("AndXCommand", "\xff"),
            ("Reserved", "\x00"),
            ("Andxoffset", "\x5f\x01"),
            ("Action", "\x00\x00"),
            ("SecBlobLen", "\xea\x00"),
            ("Bcc", "\x34\x01"),
            ("ChoiceTagASNId", "\xa1"),
            ("ChoiceTagASNLenOfLen", "\x81"),
            ("ChoiceTagASNIdLen", "\x00"),
            ("NegTokenTagASNId", "\x30"),
            ("NegTokenTagASNLenOfLen", "\x81"),
            ("NegTokenTagASNIdLen", "\x00"),
            ("Tag0ASNId", "\xa0"),
            ("Tag0ASNIdLen", "\x03"),
            ("NegoStateASNId", "\x0a"),
            ("NegoStateASNLen", "\x01"),
            ("NegoStateASNValue", "\x01"),
            ("Tag1ASNId", "\xa1"),
            ("Tag1ASNIdLen", "\x0c"),
            ("Tag1ASNId2", "\x06"),
            ("Tag1ASNId2Len", "\x0a"),
            ("Tag1ASNId2Str", "\x2b\x06\x01\x04\x01\x82\x37\x02\x02\x0a"),
            ("Tag2ASNId", "\xa2"),
            ("Tag2ASNIdLenOfLen", "\x81"),
            ("Tag2ASNIdLen", "\xed"),
            ("Tag3ASNId", "\x04"),
            ("Tag3ASNIdLenOfLen", "\x81"),
            ("Tag3ASNIdLen", "\xea"),
            ("NTLMSSPSignature", "NTLMSSP"),
            ("NTLMSSPSignatureNull", "\x00"),
            ("NTLMSSPMessageType", "\x02\x00\x00\x00"),
            ("NTLMSSPNtWorkstationLen", "\x1e\x00"),
            ("NTLMSSPNtWorkstationMaxLen", "\x1e\x00"),
            ("NTLMSSPNtWorkstationBuffOffset", "\x38\x00\x00\x00"),
            (
                "NTLMSSPNtNegotiateFlags",
                (
                    "\x15\x82\x81\xe2"
                    if settings.Config.NOESS_On_Off
                    else "\x15\x82\x89\xe2"
                ),
            ),
            ("NTLMSSPNtServerChallenge", "\x81\x22\x33\x34\x55\x46\xe7\x88"),
            ("NTLMSSPNtReserved", "\x00\x00\x00\x00\x00\x00\x00\x00"),
            ("NTLMSSPNtTargetInfoLen", "\x94\x00"),
            ("NTLMSSPNtTargetInfoMaxLen", "\x94\x00"),
            ("NTLMSSPNtTargetInfoBuffOffset", "\x56\x00\x00\x00"),
            ("NegTokenInitSeqMechMessageVersionHigh", "\x05"),
            ("NegTokenInitSeqMechMessageVersionLow", "\x02"),
            ("NegTokenInitSeqMechMessageVersionBuilt", "\xce\x0e"),
            ("NegTokenInitSeqMechMessageVersionReserved", "\x00\x00\x00"),
            ("NegTokenInitSeqMechMessageVersionNTLMType", "\x0f"),
            ("NTLMSSPNtWorkstationName", settings.Config.Domain),
            ("NTLMSSPNTLMChallengeAVPairsId", "\x02\x00"),
            ("NTLMSSPNTLMChallengeAVPairsLen", "\x0a\x00"),
            ("NTLMSSPNTLMChallengeAVPairsUnicodeStr", settings.Config.Domain),
            ("NTLMSSPNTLMChallengeAVPairs1Id", "\x01\x00"),
            ("NTLMSSPNTLMChallengeAVPairs1Len", "\x1e\x00"),
            ("NTLMSSPNTLMChallengeAVPairs1UnicodeStr", settings.Config.MachineName),
            ("NTLMSSPNTLMChallengeAVPairs2Id", "\x04\x00"),
            ("NTLMSSPNTLMChallengeAVPairs2Len", "\x1e\x00"),
            (
                "NTLMSSPNTLMChallengeAVPairs2UnicodeStr",
                settings.Config.MachineName + "." + settings.Config.DomainName,
            ),
            ("NTLMSSPNTLMChallengeAVPairs3Id", "\x03\x00"),
            ("NTLMSSPNTLMChallengeAVPairs3Len", "\x1e\x00"),
            ("NTLMSSPNTLMChallengeAVPairs3UnicodeStr", settings.Config.DomainName),
            ("NTLMSSPNTLMChallengeAVPairs5Id", "\x05\x00"),
            ("NTLMSSPNTLMChallengeAVPairs5Len", "\x04\x00"),
            ("NTLMSSPNTLMChallengeAVPairs5UnicodeStr", settings.Config.DomainName),
            ("NTLMSSPNTLMChallengeAVPairs6Id", "\x00\x00"),
            ("NTLMSSPNTLMChallengeAVPairs6Len", "\x00\x00"),
            ("NTLMSSPNTLMPadding", ""),
            ("NativeOs", "Windows Server 2003 3790 Service Pack 2"),
            ("NativeOsTerminator", "\x00\x00"),
            ("NativeLAN", "Windows Server 2003 5.2"),
            ("NativeLANTerminator", "\x00\x00"),
        ]
    )

    def calculate(self):
        ###### Convert strings to Unicode
        self.fields["NTLMSSPNtWorkstationName"] = (
            self.fields["NTLMSSPNtWorkstationName"].encode("utf-16le").decode("latin-1")
        )
        self.fields["NTLMSSPNTLMChallengeAVPairsUnicodeStr"] = (
            self.fields["NTLMSSPNTLMChallengeAVPairsUnicodeStr"]
            .encode("utf-16le")
            .decode("latin-1")
        )
        self.fields["NTLMSSPNTLMChallengeAVPairs1UnicodeStr"] = (
            self.fields["NTLMSSPNTLMChallengeAVPairs1UnicodeStr"]
            .encode("utf-16le")
            .decode("latin-1")
        )
        self.fields["NTLMSSPNTLMChallengeAVPairs2UnicodeStr"] = (
            self.fields["NTLMSSPNTLMChallengeAVPairs2UnicodeStr"]
            .encode("utf-16le")
            .decode("latin-1")
        )
        self.fields["NTLMSSPNTLMChallengeAVPairs3UnicodeStr"] = (
            self.fields["NTLMSSPNTLMChallengeAVPairs3UnicodeStr"]
            .encode("utf-16le")
            .decode("latin-1")
        )
        self.fields["NTLMSSPNTLMChallengeAVPairs5UnicodeStr"] = (
            self.fields["NTLMSSPNTLMChallengeAVPairs5UnicodeStr"]
            .encode("utf-16le")
            .decode("latin-1")
        )
        self.fields["NativeOs"] = (
            self.fields["NativeOs"].encode("utf-16le").decode("latin-1")
        )
        self.fields["NativeLAN"] = (
            self.fields["NativeLAN"].encode("utf-16le").decode("latin-1")
        )

        ###### SecBlobLen Calc:
        AsnLen = (
            str(self.fields["ChoiceTagASNId"])
            + str(self.fields["ChoiceTagASNLenOfLen"])
            + str(self.fields["ChoiceTagASNIdLen"])
            + str(self.fields["NegTokenTagASNId"])
            + str(self.fields["NegTokenTagASNLenOfLen"])
            + str(self.fields["NegTokenTagASNIdLen"])
            + str(self.fields["Tag0ASNId"])
            + str(self.fields["Tag0ASNIdLen"])
            + str(self.fields["NegoStateASNId"])
            + str(self.fields["NegoStateASNLen"])
            + str(self.fields["NegoStateASNValue"])
            + str(self.fields["Tag1ASNId"])
            + str(self.fields["Tag1ASNIdLen"])
            + str(self.fields["Tag1ASNId2"])
            + str(self.fields["Tag1ASNId2Len"])
            + str(self.fields["Tag1ASNId2Str"])
            + str(self.fields["Tag2ASNId"])
            + str(self.fields["Tag2ASNIdLenOfLen"])
            + str(self.fields["Tag2ASNIdLen"])
            + str(self.fields["Tag3ASNId"])
            + str(self.fields["Tag3ASNIdLenOfLen"])
            + str(self.fields["Tag3ASNIdLen"])
        )
        CalculateSecBlob = (
            str(self.fields["NTLMSSPSignature"])
            + str(self.fields["NTLMSSPSignatureNull"])
            + str(self.fields["NTLMSSPMessageType"])
            + str(self.fields["NTLMSSPNtWorkstationLen"])
            + str(self.fields["NTLMSSPNtWorkstationMaxLen"])
            + str(self.fields["NTLMSSPNtWorkstationBuffOffset"])
            + str(self.fields["NTLMSSPNtNegotiateFlags"])
            + str(self.fields["NTLMSSPNtServerChallenge"])
            + str(self.fields["NTLMSSPNtReserved"])
            + str(self.fields["NTLMSSPNtTargetInfoLen"])
            + str(self.fields["NTLMSSPNtTargetInfoMaxLen"])
            + str(self.fields["NTLMSSPNtTargetInfoBuffOffset"])
            + str(self.fields["NegTokenInitSeqMechMessageVersionHigh"])
            + str(self.fields["NegTokenInitSeqMechMessageVersionLow"])
            + str(self.fields["NegTokenInitSeqMechMessageVersionBuilt"])
            + str(self.fields["NegTokenInitSeqMechMessageVersionReserved"])
            + str(self.fields["NegTokenInitSeqMechMessageVersionNTLMType"])
            + str(self.fields["NTLMSSPNtWorkstationName"])
            + str(self.fields["NTLMSSPNTLMChallengeAVPairsId"])
            + str(self.fields["NTLMSSPNTLMChallengeAVPairsLen"])
            + str(self.fields["NTLMSSPNTLMChallengeAVPairsUnicodeStr"])
            + str(self.fields["NTLMSSPNTLMChallengeAVPairs1Id"])
            + str(self.fields["NTLMSSPNTLMChallengeAVPairs1Len"])
            + str(self.fields["NTLMSSPNTLMChallengeAVPairs1UnicodeStr"])
            + (self.fields["NTLMSSPNTLMChallengeAVPairs2Id"])
            + str(self.fields["NTLMSSPNTLMChallengeAVPairs2Len"])
            + str(self.fields["NTLMSSPNTLMChallengeAVPairs2UnicodeStr"])
            + (self.fields["NTLMSSPNTLMChallengeAVPairs3Id"])
            + str(self.fields["NTLMSSPNTLMChallengeAVPairs3Len"])
            + str(self.fields["NTLMSSPNTLMChallengeAVPairs3UnicodeStr"])
            + (self.fields["NTLMSSPNTLMChallengeAVPairs5Id"])
            + str(self.fields["NTLMSSPNTLMChallengeAVPairs5Len"])
            + str(self.fields["NTLMSSPNTLMChallengeAVPairs5UnicodeStr"])
            + (self.fields["NTLMSSPNTLMChallengeAVPairs6Id"])
            + str(self.fields["NTLMSSPNTLMChallengeAVPairs6Len"])
        )

        ###### Bcc len
        BccLen = (
            AsnLen
            + CalculateSecBlob
            + str(self.fields["NTLMSSPNTLMPadding"])
            + str(self.fields["NativeOs"])
            + str(self.fields["NativeOsTerminator"])
            + str(self.fields["NativeLAN"])
            + str(self.fields["NativeLANTerminator"])
        )

        ###### SecBlobLen
        self.fields["SecBlobLen"] = StructWithLenPython2or3(
            "<h", len(AsnLen + CalculateSecBlob)
        )
        self.fields["Bcc"] = StructWithLenPython2or3("<h", len(BccLen))
        self.fields["ChoiceTagASNIdLen"] = StructWithLenPython2or3(
            ">B", len(AsnLen + CalculateSecBlob) - 3
        )
        self.fields["NegTokenTagASNIdLen"] = StructWithLenPython2or3(
            ">B", len(AsnLen + CalculateSecBlob) - 6
        )
        self.fields["Tag1ASNIdLen"] = StructWithLenPython2or3(
            ">B",
            len(
                str(self.fields["Tag1ASNId2"])
                + str(self.fields["Tag1ASNId2Len"])
                + str(self.fields["Tag1ASNId2Str"])
            ),
        )
        self.fields["Tag1ASNId2Len"] = StructWithLenPython2or3(
            ">B", len(str(self.fields["Tag1ASNId2Str"]))
        )
        self.fields["Tag2ASNIdLen"] = StructWithLenPython2or3(
            ">B",
            len(
                CalculateSecBlob
                + str(self.fields["Tag3ASNId"])
                + str(self.fields["Tag3ASNIdLenOfLen"])
                + str(self.fields["Tag3ASNIdLen"])
            ),
        )
        self.fields["Tag3ASNIdLen"] = StructWithLenPython2or3(
            ">B", len(CalculateSecBlob)
        )

        ###### Andxoffset calculation.
        CalculateCompletePacket = (
            str(self.fields["Wordcount"])
            + str(self.fields["AndXCommand"])
            + str(self.fields["Reserved"])
            + str(self.fields["Andxoffset"])
            + str(self.fields["Action"])
            + str(self.fields["SecBlobLen"])
            + str(self.fields["Bcc"])
            + BccLen
        )
        self.fields["Andxoffset"] = StructWithLenPython2or3(
            "<h", len(CalculateCompletePacket) + 32
        )

        ###### Workstation Offset
        CalculateOffsetWorkstation = (
            str(self.fields["NTLMSSPSignature"])
            + str(self.fields["NTLMSSPSignatureNull"])
            + str(self.fields["NTLMSSPMessageType"])
            + str(self.fields["NTLMSSPNtWorkstationLen"])
            + str(self.fields["NTLMSSPNtWorkstationMaxLen"])
            + str(self.fields["NTLMSSPNtWorkstationBuffOffset"])
            + str(self.fields["NTLMSSPNtNegotiateFlags"])
            + str(self.fields["NTLMSSPNtServerChallenge"])
            + str(self.fields["NTLMSSPNtReserved"])
            + str(self.fields["NTLMSSPNtTargetInfoLen"])
            + str(self.fields["NTLMSSPNtTargetInfoMaxLen"])
            + str(self.fields["NTLMSSPNtTargetInfoBuffOffset"])
            + str(self.fields["NegTokenInitSeqMechMessageVersionHigh"])
            + str(self.fields["NegTokenInitSeqMechMessageVersionLow"])
            + str(self.fields["NegTokenInitSeqMechMessageVersionBuilt"])
            + str(self.fields["NegTokenInitSeqMechMessageVersionReserved"])
            + str(self.fields["NegTokenInitSeqMechMessageVersionNTLMType"])
        )

        ###### AvPairs Offset
        CalculateLenAvpairs = (
            str(self.fields["NTLMSSPNTLMChallengeAVPairsId"])
            + str(self.fields["NTLMSSPNTLMChallengeAVPairsLen"])
            + str(self.fields["NTLMSSPNTLMChallengeAVPairsUnicodeStr"])
            + str(self.fields["NTLMSSPNTLMChallengeAVPairs1Id"])
            + str(self.fields["NTLMSSPNTLMChallengeAVPairs1Len"])
            + str(self.fields["NTLMSSPNTLMChallengeAVPairs1UnicodeStr"])
            + (self.fields["NTLMSSPNTLMChallengeAVPairs2Id"])
            + str(self.fields["NTLMSSPNTLMChallengeAVPairs2Len"])
            + str(self.fields["NTLMSSPNTLMChallengeAVPairs2UnicodeStr"])
            + (self.fields["NTLMSSPNTLMChallengeAVPairs3Id"])
            + str(self.fields["NTLMSSPNTLMChallengeAVPairs3Len"])
            + str(self.fields["NTLMSSPNTLMChallengeAVPairs3UnicodeStr"])
            + (self.fields["NTLMSSPNTLMChallengeAVPairs5Id"])
            + str(self.fields["NTLMSSPNTLMChallengeAVPairs5Len"])
            + str(self.fields["NTLMSSPNTLMChallengeAVPairs5UnicodeStr"])
            + (self.fields["NTLMSSPNTLMChallengeAVPairs6Id"])
            + str(self.fields["NTLMSSPNTLMChallengeAVPairs6Len"])
        )

        ##### Workstation Offset Calculation:
        self.fields["NTLMSSPNtWorkstationBuffOffset"] = StructWithLenPython2or3(
            "<i", len(CalculateOffsetWorkstation)
        )
        self.fields["NTLMSSPNtWorkstationLen"] = StructWithLenPython2or3(
            "<h", len(str(self.fields["NTLMSSPNtWorkstationName"]))
        )
        self.fields["NTLMSSPNtWorkstationMaxLen"] = StructWithLenPython2or3(
            "<h", len(str(self.fields["NTLMSSPNtWorkstationName"]))
        )

        ##### IvPairs Offset Calculation:
        self.fields["NTLMSSPNtTargetInfoBuffOffset"] = StructWithLenPython2or3(
            "<i",
            len(
                CalculateOffsetWorkstation
                + str(self.fields["NTLMSSPNtWorkstationName"])
            ),
        )
        self.fields["NTLMSSPNtTargetInfoLen"] = StructWithLenPython2or3(
            "<h", len(CalculateLenAvpairs)
        )
        self.fields["NTLMSSPNtTargetInfoMaxLen"] = StructWithLenPython2or3(
            "<h", len(CalculateLenAvpairs)
        )

        ##### IvPair Calculation:
        self.fields["NTLMSSPNTLMChallengeAVPairs5Len"] = StructWithLenPython2or3(
            "<h", len(str(self.fields["NTLMSSPNTLMChallengeAVPairs5UnicodeStr"]))
        )
        self.fields["NTLMSSPNTLMChallengeAVPairs3Len"] = StructWithLenPython2or3(
            "<h", len(str(self.fields["NTLMSSPNTLMChallengeAVPairs3UnicodeStr"]))
        )
        self.fields["NTLMSSPNTLMChallengeAVPairs2Len"] = StructWithLenPython2or3(
            "<h", len(str(self.fields["NTLMSSPNTLMChallengeAVPairs2UnicodeStr"]))
        )
        self.fields["NTLMSSPNTLMChallengeAVPairs1Len"] = StructWithLenPython2or3(
            "<h", len(str(self.fields["NTLMSSPNTLMChallengeAVPairs1UnicodeStr"]))
        )
        self.fields["NTLMSSPNTLMChallengeAVPairsLen"] = StructWithLenPython2or3(
            "<h", len(str(self.fields["NTLMSSPNTLMChallengeAVPairsUnicodeStr"]))
        )


class SMBSession2Accept(Packet):
    fields = OrderedDict(
        [
            ("Wordcount", "\x04"),
            ("AndXCommand", "\xff"),
            ("Reserved", "\x00"),
            ("Andxoffset", "\xb4\x00"),
            ("Action", "\x00\x00"),
            ("SecBlobLen", "\x09\x00"),
            ("Bcc", "\x89\x01"),
            ("SSPIAccept", "\xa1\x07\x30\x05\xa0\x03\x0a\x01\x00"),
            ("NativeOs", "Windows Server 2003 3790 Service Pack 2"),
            ("NativeOsTerminator", "\x00\x00"),
            ("NativeLAN", "Windows Server 2003 5.2"),
            ("NativeLANTerminator", "\x00\x00"),
        ]
    )

    def calculate(self):
        self.fields["NativeOs"] = self.fields["NativeOs"].encode("utf-16le")
        self.fields["NativeLAN"] = self.fields["NativeLAN"].encode("utf-16le")
        BccLen = (
            str(self.fields["SSPIAccept"])
            + str(self.fields["NativeOs"])
            + str(self.fields["NativeOsTerminator"])
            + str(self.fields["NativeLAN"])
            + str(self.fields["NativeLANTerminator"])
        )
        self.fields["Bcc"] = StructWithLenPython2or3("<h", len(BccLen))


class SMBSessEmpty(Packet):
    fields = OrderedDict(
        [
            ("Empty", "\x00\x00\x00"),
        ]
    )


class SMBTreeData(Packet):
    fields = OrderedDict(
        [
            ("Wordcount", "\x07"),
            ("AndXCommand", "\xff"),
            ("Reserved", "\x00"),
            ("Andxoffset", "\xbd\x00"),
            ("OptionalSupport", "\x00\x00"),
            ("MaxShareAccessRight", "\x00\x00\x00\x00"),
            ("GuestShareAccessRight", "\x00\x00\x00\x00"),
            ("Bcc", "\x94\x00"),
            ("Service", "IPC"),
            ("ServiceTerminator", "\x00\x00\x00\x00"),
        ]
    )

    def calculate(self):
        ## Complete Packet Len
        CompletePacket = (
            str(self.fields["Wordcount"])
            + str(self.fields["AndXCommand"])
            + str(self.fields["Reserved"])
            + str(self.fields["Andxoffset"])
            + str(self.fields["OptionalSupport"])
            + str(self.fields["MaxShareAccessRight"])
            + str(self.fields["GuestShareAccessRight"])
            + str(self.fields["Bcc"])
            + str(self.fields["Service"])
            + str(self.fields["ServiceTerminator"])
        )
        ## AndXOffset
        self.fields["Andxoffset"] = StructWithLenPython2or3(
            "<H", len(CompletePacket) + 32
        )
        ## BCC Len Calc
        BccLen = str(self.fields["Service"]) + str(self.fields["ServiceTerminator"])
        self.fields["Bcc"] = StructWithLenPython2or3("<H", len(BccLen))


class SMBSessTreeAns(Packet):
    fields = OrderedDict(
        [
            ("Wordcount", "\x03"),
            ("Command", "\x75"),
            ("Reserved", "\x00"),
            ("AndXoffset", "\x4e\x00"),
            ("Action", "\x01\x00"),
            ("Bcc", "\x25\x00"),
            ("NativeOs", "Windows 5.1"),
            ("NativeOsNull", "\x00"),
            ("NativeLan", "Windows 2000 LAN Manager"),
            ("NativeLanNull", "\x00"),
            ("WordcountTree", "\x03"),
            ("AndXCommand", "\xff"),
            ("Reserved1", "\x00"),
            ("AndxOffset", "\x00\x00"),
            ("OptionalSupport", "\x01\x00"),
            ("Bcc2", "\x08\x00"),
            ("Service", "A:"),
            ("ServiceNull", "\x00"),
            ("FileSystem", "NTFS"),
            ("FileSystemNull", "\x00"),
        ]
    )

    def calculate(self):
        ## AndxOffset
        CalculateCompletePacket = (
            str(self.fields["Wordcount"])
            + str(self.fields["Command"])
            + str(self.fields["Reserved"])
            + str(self.fields["AndXoffset"])
            + str(self.fields["Action"])
            + str(self.fields["Bcc"])
            + str(self.fields["NativeOs"])
            + str(self.fields["NativeOsNull"])
            + str(self.fields["NativeLan"])
            + str(self.fields["NativeLanNull"])
        )
        self.fields["AndXoffset"] = StructWithLenPython2or3(
            "<i", len(CalculateCompletePacket) + 32
        )[:2]
        ## BCC 1 and 2
        CompleteBCCLen = (
            str(self.fields["NativeOs"])
            + str(self.fields["NativeOsNull"])
            + str(self.fields["NativeLan"])
            + str(self.fields["NativeLanNull"])
        )
        self.fields["Bcc"] = StructWithLenPython2or3("<h", len(CompleteBCCLen))
        CompleteBCC2Len = (
            str(self.fields["Service"])
            + str(self.fields["ServiceNull"])
            + str(self.fields["FileSystem"])
            + str(self.fields["FileSystemNull"])
        )
        self.fields["Bcc2"] = StructWithLenPython2or3("<h", len(CompleteBCC2Len))


### SMB2 Packets


class SMB2Header(Packet):
    fields = OrderedDict(
        [
            ("Proto", "\xfe\x53\x4d\x42"),
            ("Len", "\x40\x00"),  # Always 64.
            ("CreditCharge", "\x00\x00"),
            ("NTStatus", "\x00\x00\x00\x00"),
            ("Cmd", "\x00\x00"),
            ("Credits", "\x01\x00"),
            ("Flags", "\x01\x00\x00\x00"),
            ("NextCmd", "\x00\x00\x00\x00"),
            ("MessageId", "\x00\x00\x00\x00\x00\x00\x00\x00"),
            ("PID", "\x00\x00\x00\x00"),
            ("TID", "\x00\x00\x00\x00"),
            ("SessionID", "\x00\x00\x00\x00\x00\x00\x00\x00"),
            (
                "Signature",
                "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
            ),
        ]
    )


class SMB2NegoAns(Packet):
    fields = OrderedDict(
        [
            ("Len", "\x41\x00"),
            ("Signing", "\x01\x00"),
            ("Dialect", "\xff\x02"),
            ("Reserved", "\x00\x00"),
            ("Guid", urandom(16).decode("latin-1")),
            ("Capabilities", "\x07\x00\x00\x00"),
            ("MaxTransSize", "\x00\x00\x10\x00"),
            ("MaxReadSize", "\x00\x00\x10\x00"),
            ("MaxWriteSize", "\x00\x00\x10\x00"),
            ("SystemTime", SMBTime()),
            ("BootTime", SMBTime()),
            ("SecBlobOffSet", "\x80\x00"),
            ("SecBlobLen", "\x78\x00"),
            ("Reserved2", "\x00\x00\x00\x00"),
            ("InitContextTokenASNId", "\x60"),
            ("InitContextTokenASNLen", "\x76"),
            ("ThisMechASNId", "\x06"),
            ("ThisMechASNLen", "\x06"),
            ("ThisMechASNStr", "\x2b\x06\x01\x05\x05\x02"),
            ("SpNegoTokenASNId", "\xa0"),
            ("SpNegoTokenASNLen", "\x6c"),
            ("NegTokenASNId", "\x30"),
            ("NegTokenASNLen", "\x6a"),
            ("NegTokenTag0ASNId", "\xa0"),
            ("NegTokenTag0ASNLen", "\x3c"),
            ("NegThisMechASNId", "\x30"),
            ("NegThisMechASNLen", "\x3a"),
            # ("NegThisMech1ASNId",         "\x06"),
            # ("NegThisMech1ASNLen",        "\x0a"),
            # ("NegThisMech1ASNStr",        "\x2b\x06\x01\x04\x01\x82\x37\x02\x02\x1e"),
            ("NegThisMech2ASNId", "\x06"),
            ("NegThisMech2ASNLen", "\x09"),
            ("NegThisMech2ASNStr", "\x2a\x86\x48\x82\xf7\x12\x01\x02\x02"),
            ("NegThisMech3ASNId", "\x06"),
            ("NegThisMech3ASNLen", "\x09"),
            ("NegThisMech3ASNStr", "\x2a\x86\x48\x86\xf7\x12\x01\x02\x02"),
            ("NegThisMech4ASNId", "\x06"),
            ("NegThisMech4ASNLen", "\x0a"),
            ("NegThisMech4ASNStr", "\x2a\x86\x48\x86\xf7\x12\x01\x02\x02\x03"),
            ("NegThisMech5ASNId", "\x06"),
            ("NegThisMech5ASNLen", "\x0a"),
            ("NegThisMech5ASNStr", "\x2b\x06\x01\x04\x01\x82\x37\x02\x02\x0a"),
            ("NegTokenTag3ASNId", "\xa3"),
            ("NegTokenTag3ASNLen", "\x2a"),
            ("NegHintASNId", "\x30"),
            ("NegHintASNLen", "\x28"),
            ("NegHintTag0ASNId", "\xa0"),
            ("NegHintTag0ASNLen", "\x26"),
            ("NegHintFinalASNId", "\x1b"),
            ("NegHintFinalASNLen", "\x24"),
            ("NegHintFinalASNStr", "not_defined_in_RFC4178@please_ignore"),
        ]
    )

    def calculate(self):

        StructLen = (
            str(self.fields["Len"])
            + str(self.fields["Signing"])
            + str(self.fields["Dialect"])
            + str(self.fields["Reserved"])
            + str(self.fields["Guid"])
            + str(self.fields["Capabilities"])
            + str(self.fields["MaxTransSize"])
            + str(self.fields["MaxReadSize"])
            + str(self.fields["MaxWriteSize"])
            + str(self.fields["SystemTime"])
            + str(self.fields["BootTime"])
            + str(self.fields["SecBlobOffSet"])
            + str(self.fields["SecBlobLen"])
            + str(self.fields["Reserved2"])
        )

        SecBlobLen = (
            str(self.fields["InitContextTokenASNId"])
            + str(self.fields["InitContextTokenASNLen"])
            + str(self.fields["ThisMechASNId"])
            + str(self.fields["ThisMechASNLen"])
            + str(self.fields["ThisMechASNStr"])
            + str(self.fields["SpNegoTokenASNId"])
            + str(self.fields["SpNegoTokenASNLen"])
            + str(self.fields["NegTokenASNId"])
            + str(self.fields["NegTokenASNLen"])
            + str(self.fields["NegTokenTag0ASNId"])
            + str(self.fields["NegTokenTag0ASNLen"])
            + str(self.fields["NegThisMechASNId"])
            + str(self.fields["NegThisMechASNLen"])
            + str(self.fields["NegThisMech2ASNId"])
            + str(self.fields["NegThisMech2ASNLen"])
            + str(self.fields["NegThisMech2ASNStr"])
            + str(self.fields["NegThisMech3ASNId"])
            + str(self.fields["NegThisMech3ASNLen"])
            + str(self.fields["NegThisMech3ASNStr"])
            + str(self.fields["NegThisMech4ASNId"])
            + str(self.fields["NegThisMech4ASNLen"])
            + str(self.fields["NegThisMech4ASNStr"])
            + str(self.fields["NegThisMech5ASNId"])
            + str(self.fields["NegThisMech5ASNLen"])
            + str(self.fields["NegThisMech5ASNStr"])
            + str(self.fields["NegTokenTag3ASNId"])
            + str(self.fields["NegTokenTag3ASNLen"])
            + str(self.fields["NegHintASNId"])
            + str(self.fields["NegHintASNLen"])
            + str(self.fields["NegHintTag0ASNId"])
            + str(self.fields["NegHintTag0ASNLen"])
            + str(self.fields["NegHintFinalASNId"])
            + str(self.fields["NegHintFinalASNLen"])
            + str(self.fields["NegHintFinalASNStr"])
        )

        AsnLenStart = (
            str(self.fields["ThisMechASNId"])
            + str(self.fields["ThisMechASNLen"])
            + str(self.fields["ThisMechASNStr"])
            + str(self.fields["SpNegoTokenASNId"])
            + str(self.fields["SpNegoTokenASNLen"])
            + str(self.fields["NegTokenASNId"])
            + str(self.fields["NegTokenASNLen"])
            + str(self.fields["NegTokenTag0ASNId"])
            + str(self.fields["NegTokenTag0ASNLen"])
            + str(self.fields["NegThisMechASNId"])
            + str(self.fields["NegThisMechASNLen"])
            + str(self.fields["NegThisMech2ASNId"])
            + str(self.fields["NegThisMech2ASNLen"])
            + str(self.fields["NegThisMech2ASNStr"])
            + str(self.fields["NegThisMech3ASNId"])
            + str(self.fields["NegThisMech3ASNLen"])
            + str(self.fields["NegThisMech3ASNStr"])
            + str(self.fields["NegThisMech4ASNId"])
            + str(self.fields["NegThisMech4ASNLen"])
            + str(self.fields["NegThisMech4ASNStr"])
            + str(self.fields["NegThisMech5ASNId"])
            + str(self.fields["NegThisMech5ASNLen"])
            + str(self.fields["NegThisMech5ASNStr"])
            + str(self.fields["NegTokenTag3ASNId"])
            + str(self.fields["NegTokenTag3ASNLen"])
            + str(self.fields["NegHintASNId"])
            + str(self.fields["NegHintASNLen"])
            + str(self.fields["NegHintTag0ASNId"])
            + str(self.fields["NegHintTag0ASNLen"])
            + str(self.fields["NegHintFinalASNId"])
            + str(self.fields["NegHintFinalASNLen"])
            + str(self.fields["NegHintFinalASNStr"])
        )

        AsnLen2 = (
            str(self.fields["NegTokenASNId"])
            + str(self.fields["NegTokenASNLen"])
            + str(self.fields["NegTokenTag0ASNId"])
            + str(self.fields["NegTokenTag0ASNLen"])
            + str(self.fields["NegThisMechASNId"])
            + str(self.fields["NegThisMechASNLen"])
            + str(self.fields["NegThisMech2ASNId"])
            + str(self.fields["NegThisMech2ASNLen"])
            + str(self.fields["NegThisMech2ASNStr"])
            + str(self.fields["NegThisMech3ASNId"])
            + str(self.fields["NegThisMech3ASNLen"])
            + str(self.fields["NegThisMech3ASNStr"])
            + str(self.fields["NegThisMech4ASNId"])
            + str(self.fields["NegThisMech4ASNLen"])
            + str(self.fields["NegThisMech4ASNStr"])
            + str(self.fields["NegThisMech5ASNId"])
            + str(self.fields["NegThisMech5ASNLen"])
            + str(self.fields["NegThisMech5ASNStr"])
            + str(self.fields["NegTokenTag3ASNId"])
            + str(self.fields["NegTokenTag3ASNLen"])
            + str(self.fields["NegHintASNId"])
            + str(self.fields["NegHintASNLen"])
            + str(self.fields["NegHintTag0ASNId"])
            + str(self.fields["NegHintTag0ASNLen"])
            + str(self.fields["NegHintFinalASNId"])
            + str(self.fields["NegHintFinalASNLen"])
            + str(self.fields["NegHintFinalASNStr"])
        )

        MechTypeLen = (
            str(self.fields["NegThisMechASNId"])
            + str(self.fields["NegThisMechASNLen"])
            + str(self.fields["NegThisMech2ASNId"])
            + str(self.fields["NegThisMech2ASNLen"])
            + str(self.fields["NegThisMech2ASNStr"])
            + str(self.fields["NegThisMech3ASNId"])
            + str(self.fields["NegThisMech3ASNLen"])
            + str(self.fields["NegThisMech3ASNStr"])
            + str(self.fields["NegThisMech4ASNId"])
            + str(self.fields["NegThisMech4ASNLen"])
            + str(self.fields["NegThisMech4ASNStr"])
            + str(self.fields["NegThisMech5ASNId"])
            + str(self.fields["NegThisMech5ASNLen"])
            + str(self.fields["NegThisMech5ASNStr"])
        )

        Tag3Len = (
            str(self.fields["NegHintASNId"])
            + str(self.fields["NegHintASNLen"])
            + str(self.fields["NegHintTag0ASNId"])
            + str(self.fields["NegHintTag0ASNLen"])
            + str(self.fields["NegHintFinalASNId"])
            + str(self.fields["NegHintFinalASNLen"])
            + str(self.fields["NegHintFinalASNStr"])
        )

        # Packet Struct len
        self.fields["Len"] = StructWithLenPython2or3("<h", len(StructLen) + 1)
        # Sec Blob lens
        self.fields["SecBlobOffSet"] = StructWithLenPython2or3(
            "<h", len(StructLen) + 64
        )
        self.fields["SecBlobLen"] = StructWithLenPython2or3("<h", len(SecBlobLen))
        # ASN Stuff
        self.fields["InitContextTokenASNLen"] = StructWithLenPython2or3(
            "<B", len(SecBlobLen) - 2
        )
        self.fields["ThisMechASNLen"] = StructWithLenPython2or3(
            "<B", len(str(self.fields["ThisMechASNStr"]))
        )
        self.fields["SpNegoTokenASNLen"] = StructWithLenPython2or3("<B", len(AsnLen2))
        self.fields["NegTokenASNLen"] = StructWithLenPython2or3("<B", len(AsnLen2) - 2)
        self.fields["NegTokenTag0ASNLen"] = StructWithLenPython2or3(
            "<B", len(MechTypeLen)
        )
        self.fields["NegThisMechASNLen"] = StructWithLenPython2or3(
            "<B", len(MechTypeLen) - 2
        )
        # self.fields["NegThisMech1ASNLen"] = StructWithLenPython2or3("<B", len(str(self.fields["NegThisMech1ASNStr"])))
        self.fields["NegThisMech2ASNLen"] = StructWithLenPython2or3(
            "<B", len(str(self.fields["NegThisMech2ASNStr"]))
        )
        self.fields["NegThisMech3ASNLen"] = StructWithLenPython2or3(
            "<B", len(str(self.fields["NegThisMech3ASNStr"]))
        )
        self.fields["NegThisMech4ASNLen"] = StructWithLenPython2or3(
            "<B", len(str(self.fields["NegThisMech4ASNStr"]))
        )
        self.fields["NegThisMech5ASNLen"] = StructWithLenPython2or3(
            "<B", len(str(self.fields["NegThisMech5ASNStr"]))
        )
        self.fields["NegTokenTag3ASNLen"] = StructWithLenPython2or3("<B", len(Tag3Len))
        self.fields["NegHintASNLen"] = StructWithLenPython2or3("<B", len(Tag3Len) - 2)
        self.fields["NegHintTag0ASNLen"] = StructWithLenPython2or3(
            "<B", len(Tag3Len) - 4
        )
        self.fields["NegHintFinalASNLen"] = StructWithLenPython2or3(
            "<B", len(str(self.fields["NegHintFinalASNStr"]))
        )


class SMB2Session1Data(Packet):
    fields = OrderedDict(
        [
            ("Len", "\x09\x00"),
            ("SessionFlag", "\x00\x00"),
            ("SecBlobOffSet", "\x48\x00"),
            ("SecBlobLen", "\x06\x01"),
            ("ChoiceTagASNId", "\xa1"),
            ("ChoiceTagASNLenOfLen", "\x82"),
            ("ChoiceTagASNIdLen", "\x01\x02"),
            ("NegTokenTagASNId", "\x30"),
            ("NegTokenTagASNLenOfLen", "\x81"),
            ("NegTokenTagASNIdLen", "\xff"),
            ("Tag0ASNId", "\xa0"),
            ("Tag0ASNIdLen", "\x03"),
            ("NegoStateASNId", "\x0a"),
            ("NegoStateASNLen", "\x01"),
            ("NegoStateASNValue", "\x01"),
            ("Tag1ASNId", "\xa1"),
            ("Tag1ASNIdLen", "\x0c"),
            ("Tag1ASNId2", "\x06"),
            ("Tag1ASNId2Len", "\x0a"),
            ("Tag1ASNId2Str", "\x2b\x06\x01\x04\x01\x82\x37\x02\x02\x0a"),
            ("Tag2ASNId", "\xa2"),
            ("Tag2ASNIdLenOfLen", "\x81"),
            ("Tag2ASNIdLen", "\xe9"),
            ("Tag3ASNId", "\x04"),
            ("Tag3ASNIdLenOfLen", "\x81"),
            ("Tag3ASNIdLen", "\xe6"),
            ("NTLMSSPSignature", "NTLMSSP"),
            ("NTLMSSPSignatureNull", "\x00"),
            ("NTLMSSPMessageType", "\x02\x00\x00\x00"),
            ("NTLMSSPNtWorkstationLen", "\x1e\x00"),
            ("NTLMSSPNtWorkstationMaxLen", "\x1e\x00"),
            ("NTLMSSPNtWorkstationBuffOffset", "\x38\x00\x00\x00"),
            (
                "NTLMSSPNtNegotiateFlags",
                (
                    "\x15\x82\x81\xe2"
                    if settings.Config.NOESS_On_Off
                    else "\x15\x82\x89\xe2"
                ),
            ),
            ("NTLMSSPNtServerChallenge", "\x81\x22\x33\x34\x55\x46\xe7\x88"),
            ("NTLMSSPNtReserved", "\x00\x00\x00\x00\x00\x00\x00\x00"),
            ("NTLMSSPNtTargetInfoLen", "\x94\x00"),
            ("NTLMSSPNtTargetInfoMaxLen", "\x94\x00"),
            ("NTLMSSPNtTargetInfoBuffOffset", "\x56\x00\x00\x00"),
            ("NegTokenInitSeqMechMessageVersionHigh", "\x06"),
            ("NegTokenInitSeqMechMessageVersionLow", "\x03"),
            ("NegTokenInitSeqMechMessageVersionBuilt", "\x80\x25"),
            ("NegTokenInitSeqMechMessageVersionReserved", "\x00\x00\x00"),
            ("NegTokenInitSeqMechMessageVersionNTLMType", "\x0f"),
            ("NTLMSSPNtWorkstationName", settings.Config.Domain),
            ("NTLMSSPNTLMChallengeAVPairsId", "\x02\x00"),
            ("NTLMSSPNTLMChallengeAVPairsLen", "\x0a\x00"),
            ("NTLMSSPNTLMChallengeAVPairsUnicodeStr", settings.Config.Domain),
            ("NTLMSSPNTLMChallengeAVPairs1Id", "\x01\x00"),
            ("NTLMSSPNTLMChallengeAVPairs1Len", "\x1e\x00"),
            ("NTLMSSPNTLMChallengeAVPairs1UnicodeStr", settings.Config.MachineName),
            ("NTLMSSPNTLMChallengeAVPairs2Id", "\x04\x00"),
            ("NTLMSSPNTLMChallengeAVPairs2Len", "\x1e\x00"),
            (
                "NTLMSSPNTLMChallengeAVPairs2UnicodeStr",
                settings.Config.MachineName + "." + settings.Config.DomainName,
            ),
            ("NTLMSSPNTLMChallengeAVPairs3Id", "\x03\x00"),
            ("NTLMSSPNTLMChallengeAVPairs3Len", "\x1e\x00"),
            ("NTLMSSPNTLMChallengeAVPairs3UnicodeStr", settings.Config.DomainName),
            ("NTLMSSPNTLMChallengeAVPairs5Id", "\x05\x00"),
            ("NTLMSSPNTLMChallengeAVPairs5Len", "\x04\x00"),
            ("NTLMSSPNTLMChallengeAVPairs5UnicodeStr", settings.Config.DomainName),
            ("NTLMSSPNTLMChallengeAVPairs7Id", "\x07\x00"),
            ("NTLMSSPNTLMChallengeAVPairs7Len", "\x08\x00"),
            ("NTLMSSPNTLMChallengeAVPairs7UnicodeStr", SMBTime()),
            ("NTLMSSPNTLMChallengeAVPairs6Id", "\x00\x00"),
            ("NTLMSSPNTLMChallengeAVPairs6Len", "\x00\x00"),
        ]
    )

    def calculate(self):
        ###### Convert strings to Unicode
        self.fields["NTLMSSPNtWorkstationName"] = (
            self.fields["NTLMSSPNtWorkstationName"].encode("utf-16le").decode("latin-1")
        )
        self.fields["NTLMSSPNTLMChallengeAVPairsUnicodeStr"] = (
            self.fields["NTLMSSPNTLMChallengeAVPairsUnicodeStr"]
            .encode("utf-16le")
            .decode("latin-1")
        )
        self.fields["NTLMSSPNTLMChallengeAVPairs1UnicodeStr"] = (
            self.fields["NTLMSSPNTLMChallengeAVPairs1UnicodeStr"]
            .encode("utf-16le")
            .decode("latin-1")
        )
        self.fields["NTLMSSPNTLMChallengeAVPairs2UnicodeStr"] = (
            self.fields["NTLMSSPNTLMChallengeAVPairs2UnicodeStr"]
            .encode("utf-16le")
            .decode("latin-1")
        )
        self.fields["NTLMSSPNTLMChallengeAVPairs3UnicodeStr"] = (
            self.fields["NTLMSSPNTLMChallengeAVPairs3UnicodeStr"]
            .encode("utf-16le")
            .decode("latin-1")
        )
        self.fields["NTLMSSPNTLMChallengeAVPairs5UnicodeStr"] = (
            self.fields["NTLMSSPNTLMChallengeAVPairs5UnicodeStr"]
            .encode("utf-16le")
            .decode("latin-1")
        )

        # Packet struct calc:
        StructLen = (
            str(self.fields["Len"])
            + str(self.fields["SessionFlag"])
            + str(self.fields["SecBlobOffSet"])
            + str(self.fields["SecBlobLen"])
        )
        ###### SecBlobLen Calc:
        CalculateSecBlob = (
            str(self.fields["NTLMSSPSignature"])
            + str(self.fields["NTLMSSPSignatureNull"])
            + str(self.fields["NTLMSSPMessageType"])
            + str(self.fields["NTLMSSPNtWorkstationLen"])
            + str(self.fields["NTLMSSPNtWorkstationMaxLen"])
            + str(self.fields["NTLMSSPNtWorkstationBuffOffset"])
            + str(self.fields["NTLMSSPNtNegotiateFlags"])
            + str(self.fields["NTLMSSPNtServerChallenge"])
            + str(self.fields["NTLMSSPNtReserved"])
            + str(self.fields["NTLMSSPNtTargetInfoLen"])
            + str(self.fields["NTLMSSPNtTargetInfoMaxLen"])
            + str(self.fields["NTLMSSPNtTargetInfoBuffOffset"])
            + str(self.fields["NegTokenInitSeqMechMessageVersionHigh"])
            + str(self.fields["NegTokenInitSeqMechMessageVersionLow"])
            + str(self.fields["NegTokenInitSeqMechMessageVersionBuilt"])
            + str(self.fields["NegTokenInitSeqMechMessageVersionReserved"])
            + str(self.fields["NegTokenInitSeqMechMessageVersionNTLMType"])
            + str(self.fields["NTLMSSPNtWorkstationName"])
            + str(self.fields["NTLMSSPNTLMChallengeAVPairsId"])
            + str(self.fields["NTLMSSPNTLMChallengeAVPairsLen"])
            + str(self.fields["NTLMSSPNTLMChallengeAVPairsUnicodeStr"])
            + str(self.fields["NTLMSSPNTLMChallengeAVPairs1Id"])
            + str(self.fields["NTLMSSPNTLMChallengeAVPairs1Len"])
            + str(self.fields["NTLMSSPNTLMChallengeAVPairs1UnicodeStr"])
            + (self.fields["NTLMSSPNTLMChallengeAVPairs2Id"])
            + str(self.fields["NTLMSSPNTLMChallengeAVPairs2Len"])
            + str(self.fields["NTLMSSPNTLMChallengeAVPairs2UnicodeStr"])
            + (self.fields["NTLMSSPNTLMChallengeAVPairs3Id"])
            + str(self.fields["NTLMSSPNTLMChallengeAVPairs3Len"])
            + str(self.fields["NTLMSSPNTLMChallengeAVPairs3UnicodeStr"])
            + (self.fields["NTLMSSPNTLMChallengeAVPairs5Id"])
            + str(self.fields["NTLMSSPNTLMChallengeAVPairs5Len"])
            + str(self.fields["NTLMSSPNTLMChallengeAVPairs5UnicodeStr"])
            + (self.fields["NTLMSSPNTLMChallengeAVPairs7Id"])
            + str(self.fields["NTLMSSPNTLMChallengeAVPairs7Len"])
            + str(self.fields["NTLMSSPNTLMChallengeAVPairs7UnicodeStr"])
            + (self.fields["NTLMSSPNTLMChallengeAVPairs6Id"])
            + str(self.fields["NTLMSSPNTLMChallengeAVPairs6Len"])
        )

        AsnLen = (
            str(self.fields["ChoiceTagASNId"])
            + str(self.fields["ChoiceTagASNLenOfLen"])
            + str(self.fields["ChoiceTagASNIdLen"])
            + str(self.fields["NegTokenTagASNId"])
            + str(self.fields["NegTokenTagASNLenOfLen"])
            + str(self.fields["NegTokenTagASNIdLen"])
            + str(self.fields["Tag0ASNId"])
            + str(self.fields["Tag0ASNIdLen"])
            + str(self.fields["NegoStateASNId"])
            + str(self.fields["NegoStateASNLen"])
            + str(self.fields["NegoStateASNValue"])
            + str(self.fields["Tag1ASNId"])
            + str(self.fields["Tag1ASNIdLen"])
            + str(self.fields["Tag1ASNId2"])
            + str(self.fields["Tag1ASNId2Len"])
            + str(self.fields["Tag1ASNId2Str"])
            + str(self.fields["Tag2ASNId"])
            + str(self.fields["Tag2ASNIdLenOfLen"])
            + str(self.fields["Tag2ASNIdLen"])
            + str(self.fields["Tag3ASNId"])
            + str(self.fields["Tag3ASNIdLenOfLen"])
            + str(self.fields["Tag3ASNIdLen"])
        )

        # Packet Struct len
        self.fields["Len"] = StructWithLenPython2or3("<h", len(StructLen) + 1)
        self.fields["SecBlobLen"] = StructWithLenPython2or3(
            "<H", len(AsnLen + CalculateSecBlob)
        )
        self.fields["SecBlobOffSet"] = StructWithLenPython2or3(
            "<h", len(StructLen) + 64
        )

        ###### ASN Stuff
        if len(CalculateSecBlob) > 255:
            self.fields["Tag3ASNIdLen"] = StructWithLenPython2or3(
                ">H", len(CalculateSecBlob)
            )
        else:
            self.fields["Tag3ASNIdLenOfLen"] = "\x81"
            self.fields["Tag3ASNIdLen"] = StructWithLenPython2or3(
                ">B", len(CalculateSecBlob)
            )

        if len(AsnLen + CalculateSecBlob) - 3 > 255:
            self.fields["ChoiceTagASNIdLen"] = StructWithLenPython2or3(
                ">H", len(AsnLen + CalculateSecBlob) - 4
            )
        else:
            self.fields["ChoiceTagASNLenOfLen"] = "\x81"
            self.fields["ChoiceTagASNIdLen"] = StructWithLenPython2or3(
                ">B", len(AsnLen + CalculateSecBlob) - 3
            )

        if len(AsnLen + CalculateSecBlob) - 7 > 255:
            self.fields["NegTokenTagASNIdLen"] = StructWithLenPython2or3(
                ">H", len(AsnLen + CalculateSecBlob) - 8
            )
        else:
            self.fields["NegTokenTagASNLenOfLen"] = "\x81"
            self.fields["NegTokenTagASNIdLen"] = StructWithLenPython2or3(
                ">B", len(AsnLen + CalculateSecBlob) - 7
            )

        tag2length = (
            CalculateSecBlob
            + str(self.fields["Tag3ASNId"])
            + str(self.fields["Tag3ASNIdLenOfLen"])
            + str(self.fields["Tag3ASNIdLen"])
        )

        if len(tag2length) > 255:
            self.fields["Tag2ASNIdLen"] = StructWithLenPython2or3(">H", len(tag2length))
        else:
            self.fields["Tag2ASNIdLenOfLen"] = "\x81"
            self.fields["Tag2ASNIdLen"] = StructWithLenPython2or3(">B", len(tag2length))

        self.fields["Tag1ASNIdLen"] = StructWithLenPython2or3(
            ">B",
            len(
                str(self.fields["Tag1ASNId2"])
                + str(self.fields["Tag1ASNId2Len"])
                + str(self.fields["Tag1ASNId2Str"])
            ),
        )
        self.fields["Tag1ASNId2Len"] = StructWithLenPython2or3(
            ">B", len(str(self.fields["Tag1ASNId2Str"]))
        )

        ###### Workstation Offset
        CalculateOffsetWorkstation = (
            str(self.fields["NTLMSSPSignature"])
            + str(self.fields["NTLMSSPSignatureNull"])
            + str(self.fields["NTLMSSPMessageType"])
            + str(self.fields["NTLMSSPNtWorkstationLen"])
            + str(self.fields["NTLMSSPNtWorkstationMaxLen"])
            + str(self.fields["NTLMSSPNtWorkstationBuffOffset"])
            + str(self.fields["NTLMSSPNtNegotiateFlags"])
            + str(self.fields["NTLMSSPNtServerChallenge"])
            + str(self.fields["NTLMSSPNtReserved"])
            + str(self.fields["NTLMSSPNtTargetInfoLen"])
            + str(self.fields["NTLMSSPNtTargetInfoMaxLen"])
            + str(self.fields["NTLMSSPNtTargetInfoBuffOffset"])
            + str(self.fields["NegTokenInitSeqMechMessageVersionHigh"])
            + str(self.fields["NegTokenInitSeqMechMessageVersionLow"])
            + str(self.fields["NegTokenInitSeqMechMessageVersionBuilt"])
            + str(self.fields["NegTokenInitSeqMechMessageVersionReserved"])
            + str(self.fields["NegTokenInitSeqMechMessageVersionNTLMType"])
        )

        ###### AvPairs Offset
        CalculateLenAvpairs = (
            str(self.fields["NTLMSSPNTLMChallengeAVPairsId"])
            + str(self.fields["NTLMSSPNTLMChallengeAVPairsLen"])
            + str(self.fields["NTLMSSPNTLMChallengeAVPairsUnicodeStr"])
            + str(self.fields["NTLMSSPNTLMChallengeAVPairs1Id"])
            + str(self.fields["NTLMSSPNTLMChallengeAVPairs1Len"])
            + str(self.fields["NTLMSSPNTLMChallengeAVPairs1UnicodeStr"])
            + (self.fields["NTLMSSPNTLMChallengeAVPairs2Id"])
            + str(self.fields["NTLMSSPNTLMChallengeAVPairs2Len"])
            + str(self.fields["NTLMSSPNTLMChallengeAVPairs2UnicodeStr"])
            + (self.fields["NTLMSSPNTLMChallengeAVPairs3Id"])
            + str(self.fields["NTLMSSPNTLMChallengeAVPairs3Len"])
            + str(self.fields["NTLMSSPNTLMChallengeAVPairs3UnicodeStr"])
            + (self.fields["NTLMSSPNTLMChallengeAVPairs5Id"])
            + str(self.fields["NTLMSSPNTLMChallengeAVPairs5Len"])
            + str(self.fields["NTLMSSPNTLMChallengeAVPairs5UnicodeStr"])
            + (self.fields["NTLMSSPNTLMChallengeAVPairs7Id"])
            + str(self.fields["NTLMSSPNTLMChallengeAVPairs7Len"])
            + str(self.fields["NTLMSSPNTLMChallengeAVPairs7UnicodeStr"])
            + (self.fields["NTLMSSPNTLMChallengeAVPairs6Id"])
            + str(self.fields["NTLMSSPNTLMChallengeAVPairs6Len"])
        )

        ##### Workstation Offset Calculation:
        self.fields["NTLMSSPNtWorkstationBuffOffset"] = StructWithLenPython2or3(
            "<i", len(CalculateOffsetWorkstation)
        )
        self.fields["NTLMSSPNtWorkstationLen"] = StructWithLenPython2or3(
            "<h", len(str(self.fields["NTLMSSPNtWorkstationName"]))
        )
        self.fields["NTLMSSPNtWorkstationMaxLen"] = StructWithLenPython2or3(
            "<h", len(str(self.fields["NTLMSSPNtWorkstationName"]))
        )

        ##### Target Offset Calculation:
        self.fields["NTLMSSPNtTargetInfoBuffOffset"] = StructWithLenPython2or3(
            "<i",
            len(
                CalculateOffsetWorkstation
                + str(self.fields["NTLMSSPNtWorkstationName"])
            ),
        )
        self.fields["NTLMSSPNtTargetInfoLen"] = StructWithLenPython2or3(
            "<h", len(CalculateLenAvpairs)
        )
        self.fields["NTLMSSPNtTargetInfoMaxLen"] = StructWithLenPython2or3(
            "<h", len(CalculateLenAvpairs)
        )

        ##### IvPair Calculation:
        self.fields["NTLMSSPNTLMChallengeAVPairs7Len"] = StructWithLenPython2or3(
            "<h", len(str(self.fields["NTLMSSPNTLMChallengeAVPairs7UnicodeStr"]))
        )
        self.fields["NTLMSSPNTLMChallengeAVPairs5Len"] = StructWithLenPython2or3(
            "<h", len(str(self.fields["NTLMSSPNTLMChallengeAVPairs5UnicodeStr"]))
        )
        self.fields["NTLMSSPNTLMChallengeAVPairs3Len"] = StructWithLenPython2or3(
            "<h", len(str(self.fields["NTLMSSPNTLMChallengeAVPairs3UnicodeStr"]))
        )
        self.fields["NTLMSSPNTLMChallengeAVPairs2Len"] = StructWithLenPython2or3(
            "<h", len(str(self.fields["NTLMSSPNTLMChallengeAVPairs2UnicodeStr"]))
        )
        self.fields["NTLMSSPNTLMChallengeAVPairs1Len"] = StructWithLenPython2or3(
            "<h", len(str(self.fields["NTLMSSPNTLMChallengeAVPairs1UnicodeStr"]))
        )
        self.fields["NTLMSSPNTLMChallengeAVPairsLen"] = StructWithLenPython2or3(
            "<h", len(str(self.fields["NTLMSSPNTLMChallengeAVPairsUnicodeStr"]))
        )


class SMB2Session2Data(Packet):
    fields = OrderedDict(
        [
            ("Len", "\x09\x00"),
            ("SessionFlag", "\x00\x00"),
            ("SecBlobOffSet", "\x00\x00\x00\x00"),
        ]
    )


###################RDP Packets################################
class TPKT(Packet):
    fields = OrderedDict(
        [
            ("Version", "\x03"),
            ("Reserved", "\x00"),
            ("Length", "\x00\x24"),
            ("Data", ""),
        ]
    )

    def calculate(self):
        self.fields["Length"] = StructWithLenPython2or3(
            ">h", len(str(self.fields["Data"])) + 4
        )  # Data+own header.


class X224(Packet):
    fields = OrderedDict(
        [
            ("Length", "\x0e"),
            ("Cmd", "\xd0"),
            ("Dstref", "\x00\x00"),
            ("Srcref", "\x12\x34"),
            ("Class", "\x00"),
            ("Data", ""),
        ]
    )

    def calculate(self):
        self.fields["Length"] = StructWithLenPython2or3(
            ">B", len(str(self.fields["Data"])) + 6
        )


class RDPNEGOAnswer(Packet):
    fields = OrderedDict(
        [
            ("Cmd", "\x02"),
            ("Flags", "\x00"),
            ("Length", "\x08\x00"),
            ("SelectedProto", "\x02\x00\x00\x00"),  # CredSSP
        ]
    )

    def calculate(self):
        self.fields["Length"] = StructWithLenPython2or3("<h", 8)


class RDPNTLMChallengeAnswer(Packet):
    fields = OrderedDict(
        [
            ("PacketStartASN", "\x30"),
            ("PacketStartASNLenOfLen", "\x81"),
            (
                "PacketStartASNStr",
                "\x01",
            ),  # Len of what follows... in this case, +20 since it's x81 lengths are >B
            ("PacketStartASNTag0", "\xa0"),
            ("PacketStartASNTag0Len", "\x03"),  # Static for TSVersion
            ("PacketStartASNTag0Len2", "\x02"),
            ("PacketStartASNTag0Len3", "\x01"),
            (
                "PacketStartASNTag0CredSSPVersion",
                "\x05",
            ),  ##TSVersion: Since padding oracle, v2,v3,v4 are rejected by win7..
            ("ParserHeadASNID1", "\xa1"),
            ("ParserHeadASNLenOfLen1", "\x81"),
            ("ParserHeadASNLen1", "\xfa"),
            ("MessageIDASNID", "\x30"),
            ("MessageIDASNLen", "\x81"),
            ("MessageIDASNLen2", "\xf7"),
            ("OpHeadASNID", "\x30"),
            ("OpHeadASNIDLenOfLen", "\x81"),
            ("OpHeadASNIDLen", "\xf4"),
            ("StatusASNID", "\xa0"),
            ("MatchedDN", "\x81"),
            ("ASNLen01", "\xf1"),
            ("SequenceHeader", "\x04"),
            ("SequenceHeaderLenOfLen", "\x81"),
            ("SequenceHeaderLen", "\xee"),
            #######
            ("NTLMSSPSignature", "NTLMSSP"),
            ("NTLMSSPSignatureNull", "\x00"),
            ("NTLMSSPMessageType", "\x02\x00\x00\x00"),
            ("NTLMSSPNtWorkstationLen", "\x1e\x00"),
            ("NTLMSSPNtWorkstationMaxLen", "\x1e\x00"),
            ("NTLMSSPNtWorkstationBuffOffset", "\x38\x00\x00\x00"),
            ("NTLMSSPNtNegotiateFlags", "\x15\x82\x8a\xe2"),
            ("NTLMSSPNtServerChallenge", "\x81\x22\x33\x34\x55\x46\xe7\x88"),
            ("NTLMSSPNtReserved", "\x00\x00\x00\x00\x00\x00\x00\x00"),
            ("NTLMSSPNtTargetInfoLen", "\x94\x00"),
            ("NTLMSSPNtTargetInfoMaxLen", "\x94\x00"),
            ("NTLMSSPNtTargetInfoBuffOffset", "\x56\x00\x00\x00"),
            ("NegTokenInitSeqMechMessageVersionHigh", "\x05"),
            ("NegTokenInitSeqMechMessageVersionLow", "\x02"),
            ("NegTokenInitSeqMechMessageVersionBuilt", "\xce\x0e"),
            ("NegTokenInitSeqMechMessageVersionReserved", "\x00\x00\x00"),
            ("NegTokenInitSeqMechMessageVersionNTLMType", "\x0f"),
            ("NTLMSSPNtWorkstationName", settings.Config.Domain),
            ("NTLMSSPNTLMChallengeAVPairsId", "\x02\x00"),
            ("NTLMSSPNTLMChallengeAVPairsLen", "\x0a\x00"),
            ("NTLMSSPNTLMChallengeAVPairsUnicodeStr", settings.Config.Domain),
            ("NTLMSSPNTLMChallengeAVPairs1Id", "\x01\x00"),
            ("NTLMSSPNTLMChallengeAVPairs1Len", "\x1e\x00"),
            ("NTLMSSPNTLMChallengeAVPairs1UnicodeStr", settings.Config.MachineName),
            ("NTLMSSPNTLMChallengeAVPairs2Id", "\x04\x00"),
            ("NTLMSSPNTLMChallengeAVPairs2Len", "\x1e\x00"),
            (
                "NTLMSSPNTLMChallengeAVPairs2UnicodeStr",
                settings.Config.MachineName + "." + settings.Config.DomainName,
            ),
            ("NTLMSSPNTLMChallengeAVPairs3Id", "\x03\x00"),
            ("NTLMSSPNTLMChallengeAVPairs3Len", "\x1e\x00"),
            ("NTLMSSPNTLMChallengeAVPairs3UnicodeStr", settings.Config.DomainName),
            ("NTLMSSPNTLMChallengeAVPairs5Id", "\x05\x00"),
            ("NTLMSSPNTLMChallengeAVPairs5Len", "\x04\x00"),
            ("NTLMSSPNTLMChallengeAVPairs5UnicodeStr", settings.Config.DomainName),
            ("NTLMSSPNTLMChallengeAVPairs6Id", "\x00\x00"),
            ("NTLMSSPNTLMChallengeAVPairs6Len", "\x00\x00"),
        ]
    )

    def calculate(self):

        ###### Convert strings to Unicode first
        self.fields["NTLMSSPNtWorkstationName"] = (
            self.fields["NTLMSSPNtWorkstationName"].encode("utf-16le").decode("latin-1")
        )
        self.fields["NTLMSSPNTLMChallengeAVPairsUnicodeStr"] = (
            self.fields["NTLMSSPNTLMChallengeAVPairsUnicodeStr"]
            .encode("utf-16le")
            .decode("latin-1")
        )
        self.fields["NTLMSSPNTLMChallengeAVPairs1UnicodeStr"] = (
            self.fields["NTLMSSPNTLMChallengeAVPairs1UnicodeStr"]
            .encode("utf-16le")
            .decode("latin-1")
        )
        self.fields["NTLMSSPNTLMChallengeAVPairs2UnicodeStr"] = (
            self.fields["NTLMSSPNTLMChallengeAVPairs2UnicodeStr"]
            .encode("utf-16le")
            .decode("latin-1")
        )
        self.fields["NTLMSSPNTLMChallengeAVPairs3UnicodeStr"] = (
            self.fields["NTLMSSPNTLMChallengeAVPairs3UnicodeStr"]
            .encode("utf-16le")
            .decode("latin-1")
        )
        self.fields["NTLMSSPNTLMChallengeAVPairs5UnicodeStr"] = (
            self.fields["NTLMSSPNTLMChallengeAVPairs5UnicodeStr"]
            .encode("utf-16le")
            .decode("latin-1")
        )

        ###### Workstation Offset
        CalculateOffsetWorkstation = (
            str(self.fields["NTLMSSPSignature"])
            + str(self.fields["NTLMSSPSignatureNull"])
            + str(self.fields["NTLMSSPMessageType"])
            + str(self.fields["NTLMSSPNtWorkstationLen"])
            + str(self.fields["NTLMSSPNtWorkstationMaxLen"])
            + str(self.fields["NTLMSSPNtWorkstationBuffOffset"])
            + str(self.fields["NTLMSSPNtNegotiateFlags"])
            + str(self.fields["NTLMSSPNtServerChallenge"])
            + str(self.fields["NTLMSSPNtReserved"])
            + str(self.fields["NTLMSSPNtTargetInfoLen"])
            + str(self.fields["NTLMSSPNtTargetInfoMaxLen"])
            + str(self.fields["NTLMSSPNtTargetInfoBuffOffset"])
            + str(self.fields["NegTokenInitSeqMechMessageVersionHigh"])
            + str(self.fields["NegTokenInitSeqMechMessageVersionLow"])
            + str(self.fields["NegTokenInitSeqMechMessageVersionBuilt"])
            + str(self.fields["NegTokenInitSeqMechMessageVersionReserved"])
            + str(self.fields["NegTokenInitSeqMechMessageVersionNTLMType"])
        )
        ###### AvPairs Offset
        CalculateLenAvpairs = (
            str(self.fields["NTLMSSPNTLMChallengeAVPairsId"])
            + str(self.fields["NTLMSSPNTLMChallengeAVPairsLen"])
            + str(self.fields["NTLMSSPNTLMChallengeAVPairsUnicodeStr"])
            + str(self.fields["NTLMSSPNTLMChallengeAVPairs1Id"])
            + str(self.fields["NTLMSSPNTLMChallengeAVPairs1Len"])
            + str(self.fields["NTLMSSPNTLMChallengeAVPairs1UnicodeStr"])
            + (self.fields["NTLMSSPNTLMChallengeAVPairs2Id"])
            + str(self.fields["NTLMSSPNTLMChallengeAVPairs2Len"])
            + str(self.fields["NTLMSSPNTLMChallengeAVPairs2UnicodeStr"])
            + (self.fields["NTLMSSPNTLMChallengeAVPairs3Id"])
            + str(self.fields["NTLMSSPNTLMChallengeAVPairs3Len"])
            + str(self.fields["NTLMSSPNTLMChallengeAVPairs3UnicodeStr"])
            + (self.fields["NTLMSSPNTLMChallengeAVPairs5Id"])
            + str(self.fields["NTLMSSPNTLMChallengeAVPairs5Len"])
            + str(self.fields["NTLMSSPNTLMChallengeAVPairs5UnicodeStr"])
            + (self.fields["NTLMSSPNTLMChallengeAVPairs6Id"])
            + str(self.fields["NTLMSSPNTLMChallengeAVPairs6Len"])
        )

        ###### RDP Packet Len
        NTLMMessageLen = (
            CalculateOffsetWorkstation
            + str(self.fields["NTLMSSPNtWorkstationName"])
            + CalculateLenAvpairs
        )

        ##### RDP Len Calculation:

        self.fields["SequenceHeaderLen"] = StructWithLenPython2or3(
            ">B", len(NTLMMessageLen)
        )
        self.fields["ASNLen01"] = StructWithLenPython2or3(">B", len(NTLMMessageLen) + 3)
        self.fields["OpHeadASNIDLen"] = StructWithLenPython2or3(
            ">B", len(NTLMMessageLen) + 6
        )
        self.fields["MessageIDASNLen2"] = StructWithLenPython2or3(
            ">B", len(NTLMMessageLen) + 9
        )
        self.fields["ParserHeadASNLen1"] = StructWithLenPython2or3(
            ">B", len(NTLMMessageLen) + 12
        )
        self.fields["PacketStartASNStr"] = StructWithLenPython2or3(
            ">B", len(NTLMMessageLen) + 20
        )

        ##### Workstation Offset Calculation:
        self.fields["NTLMSSPNtWorkstationBuffOffset"] = StructWithLenPython2or3(
            "<i", len(CalculateOffsetWorkstation)
        )
        self.fields["NTLMSSPNtWorkstationLen"] = StructWithLenPython2or3(
            "<h", len(str(self.fields["NTLMSSPNtWorkstationName"]))
        )
        self.fields["NTLMSSPNtWorkstationMaxLen"] = StructWithLenPython2or3(
            "<h", len(str(self.fields["NTLMSSPNtWorkstationName"]))
        )
        ##### IvPairs Offset Calculation:
        self.fields["NTLMSSPNtTargetInfoBuffOffset"] = StructWithLenPython2or3(
            "<i",
            len(
                CalculateOffsetWorkstation
                + str(self.fields["NTLMSSPNtWorkstationName"])
            ),
        )
        self.fields["NTLMSSPNtTargetInfoLen"] = StructWithLenPython2or3(
            "<h", len(CalculateLenAvpairs)
        )
        self.fields["NTLMSSPNtTargetInfoMaxLen"] = StructWithLenPython2or3(
            "<h", len(CalculateLenAvpairs)
        )
        ##### IvPair Calculation:
        self.fields["NTLMSSPNTLMChallengeAVPairs5Len"] = StructWithLenPython2or3(
            "<h", len(str(self.fields["NTLMSSPNTLMChallengeAVPairs5UnicodeStr"]))
        )
        self.fields["NTLMSSPNTLMChallengeAVPairs3Len"] = StructWithLenPython2or3(
            "<h", len(str(self.fields["NTLMSSPNTLMChallengeAVPairs3UnicodeStr"]))
        )
        self.fields["NTLMSSPNTLMChallengeAVPairs2Len"] = StructWithLenPython2or3(
            "<h", len(str(self.fields["NTLMSSPNTLMChallengeAVPairs2UnicodeStr"]))
        )
        self.fields["NTLMSSPNTLMChallengeAVPairs1Len"] = StructWithLenPython2or3(
            "<h", len(str(self.fields["NTLMSSPNTLMChallengeAVPairs1UnicodeStr"]))
        )
        self.fields["NTLMSSPNTLMChallengeAVPairsLen"] = StructWithLenPython2or3(
            "<h", len(str(self.fields["NTLMSSPNTLMChallengeAVPairsUnicodeStr"]))
        )


#######################################RPC#################################################
class RPCMapBindAckAcceptedAns(Packet):
    fields = OrderedDict(
        [
            ("Version", "\x05"),
            ("VersionLow", "\x00"),
            ("PacketType", "\x0c"),  # Bind ack.
            ("PacketFlag", "\x03"),
            ("DataRepresent", "\x10\x00\x00\x00"),
            ("FragLen", "\x2c\x02"),
            ("AuthLen", "\x00\x00"),
            ("CallID", "\x02\x00\x00\x00"),
            ("MaxTransFrag", "\xd0\x16"),
            ("MaxRecvFrag", "\xd0\x16"),
            ("GroupAssoc", "\x26\x2a\x00\x00"),
            ("SecondaryAddrLen", "\x04\x00"),
            ("SecondaryAddrstr", "\x31\x33\x35\x00"),
            ("Padding", "\x00\x00"),
            ("CTXNumber", "\x03"),
            ("CTXPadding", "\x00\x00\x00"),
            ("CTX0ContextID", "\x02\x00"),
            ("CTX0ItemNumber", "\x02\x00"),
            (
                "CTX0UID",
                "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
            ),
            ("CTX0UIDVersion", "\x00\x00\x00\x00"),
            ("CTX1ContextID", "\x00\x00"),
            ("CTX1ItemNumber", "\x00\x00"),
            (
                "CTX1UID",
                "\x33\x05\x71\x71\xba\xbe\x37\x49\x83\x19\xb5\xdb\xef\x9c\xcc\x36",
            ),
            ("CTX1UIDVersion", "\x00\x00\x00\x00"),
            ("CTX2ContextID", "\x03\x00"),
            ("CTX2ItemNumber", "\x03\x00"),
            (
                "CTX2UID",
                "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
            ),
            ("CTX2UIDVersion", "\x00\x00\x00\x00"),
        ]
    )

    def calculate(self):

        Data = (
            str(self.fields["Version"])
            + str(self.fields["VersionLow"])
            + str(self.fields["PacketType"])
            + str(self.fields["PacketFlag"])
            + str(self.fields["DataRepresent"])
            + str(self.fields["FragLen"])
            + str(self.fields["AuthLen"])
            + str(self.fields["CallID"])
            + str(self.fields["MaxTransFrag"])
            + str(self.fields["MaxRecvFrag"])
            + str(self.fields["GroupAssoc"])
            + str(self.fields["SecondaryAddrLen"])
            + str(self.fields["SecondaryAddrstr"])
            + str(self.fields["Padding"])
            + str(self.fields["CTXNumber"])
            + str(self.fields["CTXPadding"])
            + str(self.fields["CTX0ContextID"])
            + str(self.fields["CTX0ItemNumber"])
            + str(self.fields["CTX0UID"])
            + str(self.fields["CTX0UIDVersion"])
            + str(self.fields["CTX1ContextID"])
            + str(self.fields["CTX1ItemNumber"])
            + str(self.fields["CTX1UID"])
            + str(self.fields["CTX1UIDVersion"])
            + str(self.fields["CTX2ContextID"])
            + str(self.fields["CTX2ItemNumber"])
            + str(self.fields["CTX2UID"])
            + str(self.fields["CTX2UIDVersion"])
        )

        self.fields["FragLen"] = StructWithLenPython2or3("<h", len(Data))


class RPCHeader(Packet):
    fields = OrderedDict(
        [
            ("Version", "\x05"),
            ("VersionLow", "\x00"),
            ("PacketType", "\x02"),  # Bind ack.
            ("PacketFlag", "\x03"),
            ("DataRepresent", "\x10\x00\x00\x00"),
            ("FragLen", "\x0c\x01"),
            ("AuthLen", "\x00\x00"),
            ("CallID", "\x02\x00\x00\x00"),
            ("AllocHint", "\xf4\x00\x00\x00"),
            ("ContextID", "\x01\x00"),
            ("CancelCount", "\x00"),
            ("Padding", "\x00"),
            ("Data", ""),
        ]
    )

    def calculate(self):

        Data = (
            str(self.fields["Version"])
            + str(self.fields["VersionLow"])
            + str(self.fields["PacketType"])
            + str(self.fields["PacketFlag"])
            + str(self.fields["DataRepresent"])
            + str(self.fields["FragLen"])
            + str(self.fields["AuthLen"])
            + str(self.fields["CallID"])
            + str(self.fields["AllocHint"])
            + str(self.fields["ContextID"])
            + str(self.fields["CancelCount"])
            + str(self.fields["Padding"])
            + str(self.fields["Data"])
        )

        self.fields["FragLen"] = StructWithLenPython2or3("<h", len(Data))


class RPCMapBindMapperAns(Packet):
    fields = OrderedDict(
        [
            ("ContextType", "\x00\x00\x00\x00"),
            ("ContextUID", "\x00" * 16),
            ("MaxTowers", "\x02\x00\x00\x00"),
            ("TowerArrMaxCount", "\x04\x00\x00\x00\x00\x00\x00\x00"),
            ("TowerArrMaxOff", "\x00\x00\x00\x00\x00\x00\x00\x00"),
            ("TowerArrActualCount", "\x02\x00\x00\x00\x00\x00\x00\x00"),
            ("TowerPointer1", "\x03\x00\x00\x00\x00\x00\x00\x00"),
            ("TowerPointer2", "\x04\x00\x00\x00\x00\x00\x00\x00"),
            ("TowerTotalLen", "\x4b\x00\x00\x00\x00\x00\x00\x00"),
            ("Tower1Len", "\x4b\x00\x00\x00"),  # Repeat x1 from here
            ("Tower1FloorsCount", "\x05\x00"),
            ("Tower1ByteCount", "\x13\x00"),
            ("Tower1IntUID", "\x0d"),
            (
                "Tower1UID",
                "\x35\x42\x51\xe3\x06\x4b\xd1\x11\xab\x04\x00\xc0\x4f\xc2\xdc\xd2",
            ),
            ("Tower1Version", "\x04\x00"),
            ("Tower1VersionMinBC", "\x02\x00"),
            ("Tower1VersionMinimum", "\x00\x00"),
            ("Tower2ByteCount", "\x13\x00"),
            ("Tower2IntUID", "\x0d"),
            (
                "Tower2UID",
                "\x04\x5d\x88\x8a\xeb\x1c\xc9\x11\x9f\xe8\x08\x00\x2b\x10\x48\x60",
            ),
            ("Tower2Version", "\x02\x00"),
            ("Tower2VersionMinBC", "\x02\x00"),
            ("Tower2VersionMinimum", "\x00\x00"),
            ("TowerRpcByteCount", "\x01\x00"),
            ("TowerRpctIdentifier", "\x0b"),  # RPC v5
            ("TowerRpcByteCount2", "\x02\x00"),
            ("TowerRpcMinimum", "\x00\x00"),
            ("TowerPortNumberBC", "\x01\x00"),
            ("TowerPortNumberOpcode", "\x07"),  # Port is TCP.
            ("TowerPortNumberBC2", "\x02\x00"),
            ("TowerPortNumberStr", settings.Config.RPCPort),  # Port
            ("TowerIPAddressBC", "\x01\x00"),
            ("TowerIPAddressOpcode", "\x09"),  # IPv4 Opcode.
            ("TowerIPAddressBC2", "\x04\x00"),
            ("TowerIPAddressStr", ""),  # IP Address
            ("TowerIPNull", "\x00"),
            ("Data", ""),  # To here, exact same packet.
            ("Padding", "\x00"),
            ("ErrorCode", "\x00\x00\x00\x00"),  # No error.
        ]
    )

    def calculate(self):
        self.fields["TowerPortNumberStr"] = StructWithLenPython2or3(
            ">H", self.fields["TowerPortNumberStr"]
        )
        self.fields["TowerIPAddressStr"] = RespondWithIPAton()

        Data = (
            str(self.fields["TowerTotalLen"])
            + str(self.fields["Tower1Len"])
            + str(self.fields["Tower1FloorsCount"])
            + str(self.fields["Tower1ByteCount"])
            + str(self.fields["Tower1IntUID"])
            + str(self.fields["Tower1UID"])
            + str(self.fields["Tower1Version"])
            + str(self.fields["Tower1VersionMinBC"])
            + str(self.fields["Tower1VersionMinimum"])
            + str(self.fields["Tower2ByteCount"])
            + str(self.fields["Tower2IntUID"])
            + str(self.fields["Tower2UID"])
            + str(self.fields["Tower2Version"])
            + str(self.fields["Tower2VersionMinBC"])
            + str(self.fields["Tower2VersionMinimum"])
            + str(self.fields["TowerRpcByteCount"])
            + str(self.fields["TowerRpctIdentifier"])
            + str(self.fields["TowerRpcByteCount2"])
            + str(self.fields["TowerRpcMinimum"])
            + str(self.fields["TowerPortNumberBC"])
            + str(self.fields["TowerPortNumberOpcode"])
            + str(self.fields["TowerPortNumberBC2"])
            + str(self.fields["TowerPortNumberStr"])
            + str(self.fields["TowerIPAddressBC"])
            + str(self.fields["TowerIPAddressOpcode"])
            + str(self.fields["TowerIPAddressBC2"])
            + str(self.fields["TowerIPAddressStr"])
        )

        self.fields["Data"] = Data


class NTLMChallenge(Packet):
    fields = OrderedDict(
        [
            ("NTLMSSPSignature", "NTLMSSP"),
            ("NTLMSSPSignatureNull", "\x00"),
            ("NTLMSSPMessageType", "\x02\x00\x00\x00"),
            ("NTLMSSPNtWorkstationLen", "\x1e\x00"),
            ("NTLMSSPNtWorkstationMaxLen", "\x1e\x00"),
            ("NTLMSSPNtWorkstationBuffOffset", "\x38\x00\x00\x00"),
            ("NTLMSSPNtNegotiateFlags", "\x15\x82\x8a\xe2"),
            ("NTLMSSPNtServerChallenge", "\x81\x22\x33\x34\x55\x46\xe7\x88"),
            ("NTLMSSPNtReserved", "\x00\x00\x00\x00\x00\x00\x00\x00"),
            ("NTLMSSPNtTargetInfoLen", "\x94\x00"),
            ("NTLMSSPNtTargetInfoMaxLen", "\x94\x00"),
            ("NTLMSSPNtTargetInfoBuffOffset", "\x56\x00\x00\x00"),
            ("NegTokenInitSeqMechMessageVersionHigh", "\x05"),
            ("NegTokenInitSeqMechMessageVersionLow", "\x02"),
            ("NegTokenInitSeqMechMessageVersionBuilt", "\xce\x0e"),
            ("NegTokenInitSeqMechMessageVersionReserved", "\x00\x00\x00"),
            ("NegTokenInitSeqMechMessageVersionNTLMType", "\x0f"),
            ("NTLMSSPNtWorkstationName", settings.Config.Domain),
            ("NTLMSSPNTLMChallengeAVPairsId", "\x02\x00"),
            ("NTLMSSPNTLMChallengeAVPairsLen", "\x0a\x00"),
            ("NTLMSSPNTLMChallengeAVPairsUnicodeStr", settings.Config.Domain),
            ("NTLMSSPNTLMChallengeAVPairs1Id", "\x01\x00"),
            ("NTLMSSPNTLMChallengeAVPairs1Len", "\x1e\x00"),
            ("NTLMSSPNTLMChallengeAVPairs1UnicodeStr", settings.Config.MachineName),
            ("NTLMSSPNTLMChallengeAVPairs2Id", "\x04\x00"),
            ("NTLMSSPNTLMChallengeAVPairs2Len", "\x1e\x00"),
            (
                "NTLMSSPNTLMChallengeAVPairs2UnicodeStr",
                settings.Config.MachineName + "." + settings.Config.DomainName,
            ),
            ("NTLMSSPNTLMChallengeAVPairs3Id", "\x03\x00"),
            ("NTLMSSPNTLMChallengeAVPairs3Len", "\x1e\x00"),
            ("NTLMSSPNTLMChallengeAVPairs3UnicodeStr", settings.Config.DomainName),
            ("NTLMSSPNTLMChallengeAVPairs5Id", "\x05\x00"),
            ("NTLMSSPNTLMChallengeAVPairs5Len", "\x04\x00"),
            ("NTLMSSPNTLMChallengeAVPairs5UnicodeStr", settings.Config.DomainName),
            ("NTLMSSPNTLMChallengeAVPairs6Id", "\x00\x00"),
            ("NTLMSSPNTLMChallengeAVPairs6Len", "\x00\x00"),
        ]
    )

    def calculate(self):
        ###### Convert strings to Unicode first
        self.fields["NTLMSSPNtWorkstationName"] = (
            self.fields["NTLMSSPNtWorkstationName"].encode("utf-16le").decode("latin-1")
        )
        self.fields["NTLMSSPNTLMChallengeAVPairsUnicodeStr"] = (
            self.fields["NTLMSSPNTLMChallengeAVPairsUnicodeStr"]
            .encode("utf-16le")
            .decode("latin-1")
        )
        self.fields["NTLMSSPNTLMChallengeAVPairs1UnicodeStr"] = (
            self.fields["NTLMSSPNTLMChallengeAVPairs1UnicodeStr"]
            .encode("utf-16le")
            .decode("latin-1")
        )
        self.fields["NTLMSSPNTLMChallengeAVPairs2UnicodeStr"] = (
            self.fields["NTLMSSPNTLMChallengeAVPairs2UnicodeStr"]
            .encode("utf-16le")
            .decode("latin-1")
        )
        self.fields["NTLMSSPNTLMChallengeAVPairs3UnicodeStr"] = (
            self.fields["NTLMSSPNTLMChallengeAVPairs3UnicodeStr"]
            .encode("utf-16le")
            .decode("latin-1")
        )
        self.fields["NTLMSSPNTLMChallengeAVPairs5UnicodeStr"] = (
            self.fields["NTLMSSPNTLMChallengeAVPairs5UnicodeStr"]
            .encode("utf-16le")
            .decode("latin-1")
        )

        ###### Workstation Offset
        CalculateOffsetWorkstation = (
            str(self.fields["NTLMSSPSignature"])
            + str(self.fields["NTLMSSPSignatureNull"])
            + str(self.fields["NTLMSSPMessageType"])
            + str(self.fields["NTLMSSPNtWorkstationLen"])
            + str(self.fields["NTLMSSPNtWorkstationMaxLen"])
            + str(self.fields["NTLMSSPNtWorkstationBuffOffset"])
            + str(self.fields["NTLMSSPNtNegotiateFlags"])
            + str(self.fields["NTLMSSPNtServerChallenge"])
            + str(self.fields["NTLMSSPNtReserved"])
            + str(self.fields["NTLMSSPNtTargetInfoLen"])
            + str(self.fields["NTLMSSPNtTargetInfoMaxLen"])
            + str(self.fields["NTLMSSPNtTargetInfoBuffOffset"])
            + str(self.fields["NegTokenInitSeqMechMessageVersionHigh"])
            + str(self.fields["NegTokenInitSeqMechMessageVersionLow"])
            + str(self.fields["NegTokenInitSeqMechMessageVersionBuilt"])
            + str(self.fields["NegTokenInitSeqMechMessageVersionReserved"])
            + str(self.fields["NegTokenInitSeqMechMessageVersionNTLMType"])
        )
        ###### AvPairs Offset
        CalculateLenAvpairs = (
            str(self.fields["NTLMSSPNTLMChallengeAVPairsId"])
            + str(self.fields["NTLMSSPNTLMChallengeAVPairsLen"])
            + str(self.fields["NTLMSSPNTLMChallengeAVPairsUnicodeStr"])
            + str(self.fields["NTLMSSPNTLMChallengeAVPairs1Id"])
            + str(self.fields["NTLMSSPNTLMChallengeAVPairs1Len"])
            + str(self.fields["NTLMSSPNTLMChallengeAVPairs1UnicodeStr"])
            + (self.fields["NTLMSSPNTLMChallengeAVPairs2Id"])
            + str(self.fields["NTLMSSPNTLMChallengeAVPairs2Len"])
            + str(self.fields["NTLMSSPNTLMChallengeAVPairs2UnicodeStr"])
            + (self.fields["NTLMSSPNTLMChallengeAVPairs3Id"])
            + str(self.fields["NTLMSSPNTLMChallengeAVPairs3Len"])
            + str(self.fields["NTLMSSPNTLMChallengeAVPairs3UnicodeStr"])
            + (self.fields["NTLMSSPNTLMChallengeAVPairs5Id"])
            + str(self.fields["NTLMSSPNTLMChallengeAVPairs5Len"])
            + str(self.fields["NTLMSSPNTLMChallengeAVPairs5UnicodeStr"])
            + (self.fields["NTLMSSPNTLMChallengeAVPairs6Id"])
            + str(self.fields["NTLMSSPNTLMChallengeAVPairs6Len"])
        )

        ##### Workstation Offset Calculation:
        self.fields["NTLMSSPNtWorkstationBuffOffset"] = StructWithLenPython2or3(
            "<i", len(CalculateOffsetWorkstation)
        )
        self.fields["NTLMSSPNtWorkstationLen"] = StructWithLenPython2or3(
            "<h", len(str(self.fields["NTLMSSPNtWorkstationName"]))
        )
        self.fields["NTLMSSPNtWorkstationMaxLen"] = StructWithLenPython2or3(
            "<h", len(str(self.fields["NTLMSSPNtWorkstationName"]))
        )
        ##### IvPairs Offset Calculation:
        self.fields["NTLMSSPNtTargetInfoBuffOffset"] = StructWithLenPython2or3(
            "<i",
            len(
                CalculateOffsetWorkstation
                + str(self.fields["NTLMSSPNtWorkstationName"])
            ),
        )
        self.fields["NTLMSSPNtTargetInfoLen"] = StructWithLenPython2or3(
            "<h", len(CalculateLenAvpairs)
        )
        self.fields["NTLMSSPNtTargetInfoMaxLen"] = StructWithLenPython2or3(
            "<h", len(CalculateLenAvpairs)
        )
        ##### IvPair Calculation:
        self.fields["NTLMSSPNTLMChallengeAVPairs5Len"] = StructWithLenPython2or3(
            "<h", len(str(self.fields["NTLMSSPNTLMChallengeAVPairs5UnicodeStr"]))
        )
        self.fields["NTLMSSPNTLMChallengeAVPairs3Len"] = StructWithLenPython2or3(
            "<h", len(str(self.fields["NTLMSSPNTLMChallengeAVPairs3UnicodeStr"]))
        )
        self.fields["NTLMSSPNTLMChallengeAVPairs2Len"] = StructWithLenPython2or3(
            "<h", len(str(self.fields["NTLMSSPNTLMChallengeAVPairs2UnicodeStr"]))
        )
        self.fields["NTLMSSPNTLMChallengeAVPairs1Len"] = StructWithLenPython2or3(
            "<h", len(str(self.fields["NTLMSSPNTLMChallengeAVPairs1UnicodeStr"]))
        )
        self.fields["NTLMSSPNTLMChallengeAVPairsLen"] = StructWithLenPython2or3(
            "<h", len(str(self.fields["NTLMSSPNTLMChallengeAVPairsUnicodeStr"]))
        )


class RPCNTLMNego(Packet):
    fields = OrderedDict(
        [
            ("Version", "\x05"),
            ("VersionLow", "\x00"),
            ("PacketType", "\x0c"),  # Bind Ack.
            ("PacketFlag", "\x07"),  # lastfrag
            ("DataRepresent", "\x10\x00\x00\x00"),
            ("FragLen", "\xd0\x00"),
            ("AuthLen", "\x28\x00"),
            ("CallID", "\x02\x00\x00\x00"),
            ("MaxTransFrag", "\xd0\x16"),
            ("MaxRecvFrag", "\xd0\x16"),
            ("GroupAssoc", "\x94\x2c\x00\x00"),
            ("CurrentPortLen", "\x06\x00"),
            ("CurrentPortStr", settings.Config.RPCPort),
            ("CurrentPortNull", "\x00"),
            ("Pcontext", "\x03\x00\x00\x00"),
            ("CTX0ContextID", "\x02\x00"),
            ("CTX0ItemNumber", "\x02\x00"),
            (
                "CTX0UID",
                "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
            ),
            ("CTX0UIDVersion", "\x00\x00\x00\x00"),
            ("CTX1ContextID", "\x00\x00"),
            ("CTX1ItemNumber", "\x00\x00"),
            (
                "CTX1UID",
                "\x33\x05\x71\x71\xba\xbe\x37\x49\x83\x19\xb5\xdb\xef\x9c\xcc\x36",
            ),
            ("CTX1UIDVersion", "\x01\x00\x00\x00"),
            ("CTX2ContextID", "\x03\x00"),
            ("CTX2ItemNumber", "\x03\x00"),
            (
                "CTX2UID",
                "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
            ),
            ("CTX2UIDVersion", "\x00\x00\x00\x00"),
            ("AuthType", "\x0a"),  # RPC_C_AUTHN_WINNT
            ("AuthLevel", "\x06"),
            ("AuthReserved", "\x00\x00"),
            ("AuthContextID", "\x00\x00\x00\x00"),
            ("Data", ""),  # NTLM  GOES HERE
        ]
    )

    def calculate(self):

        self.fields["AuthLen"] = StructWithLenPython2or3(
            "<h", len(str(self.fields["Data"]))
        )
        Data = (
            str(self.fields["Version"])
            + str(self.fields["VersionLow"])
            + str(self.fields["PacketType"])
            + str(self.fields["PacketFlag"])
            + str(self.fields["DataRepresent"])
            + str(self.fields["FragLen"])
            + str(self.fields["AuthLen"])
            + str(self.fields["CallID"])
            + str(self.fields["MaxTransFrag"])
            + str(self.fields["MaxRecvFrag"])
            + str(self.fields["GroupAssoc"])
            + str(self.fields["CurrentPortLen"])
            + str(self.fields["CurrentPortStr"])
            + str(self.fields["CurrentPortNull"])
            + str(self.fields["Pcontext"])
            + str(self.fields["CTX0ContextID"])
            + str(self.fields["CTX0ItemNumber"])
            + str(self.fields["CTX0UID"])
            + str(self.fields["CTX0UIDVersion"])
            + str(self.fields["CTX1ContextID"])
            + str(self.fields["CTX1ItemNumber"])
            + str(self.fields["CTX1UID"])
            + str(self.fields["CTX1UIDVersion"])
            + str(self.fields["CTX2ContextID"])
            + str(self.fields["CTX2ItemNumber"])
            + str(self.fields["CTX2UID"])
            + str(self.fields["CTX2UIDVersion"])
            + str(self.fields["AuthType"])
            + str(self.fields["AuthLevel"])
            + str(self.fields["AuthReserved"])
            + str(self.fields["AuthContextID"])
            + str(self.fields["Data"])
        )

        self.fields["FragLen"] = StructWithLenPython2or3("<h", len(Data))


################### Mailslot NETLOGON ######################
class NBTUDPHeader(Packet):
    fields = OrderedDict(
        [
            ("MessType", "\x11"),
            ("MoreFrag", "\x02"),
            ("TID", "\x82\x92"),
            ("SrcIP", "0.0.0.0"),
            ("SrcPort", "\x00\x8a"),  ##Always 138
            ("DatagramLen", "\x00\x00"),
            ("PacketOffset", "\x00\x00"),
            ("ClientNBTName", ""),
            ("DstNBTName", ""),
            ("Data", ""),
        ]
    )

    def calculate(self):
        self.fields["SrcIP"] = RespondWithIPAton()
        ## DatagramLen.
        DataGramLen = (
            str(self.fields["PacketOffset"])
            + str(self.fields["ClientNBTName"])
            + str(self.fields["DstNBTName"])
            + str(self.fields["Data"])
        )
        self.fields["DatagramLen"] = StructWithLenPython2or3(">h", len(DataGramLen))


class SMBTransMailslot(Packet):
    fields = OrderedDict(
        [
            ("Wordcount", "\x11"),
            ("TotalParamCount", "\x00\x00"),
            ("TotalDataCount", "\x00\x00"),
            ("MaxParamCount", "\x02\x00"),
            ("MaxDataCount", "\x00\x00"),
            ("MaxSetupCount", "\x00"),
            ("Reserved", "\x00"),
            ("Flags", "\x00\x00"),
            ("Timeout", "\xff\xff\xff\xff"),
            ("Reserved2", "\x00\x00"),
            ("ParamCount", "\x00\x00"),
            ("ParamOffset", "\x00\x00"),
            ("DataCount", "\x00\x00"),
            ("DataOffset", "\x00\x00"),
            ("SetupCount", "\x03"),
            ("Reserved3", "\x00"),
            ("Opcode", "\x01\x00"),
            ("Priority", "\x00\x00"),
            ("Class", "\x02\x00"),
            ("Bcc", "\x00\x00"),
            ("MailSlot", "\\MAILSLOT\\NET\\NETLOGON"),
            ("MailSlotNull", "\x00"),
            ("Padding", "\x00\x00\x00"),
            ("Data", ""),
        ]
    )

    def calculate(self):
        # Padding
        if len(str(self.fields["Data"])) % 2 == 0:
            self.fields["Padding"] = "\x00\x00\x00\x00"
        else:
            self.fields["Padding"] = "\x00\x00\x00"
        BccLen = (
            str(self.fields["MailSlot"])
            + str(self.fields["MailSlotNull"])
            + str(self.fields["Padding"])
            + str(self.fields["Data"])
        )
        PacketOffsetLen = (
            str(self.fields["Wordcount"])
            + str(self.fields["TotalParamCount"])
            + str(self.fields["TotalDataCount"])
            + str(self.fields["MaxParamCount"])
            + str(self.fields["MaxDataCount"])
            + str(self.fields["MaxSetupCount"])
            + str(self.fields["Reserved"])
            + str(self.fields["Flags"])
            + str(self.fields["Timeout"])
            + str(self.fields["Reserved2"])
            + str(self.fields["ParamCount"])
            + str(self.fields["ParamOffset"])
            + str(self.fields["DataCount"])
            + str(self.fields["DataOffset"])
            + str(self.fields["SetupCount"])
            + str(self.fields["Reserved3"])
            + str(self.fields["Opcode"])
            + str(self.fields["Priority"])
            + str(self.fields["Class"])
            + str(self.fields["Bcc"])
            + str(self.fields["MailSlot"])
            + str(self.fields["MailSlotNull"])
            + str(self.fields["Padding"])
        )

        self.fields["DataCount"] = StructWithLenPython2or3(
            "<h", len(str(self.fields["Data"]))
        )
        self.fields["TotalDataCount"] = StructWithLenPython2or3(
            "<h", len(str(self.fields["Data"]))
        )
        self.fields["DataOffset"] = StructWithLenPython2or3(
            "<h", len(PacketOffsetLen) + 32
        )
        self.fields["ParamOffset"] = StructWithLenPython2or3(
            "<h", len(PacketOffsetLen) + 32
        )
        self.fields["Bcc"] = StructWithLenPython2or3("<h", len(BccLen))


class SamLogonResponseEx(Packet):
    fields = OrderedDict(
        [
            ("Cmd", "\x17\x00"),
            ("Sbz", "\x00\x00"),
            ("Flags", "\xfd\x03\x00\x00"),
            (
                "DomainGUID",
                "\xe7\xfd\xf2\x4a\x4f\x98\x8b\x49\xbb\xd3\xcd\x34\xc7\xba\x57\x70",
            ),
            ("ForestName", "\x04\x73\x6d\x62\x33\x05\x6c\x6f\x63\x61\x6c"),
            ("ForestNameNull", "\x00"),
            ("ForestDomainName", "\x04\x73\x6d\x62\x33\x05\x6c\x6f\x63\x61\x6c"),
            ("ForestDomainNull", "\x00"),
            ("DNSName", "\x0a\x73\x65\x72\x76\x65\x72\x32\x30\x30\x33"),
            ("DNSPointer", "\xc0\x18"),
            ("DomainName", "\x04\x53\x4d\x42\x33"),
            ("DomainTerminator", "\x00"),
            ("ServerLen", "\x0a"),
            ("ServerName", settings.Config.MachineName),
            ("ServerTerminator", "\x00"),
            ("UsernameLen", "\x10"),
            ("Username", settings.Config.Username),
            ("UserTerminator", "\x00"),
            ("SrvSiteNameLen", "\x17"),
            ("SrvSiteName", "Default-First-Site-Name"),
            ("SrvSiteNameNull", "\x00"),
            ("Pointer", "\xc0"),
            ("PointerOffset", "\x5c"),
            ("DCAddrSize", "\x10"),
            ("AddrType", "\x02\x00"),
            ("Port", "\x00\x00"),
            ("DCAddress", "\xc0\xab\x01\x65"),
            ("SinZero", "\x00\x00\x00\x00\x00\x00\x00\x00"),
            ("Version", "\x0d\x00\x00\x00"),
            ("LmToken", "\xff\xff"),
            ("LmToken2", "\xff\xff"),
        ]
    )

    def calculate(self):
        Offset = (
            str(self.fields["Cmd"])
            + str(self.fields["Sbz"])
            + str(self.fields["Flags"])
            + str(self.fields["DomainGUID"])
            + str(self.fields["ForestName"])
            + str(self.fields["ForestNameNull"])
            + str(self.fields["ForestDomainName"])
            + str(self.fields["ForestDomainNull"])
            + str(self.fields["DNSName"])
            + str(self.fields["DNSPointer"])
            + str(self.fields["DomainName"])
            + str(self.fields["DomainTerminator"])
            + str(self.fields["ServerLen"])
            + str(self.fields["ServerName"])
            + str(self.fields["ServerTerminator"])
            + str(self.fields["UsernameLen"])
            + str(self.fields["Username"])
            + str(self.fields["UserTerminator"])
        )

        DcLen = (
            str(self.fields["AddrType"])
            + str(self.fields["Port"])
            + str(self.fields["DCAddress"])
            + str(self.fields["SinZero"])
        )
        self.fields["DCAddress"] = RespondWithIPAton()
        self.fields["ServerLen"] = StructWithLenPython2or3(
            "<B", len(str(self.fields["ServerName"]))
        )
        self.fields["UsernameLen"] = StructWithLenPython2or3(
            "<B", len(str(self.fields["Username"]))
        )
        self.fields["SrvSiteNameLen"] = StructWithLenPython2or3(
            "<B", len(str(self.fields["SrvSiteName"]))
        )
        self.fields["DCAddrSize"] = StructWithLenPython2or3("<B", len(DcLen))
        self.fields["PointerOffset"] = StructWithLenPython2or3("<B", len(Offset))
