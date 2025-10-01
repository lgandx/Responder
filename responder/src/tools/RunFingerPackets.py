import random, struct, sys, os
from os import urandom
from socket import *
from time import sleep
from responder.src.odict import OrderedDict

# Python version
if sys.version_info > (3, 0):
    PY2OR3 = "PY3"
else:
    PY2OR3 = "PY2"


def StructWithLenPython2or3(endian, data):
    # Python2...
    if PY2OR3 == "PY2":
        return struct.pack(endian, data)
    # Python3...
    else:
        return struct.pack(endian, data).decode("latin-1")


def NetworkSendBufferPython2or3(data):
    if PY2OR3 == "PY2":
        return str(data)
    else:
        return bytes(str(data), "latin-1")


def NetworkRecvBufferPython2or3(data):
    if PY2OR3 == "PY2":
        return str(data)
    else:
        return str(data.decode("latin-1"))


class Packet:
    fields = OrderedDict([])

    def __init__(self, **kw):
        self.fields = OrderedDict(self.__class__.fields)
        for k, v in list(kw.items()):
            if callable(v):
                self.fields[k] = v(self.fields[k])
            else:
                self.fields[k] = v

    def __str__(self):
        return "".join(map(str, list(self.fields.values())))


class SMBHeader(Packet):
    fields = OrderedDict(
        [
            ("proto", "\xff\x53\x4d\x42"),
            ("cmd", "\x72"),
            ("error-code", "\x00\x00\x00\x00"),
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
    fields = OrderedDict([("Wordcount", "\x00"), ("Bcc", "\x62\x00"), ("Data", "")])

    def calculate(self):
        self.fields["Bcc"] = StructWithLenPython2or3(
            "<h", len(str(self.fields["Data"]))
        )


class SMBNegoData(Packet):
    fields = OrderedDict(
        [
            ("BuffType", "\x02"),
            ("Dialect", "NT LM 0.12\x00"),
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
            (
                "bcc1",
                "\xb1\x00",
            ),  # hardcoded len here and hardcoded packet below, no calculation, faster.
            (
                "Data",
                "\x60\x48\x06\x06\x2b\x06\x01\x05\x05\x02\xa0\x3e\x30\x3c\xa0\x0e\x30\x0c\x06\x0a\x2b\x06\x01\x04\x01\x82\x37\x02\x02\x0a\xa2\x2a\x04\x28\x4e\x54\x4c\x4d\x53\x53\x50\x00\x01\x00\x00\x00\x07\x82\x08\xa2\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x05\x01\x28\x0a\x00\x00\x00\x0f\x00\x57\x00\x69\x00\x6e\x00\x64\x00\x6f\x00\x77\x00\x73\x00\x20\x00\x32\x00\x30\x00\x30\x00\x32\x00\x20\x00\x53\x00\x65\x00\x72\x00\x76\x00\x69\x00\x63\x00\x65\x00\x20\x00\x50\x00\x61\x00\x63\x00\x6b\x00\x20\x00\x33\x00\x20\x00\x32\x00\x36\x00\x30\x00\x30\x00\x00\x00\x57\x00\x69\x00\x6e\x00\x64\x00\x6f\x00\x77\x00\x73\x00\x20\x00\x32\x00\x30\x00\x30\x00\x32\x00\x20\x00\x35\x00\x2e\x00\x31\x00\x00\x00\x00\x00",
            ),
        ]
    )


##Now Lanman
class SMBHeaderLanMan(Packet):
    fields = OrderedDict(
        [
            ("proto", "\xff\x53\x4d\x42"),
            ("cmd", "\x72"),
            ("error-code", "\x00\x00\x00\x00"),
            ("flag1", "\x08"),
            ("flag2", "\x01\xc8"),
            ("pidhigh", "\x00\x00"),
            ("signature", "\x00\x00\x00\x00\x00\x00\x00\x00"),
            ("reserved", "\x00\x00"),
            ("tid", "\x00\x00"),
            ("pid", "\x3c\x1b"),
            ("uid", "\x00\x00"),
            ("mid", "\x00\x00"),
        ]
    )


# We grab the domain and hostname from the negotiate protocol answer, since it is in a Lanman dialect format.
class SMBNegoDataLanMan(Packet):
    fields = OrderedDict(
        [
            ("Wordcount", "\x00"),
            (
                "Bcc",
                "\x0c\x00",
            ),  # hardcoded len here and hardcoded packet below, no calculation, faster.
            ("BuffType", "\x02"),
            ("Dialect", "NT LM 0.12\x00"),
        ]
    )


class SMBSessionData(Packet):
    fields = OrderedDict(
        [
            ("wordcount", "\x0c"),
            ("AndXCommand", "\xff"),
            ("reserved", "\x00"),
            ("andxoffset", "\xec\x00"),
            ("maxbuff", "\x04\x11"),
            ("maxmpx", "\x32\x00"),
            ("vcnum", "\x00\x00"),
            ("sessionkey", "\x00\x00\x00\x00"),
            ("securitybloblength", "\x4a\x00"),
            ("reserved2", "\x00\x00\x00\x00"),
            ("capabilities", "\xd4\x00\x00\xa0"),
            ("bcc1", "\xb1\x00"),
            ("ApplicationHeaderTag", "\x60"),
            ("ApplicationHeaderLen", "\x48"),
            ("AsnSecMechType", "\x06"),
            ("AsnSecMechLen", "\x06"),
            ("AsnSecMechStr", "\x2b\x06\x01\x05\x05\x02"),
            ("ChoosedTag", "\xa0"),
            ("ChoosedTagStrLen", "\x3e"),
            ("NegTokenInitSeqHeadTag", "\x30"),
            ("NegTokenInitSeqHeadLen", "\x3c"),
            ("NegTokenInitSeqHeadTag1", "\xa0"),
            ("NegTokenInitSeqHeadLen1", "\x0e"),
            ("NegTokenInitSeqNLMPTag", "\x30"),
            ("NegTokenInitSeqNLMPLen", "\x0c"),
            ("NegTokenInitSeqNLMPTag1", "\x06"),
            ("NegTokenInitSeqNLMPTag1Len", "\x0a"),
            ("NegTokenInitSeqNLMPTag1Str", "\x2b\x06\x01\x04\x01\x82\x37\x02\x02\x0a"),
            ("NegTokenInitSeqNLMPTag2", "\xa2"),
            ("NegTokenInitSeqNLMPTag2Len", "\x2a"),
            ("NegTokenInitSeqNLMPTag2Octet", "\x04"),
            ("NegTokenInitSeqNLMPTag2OctetLen", "\x28"),
            ("NegTokenInitSeqMechSignature", "\x4e\x54\x4c\x4d\x53\x53\x50\x00"),
            ("NegTokenInitSeqMechMessageType", "\x01\x00\x00\x00"),
            ("NegTokenInitSeqMechMessageFlags", "\x07\x82\x08\xa2"),
            ("NegTokenInitSeqMechMessageDomainNameLen", "\x00\x00"),
            ("NegTokenInitSeqMechMessageDomainNameMaxLen", "\x00\x00"),
            ("NegTokenInitSeqMechMessageDomainNameBuffOffset", "\x00\x00\x00\x00"),
            ("NegTokenInitSeqMechMessageWorkstationNameLen", "\x00\x00"),
            ("NegTokenInitSeqMechMessageWorkstationNameMaxLen", "\x00\x00"),
            ("NegTokenInitSeqMechMessageWorkstationNameBuffOffset", "\x00\x00\x00\x00"),
            ("NegTokenInitSeqMechMessageVersionHigh", "\x05"),
            ("NegTokenInitSeqMechMessageVersionLow", "\x01"),
            ("NegTokenInitSeqMechMessageVersionBuilt", "\x28\x0a"),
            ("NegTokenInitSeqMechMessageVersionReserved", "\x00\x00\x00"),
            ("NegTokenInitSeqMechMessageVersionNTLMType", "\x0f"),
            ("NegTokenInitSeqMechMessageVersionTerminator", "\x00"),
            (
                "nativeOs",
                "Windows 2002 Service Pack 3 2600".encode("utf-16le").decode("latin-1"),
            ),
            ("nativeOsterminator", "\x00\x00"),
            ("nativelan", "Windows 2002 5.1".encode("utf-16le").decode("latin-1")),
            ("nativelanterminator", "\x00\x00\x00\x00"),
        ]
    )

    def calculate(self):

        data1 = (
            str(self.fields["ApplicationHeaderTag"])
            + str(self.fields["ApplicationHeaderLen"])
            + str(self.fields["AsnSecMechType"])
            + str(self.fields["AsnSecMechLen"])
            + str(self.fields["AsnSecMechStr"])
            + str(self.fields["ChoosedTag"])
            + str(self.fields["ChoosedTagStrLen"])
            + str(self.fields["NegTokenInitSeqHeadTag"])
            + str(self.fields["NegTokenInitSeqHeadLen"])
            + str(self.fields["NegTokenInitSeqHeadTag1"])
            + str(self.fields["NegTokenInitSeqHeadLen1"])
            + str(self.fields["NegTokenInitSeqNLMPTag"])
            + str(self.fields["NegTokenInitSeqNLMPLen"])
            + str(self.fields["NegTokenInitSeqNLMPTag1"])
            + str(self.fields["NegTokenInitSeqNLMPTag1Len"])
            + str(self.fields["NegTokenInitSeqNLMPTag1Str"])
            + str(self.fields["NegTokenInitSeqNLMPTag2"])
            + str(self.fields["NegTokenInitSeqNLMPTag2Len"])
            + str(self.fields["NegTokenInitSeqNLMPTag2Octet"])
            + str(self.fields["NegTokenInitSeqNLMPTag2OctetLen"])
            + str(self.fields["NegTokenInitSeqMechSignature"])
            + str(self.fields["NegTokenInitSeqMechMessageType"])
            + str(self.fields["NegTokenInitSeqMechMessageFlags"])
            + str(self.fields["NegTokenInitSeqMechMessageDomainNameLen"])
            + str(self.fields["NegTokenInitSeqMechMessageDomainNameMaxLen"])
            + str(self.fields["NegTokenInitSeqMechMessageDomainNameBuffOffset"])
            + str(self.fields["NegTokenInitSeqMechMessageWorkstationNameLen"])
            + str(self.fields["NegTokenInitSeqMechMessageWorkstationNameMaxLen"])
            + str(self.fields["NegTokenInitSeqMechMessageWorkstationNameBuffOffset"])
            + str(self.fields["NegTokenInitSeqMechMessageVersionHigh"])
            + str(self.fields["NegTokenInitSeqMechMessageVersionLow"])
            + str(self.fields["NegTokenInitSeqMechMessageVersionBuilt"])
            + str(self.fields["NegTokenInitSeqMechMessageVersionReserved"])
            + str(self.fields["NegTokenInitSeqMechMessageVersionNTLMType"])
        )

        data2 = (
            str(self.fields["AsnSecMechType"])
            + str(self.fields["AsnSecMechLen"])
            + str(self.fields["AsnSecMechStr"])
            + str(self.fields["ChoosedTag"])
            + str(self.fields["ChoosedTagStrLen"])
            + str(self.fields["NegTokenInitSeqHeadTag"])
            + str(self.fields["NegTokenInitSeqHeadLen"])
            + str(self.fields["NegTokenInitSeqHeadTag1"])
            + str(self.fields["NegTokenInitSeqHeadLen1"])
            + str(self.fields["NegTokenInitSeqNLMPTag"])
            + str(self.fields["NegTokenInitSeqNLMPLen"])
            + str(self.fields["NegTokenInitSeqNLMPTag1"])
            + str(self.fields["NegTokenInitSeqNLMPTag1Len"])
            + str(self.fields["NegTokenInitSeqNLMPTag1Str"])
            + str(self.fields["NegTokenInitSeqNLMPTag2"])
            + str(self.fields["NegTokenInitSeqNLMPTag2Len"])
            + str(self.fields["NegTokenInitSeqNLMPTag2Octet"])
            + str(self.fields["NegTokenInitSeqNLMPTag2OctetLen"])
            + str(self.fields["NegTokenInitSeqMechSignature"])
            + str(self.fields["NegTokenInitSeqMechMessageType"])
            + str(self.fields["NegTokenInitSeqMechMessageFlags"])
            + str(self.fields["NegTokenInitSeqMechMessageDomainNameLen"])
            + str(self.fields["NegTokenInitSeqMechMessageDomainNameMaxLen"])
            + str(self.fields["NegTokenInitSeqMechMessageDomainNameBuffOffset"])
            + str(self.fields["NegTokenInitSeqMechMessageWorkstationNameLen"])
            + str(self.fields["NegTokenInitSeqMechMessageWorkstationNameMaxLen"])
            + str(self.fields["NegTokenInitSeqMechMessageWorkstationNameBuffOffset"])
            + str(self.fields["NegTokenInitSeqMechMessageVersionHigh"])
            + str(self.fields["NegTokenInitSeqMechMessageVersionLow"])
            + str(self.fields["NegTokenInitSeqMechMessageVersionBuilt"])
            + str(self.fields["NegTokenInitSeqMechMessageVersionReserved"])
            + str(self.fields["NegTokenInitSeqMechMessageVersionNTLMType"])
        )

        data3 = (
            str(self.fields["NegTokenInitSeqHeadTag"])
            + str(self.fields["NegTokenInitSeqHeadLen"])
            + str(self.fields["NegTokenInitSeqHeadTag1"])
            + str(self.fields["NegTokenInitSeqHeadLen1"])
            + str(self.fields["NegTokenInitSeqNLMPTag"])
            + str(self.fields["NegTokenInitSeqNLMPLen"])
            + str(self.fields["NegTokenInitSeqNLMPTag1"])
            + str(self.fields["NegTokenInitSeqNLMPTag1Len"])
            + str(self.fields["NegTokenInitSeqNLMPTag1Str"])
            + str(self.fields["NegTokenInitSeqNLMPTag2"])
            + str(self.fields["NegTokenInitSeqNLMPTag2Len"])
            + str(self.fields["NegTokenInitSeqNLMPTag2Octet"])
            + str(self.fields["NegTokenInitSeqNLMPTag2OctetLen"])
            + str(self.fields["NegTokenInitSeqMechSignature"])
            + str(self.fields["NegTokenInitSeqMechMessageType"])
            + str(self.fields["NegTokenInitSeqMechMessageFlags"])
            + str(self.fields["NegTokenInitSeqMechMessageDomainNameLen"])
            + str(self.fields["NegTokenInitSeqMechMessageDomainNameMaxLen"])
            + str(self.fields["NegTokenInitSeqMechMessageDomainNameBuffOffset"])
            + str(self.fields["NegTokenInitSeqMechMessageWorkstationNameLen"])
            + str(self.fields["NegTokenInitSeqMechMessageWorkstationNameMaxLen"])
            + str(self.fields["NegTokenInitSeqMechMessageWorkstationNameBuffOffset"])
            + str(self.fields["NegTokenInitSeqMechMessageVersionHigh"])
            + str(self.fields["NegTokenInitSeqMechMessageVersionLow"])
            + str(self.fields["NegTokenInitSeqMechMessageVersionBuilt"])
            + str(self.fields["NegTokenInitSeqMechMessageVersionReserved"])
            + str(self.fields["NegTokenInitSeqMechMessageVersionNTLMType"])
        )

        data4 = (
            str(self.fields["NegTokenInitSeqHeadTag1"])
            + str(self.fields["NegTokenInitSeqHeadLen1"])
            + str(self.fields["NegTokenInitSeqNLMPTag"])
            + str(self.fields["NegTokenInitSeqNLMPLen"])
            + str(self.fields["NegTokenInitSeqNLMPTag1"])
            + str(self.fields["NegTokenInitSeqNLMPTag1Len"])
            + str(self.fields["NegTokenInitSeqNLMPTag1Str"])
            + str(self.fields["NegTokenInitSeqNLMPTag2"])
            + str(self.fields["NegTokenInitSeqNLMPTag2Len"])
            + str(self.fields["NegTokenInitSeqNLMPTag2Octet"])
            + str(self.fields["NegTokenInitSeqNLMPTag2OctetLen"])
            + str(self.fields["NegTokenInitSeqMechSignature"])
            + str(self.fields["NegTokenInitSeqMechMessageType"])
            + str(self.fields["NegTokenInitSeqMechMessageFlags"])
            + str(self.fields["NegTokenInitSeqMechMessageDomainNameLen"])
            + str(self.fields["NegTokenInitSeqMechMessageDomainNameMaxLen"])
            + str(self.fields["NegTokenInitSeqMechMessageDomainNameBuffOffset"])
            + str(self.fields["NegTokenInitSeqMechMessageWorkstationNameLen"])
            + str(self.fields["NegTokenInitSeqMechMessageWorkstationNameMaxLen"])
            + str(self.fields["NegTokenInitSeqMechMessageWorkstationNameBuffOffset"])
            + str(self.fields["NegTokenInitSeqMechMessageVersionHigh"])
            + str(self.fields["NegTokenInitSeqMechMessageVersionLow"])
            + str(self.fields["NegTokenInitSeqMechMessageVersionBuilt"])
            + str(self.fields["NegTokenInitSeqMechMessageVersionReserved"])
            + str(self.fields["NegTokenInitSeqMechMessageVersionNTLMType"])
        )

        data5 = (
            str(self.fields["ApplicationHeaderTag"])
            + str(self.fields["ApplicationHeaderLen"])
            + str(self.fields["AsnSecMechType"])
            + str(self.fields["AsnSecMechLen"])
            + str(self.fields["AsnSecMechStr"])
            + str(self.fields["ChoosedTag"])
            + str(self.fields["ChoosedTagStrLen"])
            + str(self.fields["NegTokenInitSeqHeadTag"])
            + str(self.fields["NegTokenInitSeqHeadLen"])
            + str(self.fields["NegTokenInitSeqHeadTag1"])
            + str(self.fields["NegTokenInitSeqHeadLen1"])
            + str(self.fields["NegTokenInitSeqNLMPTag"])
            + str(self.fields["NegTokenInitSeqNLMPLen"])
            + str(self.fields["NegTokenInitSeqNLMPTag1"])
            + str(self.fields["NegTokenInitSeqNLMPTag1Len"])
            + str(self.fields["NegTokenInitSeqNLMPTag1Str"])
            + str(self.fields["NegTokenInitSeqNLMPTag2"])
            + str(self.fields["NegTokenInitSeqNLMPTag2Len"])
            + str(self.fields["NegTokenInitSeqNLMPTag2Octet"])
            + str(self.fields["NegTokenInitSeqNLMPTag2OctetLen"])
            + str(self.fields["NegTokenInitSeqMechSignature"])
            + str(self.fields["NegTokenInitSeqMechMessageType"])
            + str(self.fields["NegTokenInitSeqMechMessageFlags"])
            + str(self.fields["NegTokenInitSeqMechMessageDomainNameLen"])
            + str(self.fields["NegTokenInitSeqMechMessageDomainNameMaxLen"])
            + str(self.fields["NegTokenInitSeqMechMessageDomainNameBuffOffset"])
            + str(self.fields["NegTokenInitSeqMechMessageWorkstationNameLen"])
            + str(self.fields["NegTokenInitSeqMechMessageWorkstationNameMaxLen"])
            + str(self.fields["NegTokenInitSeqMechMessageWorkstationNameBuffOffset"])
            + str(self.fields["NegTokenInitSeqMechMessageVersionHigh"])
            + str(self.fields["NegTokenInitSeqMechMessageVersionLow"])
            + str(self.fields["NegTokenInitSeqMechMessageVersionBuilt"])
            + str(self.fields["NegTokenInitSeqMechMessageVersionReserved"])
            + str(self.fields["NegTokenInitSeqMechMessageVersionNTLMType"])
            + str(self.fields["NegTokenInitSeqMechMessageVersionTerminator"])
            + str(self.fields["nativeOs"])
            + str(self.fields["nativeOsterminator"])
            + str(self.fields["nativelan"])
            + str(self.fields["nativelanterminator"])
        )

        data6 = (
            str(self.fields["NegTokenInitSeqNLMPTag2Octet"])
            + str(self.fields["NegTokenInitSeqNLMPTag2OctetLen"])
            + str(self.fields["NegTokenInitSeqMechSignature"])
            + str(self.fields["NegTokenInitSeqMechMessageType"])
            + str(self.fields["NegTokenInitSeqMechMessageFlags"])
            + str(self.fields["NegTokenInitSeqMechMessageDomainNameLen"])
            + str(self.fields["NegTokenInitSeqMechMessageDomainNameMaxLen"])
            + str(self.fields["NegTokenInitSeqMechMessageDomainNameBuffOffset"])
            + str(self.fields["NegTokenInitSeqMechMessageWorkstationNameLen"])
            + str(self.fields["NegTokenInitSeqMechMessageWorkstationNameMaxLen"])
            + str(self.fields["NegTokenInitSeqMechMessageWorkstationNameBuffOffset"])
            + str(self.fields["NegTokenInitSeqMechMessageVersionHigh"])
            + str(self.fields["NegTokenInitSeqMechMessageVersionLow"])
            + str(self.fields["NegTokenInitSeqMechMessageVersionBuilt"])
            + str(self.fields["NegTokenInitSeqMechMessageVersionReserved"])
            + str(self.fields["NegTokenInitSeqMechMessageVersionNTLMType"])
        )

        data7 = (
            str(self.fields["NegTokenInitSeqMechSignature"])
            + str(self.fields["NegTokenInitSeqMechMessageType"])
            + str(self.fields["NegTokenInitSeqMechMessageFlags"])
            + str(self.fields["NegTokenInitSeqMechMessageDomainNameLen"])
            + str(self.fields["NegTokenInitSeqMechMessageDomainNameMaxLen"])
            + str(self.fields["NegTokenInitSeqMechMessageDomainNameBuffOffset"])
            + str(self.fields["NegTokenInitSeqMechMessageWorkstationNameLen"])
            + str(self.fields["NegTokenInitSeqMechMessageWorkstationNameMaxLen"])
            + str(self.fields["NegTokenInitSeqMechMessageWorkstationNameBuffOffset"])
            + str(self.fields["NegTokenInitSeqMechMessageVersionHigh"])
            + str(self.fields["NegTokenInitSeqMechMessageVersionLow"])
            + str(self.fields["NegTokenInitSeqMechMessageVersionBuilt"])
            + str(self.fields["NegTokenInitSeqMechMessageVersionReserved"])
            + str(self.fields["NegTokenInitSeqMechMessageVersionNTLMType"])
        )

        data9 = (
            str(self.fields["wordcount"])
            + str(self.fields["AndXCommand"])
            + str(self.fields["reserved"])
            + str(self.fields["andxoffset"])
            + str(self.fields["maxbuff"])
            + str(self.fields["maxmpx"])
            + str(self.fields["vcnum"])
            + str(self.fields["sessionkey"])
            + str(self.fields["securitybloblength"])
            + str(self.fields["reserved2"])
            + str(self.fields["capabilities"])
            + str(self.fields["bcc1"])
            + str(self.fields["ApplicationHeaderTag"])
            + str(self.fields["ApplicationHeaderLen"])
            + str(self.fields["AsnSecMechType"])
            + str(self.fields["AsnSecMechLen"])
            + str(self.fields["AsnSecMechStr"])
            + str(self.fields["ChoosedTag"])
            + str(self.fields["ChoosedTagStrLen"])
            + str(self.fields["NegTokenInitSeqHeadTag"])
            + str(self.fields["NegTokenInitSeqHeadLen"])
            + str(self.fields["NegTokenInitSeqHeadTag1"])
            + str(self.fields["NegTokenInitSeqHeadLen1"])
            + str(self.fields["NegTokenInitSeqNLMPTag"])
            + str(self.fields["NegTokenInitSeqNLMPLen"])
            + str(self.fields["NegTokenInitSeqNLMPTag1"])
            + str(self.fields["NegTokenInitSeqNLMPTag1Len"])
            + str(self.fields["NegTokenInitSeqNLMPTag1Str"])
            + str(self.fields["NegTokenInitSeqNLMPTag2"])
            + str(self.fields["NegTokenInitSeqNLMPTag2Len"])
            + str(self.fields["NegTokenInitSeqNLMPTag2Octet"])
            + str(self.fields["NegTokenInitSeqNLMPTag2OctetLen"])
            + str(self.fields["NegTokenInitSeqMechSignature"])
            + str(self.fields["NegTokenInitSeqMechMessageType"])
            + str(self.fields["NegTokenInitSeqMechMessageFlags"])
            + str(self.fields["NegTokenInitSeqMechMessageDomainNameLen"])
            + str(self.fields["NegTokenInitSeqMechMessageDomainNameMaxLen"])
            + str(self.fields["NegTokenInitSeqMechMessageDomainNameBuffOffset"])
            + str(self.fields["NegTokenInitSeqMechMessageWorkstationNameLen"])
            + str(self.fields["NegTokenInitSeqMechMessageWorkstationNameMaxLen"])
            + str(self.fields["NegTokenInitSeqMechMessageWorkstationNameBuffOffset"])
            + str(self.fields["NegTokenInitSeqMechMessageVersionHigh"])
            + str(self.fields["NegTokenInitSeqMechMessageVersionLow"])
            + str(self.fields["NegTokenInitSeqMechMessageVersionBuilt"])
            + str(self.fields["NegTokenInitSeqMechMessageVersionReserved"])
            + str(self.fields["NegTokenInitSeqMechMessageVersionNTLMType"])
            + str(self.fields["NegTokenInitSeqMechMessageVersionTerminator"])
            + str(self.fields["nativeOs"])
            + str(self.fields["nativeOsterminator"])
            + str(self.fields["nativelan"])
            + str(self.fields["nativelanterminator"])
        )

        data10 = (
            str(self.fields["NegTokenInitSeqNLMPTag"])
            + str(self.fields["NegTokenInitSeqNLMPLen"])
            + str(self.fields["NegTokenInitSeqNLMPTag1"])
            + str(self.fields["NegTokenInitSeqNLMPTag1Len"])
            + str(self.fields["NegTokenInitSeqNLMPTag1Str"])
        )

        data11 = (
            str(self.fields["NegTokenInitSeqNLMPTag1"])
            + str(self.fields["NegTokenInitSeqNLMPTag1Len"])
            + str(self.fields["NegTokenInitSeqNLMPTag1Str"])
        )

        ## Packet len
        self.fields["andxoffset"] = StructWithLenPython2or3("<H", len(data9) + 32)
        ##Buff Len
        self.fields["securitybloblength"] = StructWithLenPython2or3("<H", len(data1))
        ##Complete Buff Len
        self.fields["bcc1"] = StructWithLenPython2or3("<H", len(data5))
        ##App Header
        self.fields["ApplicationHeaderLen"] = StructWithLenPython2or3("<B", len(data2))
        ##Asn Field 1
        self.fields["AsnSecMechLen"] = StructWithLenPython2or3(
            "<B", len(str(self.fields["AsnSecMechStr"]))
        )
        ##Asn Field 1
        self.fields["ChoosedTagStrLen"] = StructWithLenPython2or3("<B", len(data3))
        ##SpNegoTokenLen
        self.fields["NegTokenInitSeqHeadLen"] = StructWithLenPython2or3(
            "<B", len(data4)
        )
        ##NegoTokenInit
        self.fields["NegTokenInitSeqHeadLen1"] = StructWithLenPython2or3(
            "<B", len(data10)
        )
        ## Tag0 Len
        self.fields["NegTokenInitSeqNLMPLen"] = StructWithLenPython2or3(
            "<B", len(data11)
        )
        ## Tag0 Str Len
        self.fields["NegTokenInitSeqNLMPTag1Len"] = StructWithLenPython2or3(
            "<B", len(str(self.fields["NegTokenInitSeqNLMPTag1Str"]))
        )
        ## Tag2 Len
        self.fields["NegTokenInitSeqNLMPTag2Len"] = StructWithLenPython2or3(
            "<B", len(data6)
        )
        ## Tag3 Len
        self.fields["NegTokenInitSeqNLMPTag2OctetLen"] = StructWithLenPython2or3(
            "<B", len(data7)
        )


#########################################################################################################
class SMBSession2(Packet):
    fields = OrderedDict(
        [
            ("wordcount", "\x0c"),
            ("AndXCommand", "\xff"),
            ("reserved", "\x00"),
            ("andxoffset", "\xfa\x00"),
            ("maxbuff", "\x04\x11"),
            ("maxmpx", "\x32\x00"),
            ("vcnum", "\x01\x00"),
            ("sessionkey", "\x00\x00\x00\x00"),
            ("securitybloblength", "\x59\x00"),
            ("reserved2", "\x00\x00\x00\x00"),
            ("capabilities", "\xd4\x00\x00\xa0"),
            ("bcc1", "\xbf\x00"),
            ("ApplicationHeaderTag", "\xa1"),
            ("ApplicationHeaderLen", "\x57"),
            ("AsnSecMechType", "\x30"),
            ("AsnSecMechLen", "\x55"),
            ("ChoosedTag", "\xa2"),
            ("ChoosedTagLen", "\x53"),
            ("ChoosedTag1", "\x04"),
            ("ChoosedTag1StrLen", "\x51"),
            ("NLMPAuthMsgSignature", "\x4e\x54\x4c\x4d\x53\x53\x50\x00"),
            ("NLMPAuthMsgMessageType", "\x03\x00\x00\x00"),
            ("NLMPAuthMsgLMChallengeLen", "\x01\x00"),
            ("NLMPAuthMsgLMChallengeMaxLen", "\x01\x00"),
            ("NLMPAuthMsgLMChallengeBuffOffset", "\x50\x00\x00\x00"),
            ("NLMPAuthMsgNtChallengeResponseLen", "\x00\x00"),
            ("NLMPAuthMsgNtChallengeResponseMaxLen", "\x00\x00"),
            ("NLMPAuthMsgNtChallengeResponseBuffOffset", "\x51\x00\x00\x00"),
            ("NLMPAuthMsgNtDomainNameLen", "\x00\x00"),
            ("NLMPAuthMsgNtDomainNameMaxLen", "\x00\x00"),
            ("NLMPAuthMsgNtDomainNameBuffOffset", "\x48\x00\x00\x00"),
            ("NLMPAuthMsgNtUserNameLen", "\x00\x00"),
            ("NLMPAuthMsgNtUserNameMaxLen", "\x00\x00"),
            ("NLMPAuthMsgNtUserNameBuffOffset", "\x48\x00\x00\x00"),
            ("NLMPAuthMsgNtWorkstationLen", "\x08\x00"),
            ("NLMPAuthMsgNtWorkstationMaxLen", "\x08\x00"),
            ("NLMPAuthMsgNtWorkstationBuffOffset", "\x48\x00\x00\x00"),
            ("NLMPAuthMsgRandomSessionKeyMessageLen", "\x00\x00"),
            ("NLMPAuthMsgRandomSessionKeyMessageMaxLen", "\x00\x00"),
            ("NLMPAuthMsgRandomSessionKeyMessageBuffOffset", "\x55\x00\x00\x00"),
            ("NLMPAuthMsgNtNegotiateFlags", "\x05\x8a\x88\xa2"),
            ("NegTokenInitSeqMechMessageVersionHigh", "\x05"),
            ("NegTokenInitSeqMechMessageVersionLow", "\x01"),
            ("NegTokenInitSeqMechMessageVersionBuilt", "\x28\x0a"),
            ("NegTokenInitSeqMechMessageVersionReserved", "\x00\x00\x00"),
            ("NegTokenInitSeqMechMessageVersionNTLMType", "\x0f"),
            ("NLMPAuthMsgNtDomainName", ""),
            ("NLMPAuthMsgNtUserName", ""),
            ("NLMPAuthMsgNtWorkstationName", ""),
            ("NLMPAuthLMChallengeStr", "\x00"),
            ("NLMPAuthMsgNTLMV1ChallengeResponseStruct", ""),
            ("NLMPAuthMsgNTerminator", ""),
            ("nativeOs", "Windows 2002 Service Pack 3 2600"),
            ("nativeOsterminator", "\x00\x00"),
            ("nativelan", "Windows 2002 5.1"),
            ("nativelanterminator", "\x00\x00\x00\x00"),
        ]
    )

    def calculate(self):

        self.fields["NLMPAuthMsgNtUserName"] = (
            self.fields["NLMPAuthMsgNtUserName"].encode("utf-16le").decode("latin-1")
        )
        self.fields["NLMPAuthMsgNtDomainName"] = (
            self.fields["NLMPAuthMsgNtDomainName"].encode("utf-16le").decode("latin-1")
        )
        self.fields["NLMPAuthMsgNtWorkstationName"] = (
            self.fields["NLMPAuthMsgNtWorkstationName"]
            .encode("utf-16le")
            .decode("latin-1")
        )

        self.fields["nativeOs"] = (
            self.fields["nativeOs"].encode("utf-16le").decode("latin-1")
        )
        self.fields["nativelan"] = (
            self.fields["nativelan"].encode("utf-16le").decode("latin-1")
        )

        CompletePacketLen = (
            str(self.fields["wordcount"])
            + str(self.fields["AndXCommand"])
            + str(self.fields["reserved"])
            + str(self.fields["andxoffset"])
            + str(self.fields["maxbuff"])
            + str(self.fields["maxmpx"])
            + str(self.fields["vcnum"])
            + str(self.fields["sessionkey"])
            + str(self.fields["securitybloblength"])
            + str(self.fields["reserved2"])
            + str(self.fields["capabilities"])
            + str(self.fields["bcc1"])
            + str(self.fields["ApplicationHeaderTag"])
            + str(self.fields["ApplicationHeaderLen"])
            + str(self.fields["AsnSecMechType"])
            + str(self.fields["AsnSecMechLen"])
            + str(self.fields["ChoosedTag"])
            + str(self.fields["ChoosedTagLen"])
            + str(self.fields["ChoosedTag1"])
            + str(self.fields["ChoosedTag1StrLen"])
            + str(self.fields["NLMPAuthMsgSignature"])
            + str(self.fields["NLMPAuthMsgMessageType"])
            + str(self.fields["NLMPAuthMsgLMChallengeLen"])
            + str(self.fields["NLMPAuthMsgLMChallengeMaxLen"])
            + str(self.fields["NLMPAuthMsgLMChallengeBuffOffset"])
            + str(self.fields["NLMPAuthMsgNtChallengeResponseLen"])
            + str(self.fields["NLMPAuthMsgNtChallengeResponseMaxLen"])
            + str(self.fields["NLMPAuthMsgNtChallengeResponseBuffOffset"])
            + str(self.fields["NLMPAuthMsgNtDomainNameLen"])
            + str(self.fields["NLMPAuthMsgNtDomainNameMaxLen"])
            + str(self.fields["NLMPAuthMsgNtDomainNameBuffOffset"])
            + str(self.fields["NLMPAuthMsgNtUserNameLen"])
            + str(self.fields["NLMPAuthMsgNtUserNameMaxLen"])
            + str(self.fields["NLMPAuthMsgNtUserNameBuffOffset"])
            + str(self.fields["NLMPAuthMsgNtWorkstationLen"])
            + str(self.fields["NLMPAuthMsgNtWorkstationMaxLen"])
            + str(self.fields["NLMPAuthMsgNtWorkstationBuffOffset"])
            + str(self.fields["NLMPAuthMsgRandomSessionKeyMessageLen"])
            + str(self.fields["NLMPAuthMsgRandomSessionKeyMessageMaxLen"])
            + str(self.fields["NLMPAuthMsgRandomSessionKeyMessageBuffOffset"])
            + str(self.fields["NLMPAuthMsgNtNegotiateFlags"])
            + str(self.fields["NegTokenInitSeqMechMessageVersionHigh"])
            + str(self.fields["NegTokenInitSeqMechMessageVersionLow"])
            + str(self.fields["NegTokenInitSeqMechMessageVersionBuilt"])
            + str(self.fields["NegTokenInitSeqMechMessageVersionReserved"])
            + str(self.fields["NegTokenInitSeqMechMessageVersionNTLMType"])
            + str(self.fields["NLMPAuthMsgNtDomainName"])
            + str(self.fields["NLMPAuthMsgNtUserName"])
            + str(self.fields["NLMPAuthMsgNtWorkstationName"])
            + str(self.fields["NLMPAuthLMChallengeStr"])
            + str(self.fields["NLMPAuthMsgNTLMV1ChallengeResponseStruct"])
            + str(self.fields["NLMPAuthMsgNTerminator"])
            + str(self.fields["nativeOs"])
            + str(self.fields["nativeOsterminator"])
            + str(self.fields["nativelan"])
            + str(self.fields["nativelanterminator"])
        )

        SecurityBlobLen = (
            str(self.fields["ApplicationHeaderTag"])
            + str(self.fields["ApplicationHeaderLen"])
            + str(self.fields["AsnSecMechType"])
            + str(self.fields["AsnSecMechLen"])
            + str(self.fields["ChoosedTag"])
            + str(self.fields["ChoosedTagLen"])
            + str(self.fields["ChoosedTag1"])
            + str(self.fields["ChoosedTag1StrLen"])
            + str(self.fields["NLMPAuthMsgSignature"])
            + str(self.fields["NLMPAuthMsgMessageType"])
            + str(self.fields["NLMPAuthMsgLMChallengeLen"])
            + str(self.fields["NLMPAuthMsgLMChallengeMaxLen"])
            + str(self.fields["NLMPAuthMsgLMChallengeBuffOffset"])
            + str(self.fields["NLMPAuthMsgNtChallengeResponseLen"])
            + str(self.fields["NLMPAuthMsgNtChallengeResponseMaxLen"])
            + str(self.fields["NLMPAuthMsgNtChallengeResponseBuffOffset"])
            + str(self.fields["NLMPAuthMsgNtDomainNameLen"])
            + str(self.fields["NLMPAuthMsgNtDomainNameMaxLen"])
            + str(self.fields["NLMPAuthMsgNtDomainNameBuffOffset"])
            + str(self.fields["NLMPAuthMsgNtUserNameLen"])
            + str(self.fields["NLMPAuthMsgNtUserNameMaxLen"])
            + str(self.fields["NLMPAuthMsgNtUserNameBuffOffset"])
            + str(self.fields["NLMPAuthMsgNtWorkstationLen"])
            + str(self.fields["NLMPAuthMsgNtWorkstationMaxLen"])
            + str(self.fields["NLMPAuthMsgNtWorkstationBuffOffset"])
            + str(self.fields["NLMPAuthMsgRandomSessionKeyMessageLen"])
            + str(self.fields["NLMPAuthMsgRandomSessionKeyMessageMaxLen"])
            + str(self.fields["NLMPAuthMsgRandomSessionKeyMessageBuffOffset"])
            + str(self.fields["NLMPAuthMsgNtNegotiateFlags"])
            + str(self.fields["NegTokenInitSeqMechMessageVersionHigh"])
            + str(self.fields["NegTokenInitSeqMechMessageVersionLow"])
            + str(self.fields["NegTokenInitSeqMechMessageVersionBuilt"])
            + str(self.fields["NegTokenInitSeqMechMessageVersionReserved"])
            + str(self.fields["NegTokenInitSeqMechMessageVersionNTLMType"])
            + str(self.fields["NLMPAuthMsgNtDomainName"])
            + str(self.fields["NLMPAuthMsgNtUserName"])
            + str(self.fields["NLMPAuthMsgNtWorkstationName"])
            + str(self.fields["NLMPAuthLMChallengeStr"])
            + str(self.fields["NLMPAuthMsgNTLMV1ChallengeResponseStruct"])
        )

        SecurityBlobLen2 = (
            str(self.fields["ApplicationHeaderTag"])
            + str(self.fields["ApplicationHeaderLen"])
            + str(self.fields["AsnSecMechType"])
            + str(self.fields["AsnSecMechLen"])
            + str(self.fields["ChoosedTag"])
            + str(self.fields["ChoosedTagLen"])
            + str(self.fields["ChoosedTag1"])
            + str(self.fields["ChoosedTag1StrLen"])
            + str(self.fields["NLMPAuthMsgSignature"])
            + str(self.fields["NLMPAuthMsgMessageType"])
            + str(self.fields["NLMPAuthMsgLMChallengeLen"])
            + str(self.fields["NLMPAuthMsgLMChallengeMaxLen"])
            + str(self.fields["NLMPAuthMsgLMChallengeBuffOffset"])
            + str(self.fields["NLMPAuthMsgNtChallengeResponseLen"])
            + str(self.fields["NLMPAuthMsgNtChallengeResponseMaxLen"])
            + str(self.fields["NLMPAuthMsgNtChallengeResponseBuffOffset"])
            + str(self.fields["NLMPAuthMsgNtDomainNameLen"])
            + str(self.fields["NLMPAuthMsgNtDomainNameMaxLen"])
            + str(self.fields["NLMPAuthMsgNtDomainNameBuffOffset"])
            + str(self.fields["NLMPAuthMsgNtUserNameLen"])
            + str(self.fields["NLMPAuthMsgNtUserNameMaxLen"])
            + str(self.fields["NLMPAuthMsgNtUserNameBuffOffset"])
            + str(self.fields["NLMPAuthMsgNtWorkstationLen"])
            + str(self.fields["NLMPAuthMsgNtWorkstationMaxLen"])
            + str(self.fields["NLMPAuthMsgNtWorkstationBuffOffset"])
            + str(self.fields["NLMPAuthMsgRandomSessionKeyMessageLen"])
            + str(self.fields["NLMPAuthMsgRandomSessionKeyMessageMaxLen"])
            + str(self.fields["NLMPAuthMsgRandomSessionKeyMessageBuffOffset"])
            + str(self.fields["NLMPAuthMsgNtNegotiateFlags"])
            + str(self.fields["NegTokenInitSeqMechMessageVersionHigh"])
            + str(self.fields["NegTokenInitSeqMechMessageVersionLow"])
            + str(self.fields["NegTokenInitSeqMechMessageVersionBuilt"])
            + str(self.fields["NegTokenInitSeqMechMessageVersionReserved"])
            + str(self.fields["NegTokenInitSeqMechMessageVersionNTLMType"])
            + str(self.fields["NLMPAuthMsgNtDomainName"])
            + str(self.fields["NLMPAuthMsgNtUserName"])
            + str(self.fields["NLMPAuthMsgNtWorkstationName"])
            + str(self.fields["NLMPAuthLMChallengeStr"])
            + str(self.fields["NLMPAuthMsgNTLMV1ChallengeResponseStruct"])
        )

        SecurityBlobBCC = (
            str(self.fields["ApplicationHeaderTag"])
            + str(self.fields["ApplicationHeaderLen"])
            + str(self.fields["AsnSecMechType"])
            + str(self.fields["AsnSecMechLen"])
            + str(self.fields["ChoosedTag"])
            + str(self.fields["ChoosedTagLen"])
            + str(self.fields["ChoosedTag1"])
            + str(self.fields["ChoosedTag1StrLen"])
            + str(self.fields["NLMPAuthMsgSignature"])
            + str(self.fields["NLMPAuthMsgMessageType"])
            + str(self.fields["NLMPAuthMsgLMChallengeLen"])
            + str(self.fields["NLMPAuthMsgLMChallengeMaxLen"])
            + str(self.fields["NLMPAuthMsgLMChallengeBuffOffset"])
            + str(self.fields["NLMPAuthMsgNtChallengeResponseLen"])
            + str(self.fields["NLMPAuthMsgNtChallengeResponseMaxLen"])
            + str(self.fields["NLMPAuthMsgNtChallengeResponseBuffOffset"])
            + str(self.fields["NLMPAuthMsgNtDomainNameLen"])
            + str(self.fields["NLMPAuthMsgNtDomainNameMaxLen"])
            + str(self.fields["NLMPAuthMsgNtDomainNameBuffOffset"])
            + str(self.fields["NLMPAuthMsgNtUserNameLen"])
            + str(self.fields["NLMPAuthMsgNtUserNameMaxLen"])
            + str(self.fields["NLMPAuthMsgNtUserNameBuffOffset"])
            + str(self.fields["NLMPAuthMsgNtWorkstationLen"])
            + str(self.fields["NLMPAuthMsgNtWorkstationMaxLen"])
            + str(self.fields["NLMPAuthMsgNtWorkstationBuffOffset"])
            + str(self.fields["NLMPAuthMsgRandomSessionKeyMessageLen"])
            + str(self.fields["NLMPAuthMsgRandomSessionKeyMessageMaxLen"])
            + str(self.fields["NLMPAuthMsgRandomSessionKeyMessageBuffOffset"])
            + str(self.fields["NLMPAuthMsgNtNegotiateFlags"])
            + str(self.fields["NegTokenInitSeqMechMessageVersionHigh"])
            + str(self.fields["NegTokenInitSeqMechMessageVersionLow"])
            + str(self.fields["NegTokenInitSeqMechMessageVersionBuilt"])
            + str(self.fields["NegTokenInitSeqMechMessageVersionReserved"])
            + str(self.fields["NegTokenInitSeqMechMessageVersionNTLMType"])
            + str(self.fields["NLMPAuthMsgNtDomainName"])
            + str(self.fields["NLMPAuthMsgNtUserName"])
            + str(self.fields["NLMPAuthMsgNtWorkstationName"])
            + str(self.fields["NLMPAuthLMChallengeStr"])
            + str(self.fields["NLMPAuthMsgNTLMV1ChallengeResponseStruct"])
            + str(self.fields["NLMPAuthMsgNTerminator"])
            + str(self.fields["nativeOs"])
            + str(self.fields["nativeOsterminator"])
            + str(self.fields["nativelan"])
            + str(self.fields["nativelanterminator"])
        )

        CalculateUserOffset = (
            str(self.fields["NLMPAuthMsgSignature"])
            + str(self.fields["NLMPAuthMsgMessageType"])
            + str(self.fields["NLMPAuthMsgLMChallengeLen"])
            + str(self.fields["NLMPAuthMsgLMChallengeMaxLen"])
            + str(self.fields["NLMPAuthMsgLMChallengeBuffOffset"])
            + str(self.fields["NLMPAuthMsgNtChallengeResponseLen"])
            + str(self.fields["NLMPAuthMsgNtChallengeResponseMaxLen"])
            + str(self.fields["NLMPAuthMsgNtChallengeResponseBuffOffset"])
            + str(self.fields["NLMPAuthMsgNtDomainNameLen"])
            + str(self.fields["NLMPAuthMsgNtDomainNameMaxLen"])
            + str(self.fields["NLMPAuthMsgNtDomainNameBuffOffset"])
            + str(self.fields["NLMPAuthMsgNtUserNameLen"])
            + str(self.fields["NLMPAuthMsgNtUserNameMaxLen"])
            + str(self.fields["NLMPAuthMsgNtUserNameBuffOffset"])
            + str(self.fields["NLMPAuthMsgNtWorkstationLen"])
            + str(self.fields["NLMPAuthMsgNtWorkstationMaxLen"])
            + str(self.fields["NLMPAuthMsgNtWorkstationBuffOffset"])
            + str(self.fields["NLMPAuthMsgRandomSessionKeyMessageLen"])
            + str(self.fields["NLMPAuthMsgRandomSessionKeyMessageMaxLen"])
            + str(self.fields["NLMPAuthMsgRandomSessionKeyMessageBuffOffset"])
            + str(self.fields["NLMPAuthMsgNtNegotiateFlags"])
            + str(self.fields["NegTokenInitSeqMechMessageVersionHigh"])
            + str(self.fields["NegTokenInitSeqMechMessageVersionLow"])
            + str(self.fields["NegTokenInitSeqMechMessageVersionBuilt"])
            + str(self.fields["NegTokenInitSeqMechMessageVersionReserved"])
            + str(self.fields["NegTokenInitSeqMechMessageVersionNTLMType"])
            + str(self.fields["NLMPAuthMsgNtDomainName"])
        )

        CalculateDomainOffset = (
            str(self.fields["NLMPAuthMsgSignature"])
            + str(self.fields["NLMPAuthMsgMessageType"])
            + str(self.fields["NLMPAuthMsgLMChallengeLen"])
            + str(self.fields["NLMPAuthMsgLMChallengeMaxLen"])
            + str(self.fields["NLMPAuthMsgLMChallengeBuffOffset"])
            + str(self.fields["NLMPAuthMsgNtChallengeResponseLen"])
            + str(self.fields["NLMPAuthMsgNtChallengeResponseMaxLen"])
            + str(self.fields["NLMPAuthMsgNtChallengeResponseBuffOffset"])
            + str(self.fields["NLMPAuthMsgNtDomainNameLen"])
            + str(self.fields["NLMPAuthMsgNtDomainNameMaxLen"])
            + str(self.fields["NLMPAuthMsgNtDomainNameBuffOffset"])
            + str(self.fields["NLMPAuthMsgNtUserNameLen"])
            + str(self.fields["NLMPAuthMsgNtUserNameMaxLen"])
            + str(self.fields["NLMPAuthMsgNtUserNameBuffOffset"])
            + str(self.fields["NLMPAuthMsgNtWorkstationLen"])
            + str(self.fields["NLMPAuthMsgNtWorkstationMaxLen"])
            + str(self.fields["NLMPAuthMsgNtWorkstationBuffOffset"])
            + str(self.fields["NLMPAuthMsgRandomSessionKeyMessageLen"])
            + str(self.fields["NLMPAuthMsgRandomSessionKeyMessageMaxLen"])
            + str(self.fields["NLMPAuthMsgRandomSessionKeyMessageBuffOffset"])
            + str(self.fields["NLMPAuthMsgNtNegotiateFlags"])
            + str(self.fields["NegTokenInitSeqMechMessageVersionHigh"])
            + str(self.fields["NegTokenInitSeqMechMessageVersionLow"])
            + str(self.fields["NegTokenInitSeqMechMessageVersionBuilt"])
            + str(self.fields["NegTokenInitSeqMechMessageVersionReserved"])
            + str(self.fields["NegTokenInitSeqMechMessageVersionNTLMType"])
        )

        CalculateWorkstationOffset = (
            str(self.fields["NLMPAuthMsgSignature"])
            + str(self.fields["NLMPAuthMsgMessageType"])
            + str(self.fields["NLMPAuthMsgLMChallengeLen"])
            + str(self.fields["NLMPAuthMsgLMChallengeMaxLen"])
            + str(self.fields["NLMPAuthMsgLMChallengeBuffOffset"])
            + str(self.fields["NLMPAuthMsgNtChallengeResponseLen"])
            + str(self.fields["NLMPAuthMsgNtChallengeResponseMaxLen"])
            + str(self.fields["NLMPAuthMsgNtChallengeResponseBuffOffset"])
            + str(self.fields["NLMPAuthMsgNtDomainNameLen"])
            + str(self.fields["NLMPAuthMsgNtDomainNameMaxLen"])
            + str(self.fields["NLMPAuthMsgNtDomainNameBuffOffset"])
            + str(self.fields["NLMPAuthMsgNtUserNameLen"])
            + str(self.fields["NLMPAuthMsgNtUserNameMaxLen"])
            + str(self.fields["NLMPAuthMsgNtUserNameBuffOffset"])
            + str(self.fields["NLMPAuthMsgNtWorkstationLen"])
            + str(self.fields["NLMPAuthMsgNtWorkstationMaxLen"])
            + str(self.fields["NLMPAuthMsgNtWorkstationBuffOffset"])
            + str(self.fields["NLMPAuthMsgRandomSessionKeyMessageLen"])
            + str(self.fields["NLMPAuthMsgRandomSessionKeyMessageMaxLen"])
            + str(self.fields["NLMPAuthMsgRandomSessionKeyMessageBuffOffset"])
            + str(self.fields["NLMPAuthMsgNtNegotiateFlags"])
            + str(self.fields["NegTokenInitSeqMechMessageVersionHigh"])
            + str(self.fields["NegTokenInitSeqMechMessageVersionLow"])
            + str(self.fields["NegTokenInitSeqMechMessageVersionBuilt"])
            + str(self.fields["NegTokenInitSeqMechMessageVersionReserved"])
            + str(self.fields["NegTokenInitSeqMechMessageVersionNTLMType"])
            + str(self.fields["NLMPAuthMsgNtDomainName"])
            + str(self.fields["NLMPAuthMsgNtUserName"])
        )

        CalculateLMChallengeOffset = (
            str(self.fields["NLMPAuthMsgSignature"])
            + str(self.fields["NLMPAuthMsgMessageType"])
            + str(self.fields["NLMPAuthMsgLMChallengeLen"])
            + str(self.fields["NLMPAuthMsgLMChallengeMaxLen"])
            + str(self.fields["NLMPAuthMsgLMChallengeBuffOffset"])
            + str(self.fields["NLMPAuthMsgNtChallengeResponseLen"])
            + str(self.fields["NLMPAuthMsgNtChallengeResponseMaxLen"])
            + str(self.fields["NLMPAuthMsgNtChallengeResponseBuffOffset"])
            + str(self.fields["NLMPAuthMsgNtDomainNameLen"])
            + str(self.fields["NLMPAuthMsgNtDomainNameMaxLen"])
            + str(self.fields["NLMPAuthMsgNtDomainNameBuffOffset"])
            + str(self.fields["NLMPAuthMsgNtUserNameLen"])
            + str(self.fields["NLMPAuthMsgNtUserNameMaxLen"])
            + str(self.fields["NLMPAuthMsgNtUserNameBuffOffset"])
            + str(self.fields["NLMPAuthMsgNtWorkstationLen"])
            + str(self.fields["NLMPAuthMsgNtWorkstationMaxLen"])
            + str(self.fields["NLMPAuthMsgNtWorkstationBuffOffset"])
            + str(self.fields["NLMPAuthMsgRandomSessionKeyMessageLen"])
            + str(self.fields["NLMPAuthMsgRandomSessionKeyMessageMaxLen"])
            + str(self.fields["NLMPAuthMsgRandomSessionKeyMessageBuffOffset"])
            + str(self.fields["NLMPAuthMsgNtNegotiateFlags"])
            + str(self.fields["NegTokenInitSeqMechMessageVersionHigh"])
            + str(self.fields["NegTokenInitSeqMechMessageVersionLow"])
            + str(self.fields["NegTokenInitSeqMechMessageVersionBuilt"])
            + str(self.fields["NegTokenInitSeqMechMessageVersionReserved"])
            + str(self.fields["NegTokenInitSeqMechMessageVersionNTLMType"])
            + str(self.fields["NLMPAuthMsgNtDomainName"])
            + str(self.fields["NLMPAuthMsgNtUserName"])
            + str(self.fields["NLMPAuthMsgNtWorkstationName"])
        )

        CalculateNTChallengeOffset = (
            str(self.fields["NLMPAuthMsgSignature"])
            + str(self.fields["NLMPAuthMsgMessageType"])
            + str(self.fields["NLMPAuthMsgLMChallengeLen"])
            + str(self.fields["NLMPAuthMsgLMChallengeMaxLen"])
            + str(self.fields["NLMPAuthMsgLMChallengeBuffOffset"])
            + str(self.fields["NLMPAuthMsgNtChallengeResponseLen"])
            + str(self.fields["NLMPAuthMsgNtChallengeResponseMaxLen"])
            + str(self.fields["NLMPAuthMsgNtChallengeResponseBuffOffset"])
            + str(self.fields["NLMPAuthMsgNtDomainNameLen"])
            + str(self.fields["NLMPAuthMsgNtDomainNameMaxLen"])
            + str(self.fields["NLMPAuthMsgNtDomainNameBuffOffset"])
            + str(self.fields["NLMPAuthMsgNtUserNameLen"])
            + str(self.fields["NLMPAuthMsgNtUserNameMaxLen"])
            + str(self.fields["NLMPAuthMsgNtUserNameBuffOffset"])
            + str(self.fields["NLMPAuthMsgNtWorkstationLen"])
            + str(self.fields["NLMPAuthMsgNtWorkstationMaxLen"])
            + str(self.fields["NLMPAuthMsgNtWorkstationBuffOffset"])
            + str(self.fields["NLMPAuthMsgRandomSessionKeyMessageLen"])
            + str(self.fields["NLMPAuthMsgRandomSessionKeyMessageMaxLen"])
            + str(self.fields["NLMPAuthMsgRandomSessionKeyMessageBuffOffset"])
            + str(self.fields["NLMPAuthMsgNtNegotiateFlags"])
            + str(self.fields["NegTokenInitSeqMechMessageVersionHigh"])
            + str(self.fields["NegTokenInitSeqMechMessageVersionLow"])
            + str(self.fields["NegTokenInitSeqMechMessageVersionBuilt"])
            + str(self.fields["NegTokenInitSeqMechMessageVersionReserved"])
            + str(self.fields["NegTokenInitSeqMechMessageVersionNTLMType"])
            + str(self.fields["NLMPAuthMsgNtDomainName"])
            + str(self.fields["NLMPAuthMsgNtUserName"])
            + str(self.fields["NLMPAuthMsgNtWorkstationName"])
            + str(self.fields["NLMPAuthLMChallengeStr"])
        )

        ## Packet len
        self.fields["andxoffset"] = StructWithLenPython2or3(
            "<i", len(CompletePacketLen) + 32
        )[:2]
        ##Buff Len
        self.fields["securitybloblength"] = StructWithLenPython2or3(
            "<i", len(SecurityBlobLen)
        )[:2]
        ##Complete Buff Len
        self.fields["bcc1"] = StructWithLenPython2or3("<i", len(SecurityBlobBCC))[:2]
        ## Guest len check
        self.fields["ApplicationHeaderLen"] = StructWithLenPython2or3(
            "<i", len(SecurityBlobLen) - 2
        )[:1]
        self.fields["AsnSecMechLen"] = StructWithLenPython2or3(
            "<i", len(SecurityBlobLen) - 4
        )[:1]
        self.fields["ChoosedTagLen"] = StructWithLenPython2or3(
            "<i", len(SecurityBlobLen) - 6
        )[:1]
        self.fields["ChoosedTag1StrLen"] = StructWithLenPython2or3(
            "<i", len(SecurityBlobLen) - 8
        )[:1]

        ##### Username Offset Calculation..######
        self.fields["NLMPAuthMsgNtUserNameBuffOffset"] = StructWithLenPython2or3(
            "<i", len(CalculateUserOffset)
        )
        self.fields["NLMPAuthMsgNtUserNameLen"] = StructWithLenPython2or3(
            "<i", len(str(self.fields["NLMPAuthMsgNtUserName"]))
        )[:2]
        self.fields["NLMPAuthMsgNtUserNameMaxLen"] = StructWithLenPython2or3(
            "<i", len(str(self.fields["NLMPAuthMsgNtUserName"]))
        )[:2]
        ##### Domain Offset Calculation..######
        self.fields["NLMPAuthMsgNtDomainNameBuffOffset"] = StructWithLenPython2or3(
            "<i", len(CalculateDomainOffset)
        )
        self.fields["NLMPAuthMsgNtDomainNameLen"] = StructWithLenPython2or3(
            "<i", len(str(self.fields["NLMPAuthMsgNtDomainName"]))
        )[:2]
        self.fields["NLMPAuthMsgNtDomainNameMaxLen"] = StructWithLenPython2or3(
            "<i", len(str(self.fields["NLMPAuthMsgNtDomainName"]))
        )[:2]
        ##### Workstation Offset Calculation..######
        self.fields["NLMPAuthMsgNtWorkstationBuffOffset"] = StructWithLenPython2or3(
            "<i", len(CalculateWorkstationOffset)
        )
        self.fields["NLMPAuthMsgNtWorkstationLen"] = StructWithLenPython2or3(
            "<i", len(str(self.fields["NLMPAuthMsgNtWorkstationName"]))
        )[:2]
        self.fields["NLMPAuthMsgNtWorkstationMaxLen"] = StructWithLenPython2or3(
            "<i", len(str(self.fields["NLMPAuthMsgNtWorkstationName"]))
        )[:2]

        ##### NT Challenge Offset Calculation..######
        self.fields["NLMPAuthMsgNtChallengeResponseBuffOffset"] = (
            StructWithLenPython2or3("<i", len(CalculateNTChallengeOffset))
        )
        self.fields["NLMPAuthMsgNtChallengeResponseLen"] = StructWithLenPython2or3(
            "<i", len(str(self.fields["NLMPAuthMsgNTLMV1ChallengeResponseStruct"]))
        )[:2]
        self.fields["NLMPAuthMsgNtChallengeResponseMaxLen"] = StructWithLenPython2or3(
            "<i", len(str(self.fields["NLMPAuthMsgNTLMV1ChallengeResponseStruct"]))
        )[:2]
        ##### LM Challenge Offset Calculation..######
        self.fields["NLMPAuthMsgLMChallengeBuffOffset"] = StructWithLenPython2or3(
            "<i", len(CalculateLMChallengeOffset)
        )
        self.fields["NLMPAuthMsgLMChallengeLen"] = StructWithLenPython2or3(
            "<i", len(str(self.fields["NLMPAuthLMChallengeStr"]))
        )[:2]
        self.fields["NLMPAuthMsgLMChallengeMaxLen"] = StructWithLenPython2or3(
            "<i", len(str(self.fields["NLMPAuthLMChallengeStr"]))
        )[:2]


######################################################################################################


class SMBTreeConnectData(Packet):
    fields = OrderedDict(
        [
            ("Wordcount", "\x04"),
            ("AndXCommand", "\xff"),
            ("Reserved", "\x00"),
            ("Andxoffset", "\x5a\x00"),
            ("Flags", "\x08\x00"),
            ("PasswdLen", "\x01\x00"),
            ("Bcc", "\x2f\x00"),
            ("Passwd", "\x00"),
            ("Path", "IPC$"),
            ("PathTerminator", "\x00\x00"),
            ("Service", "?????"),
            ("Terminator", "\x00"),
        ]
    )

    def calculate(self):

        ##Convert Path to Unicode first before any Len calc.
        self.fields["Path"] = self.fields["Path"].encode("utf-16le").decode("latin-1")

        ##Passwd Len
        self.fields["PasswdLen"] = StructWithLenPython2or3(
            "<i", len(str(self.fields["Passwd"]))
        )[:2]

        ##Packet len
        CompletePacket = (
            str(self.fields["Wordcount"])
            + str(self.fields["AndXCommand"])
            + str(self.fields["Reserved"])
            + str(self.fields["Andxoffset"])
            + str(self.fields["Flags"])
            + str(self.fields["PasswdLen"])
            + str(self.fields["Bcc"])
            + str(self.fields["Passwd"])
            + str(self.fields["Path"])
            + str(self.fields["PathTerminator"])
            + str(self.fields["Service"])
            + str(self.fields["Terminator"])
        )

        self.fields["Andxoffset"] = StructWithLenPython2or3(
            "<i", len(CompletePacket) + 32
        )[:2]

        ##Bcc Buff Len
        BccComplete = (
            str(self.fields["Passwd"])
            + str(self.fields["Path"])
            + str(self.fields["PathTerminator"])
            + str(self.fields["Service"])
            + str(self.fields["Terminator"])
        )
        self.fields["Bcc"] = StructWithLenPython2or3("<i", len(BccComplete))[:2]


class SMBTransRAPData(Packet):
    fields = OrderedDict(
        [
            ("Wordcount", "\x10"),
            ("TotalParamCount", "\x00\x00"),
            ("TotalDataCount", "\x00\x00"),
            ("MaxParamCount", "\xff\xff"),
            ("MaxDataCount", "\xff\xff"),
            ("MaxSetupCount", "\x00"),
            ("Reserved", "\x00\x00"),
            ("Flags", "\x00"),
            ("Timeout", "\x00\x00\x00\x00"),
            ("Reserved1", "\x00\x00"),
            ("ParamCount", "\x00\x00"),
            ("ParamOffset", "\x5c\x00"),
            ("DataCount", "\x00\x00"),
            ("DataOffset", "\x54\x00"),
            ("SetupCount", "\x02"),
            ("Reserved2", "\x00"),
            ("PeekNamedPipe", "\x23\x00"),
            ("FID", "\x00\x00"),
            ("Bcc", "\x47\x00"),
            ("Terminator", "\x00"),
            ("PipeName", "\\PIPE\\"),
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
            + str(self.fields["PeekNamedPipe"])
            + str(self.fields["FID"])
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


######################FindSMBTime.py##########################
class SMBHeaderReq(Packet):
    fields = OrderedDict(
        [
            ("Proto", "\xff\x53\x4d\x42"),
            ("Cmd", "\x72"),
            ("Error-Code", "\x00\x00\x00\x00"),
            ("Flag1", "\x10"),
            ("Flag2", "\x00\x00"),
            ("Pidhigh", "\x00\x00"),
            ("Signature", "\x00\x00\x00\x00\x00\x00\x00\x00"),
            ("Reserved", "\x00\x00"),
            ("TID", "\x00\x00"),
            ("PID", "\xff\xfe"),
            ("UID", "\x00\x00"),
            ("MID", "\x00\x00"),
        ]
    )


class SMB2NegoReq(Packet):
    fields = OrderedDict([("Wordcount", "\x00"), ("Bcc", "\x62\x00"), ("Data", "")])

    def calculate(self):
        self.fields["Bcc"] = StructWithLenPython2or3(
            "<H", len(str(self.fields["Data"]))
        )


class SMB2NegoDataReq(Packet):
    fields = OrderedDict(
        [
            ("StrType", "\x02"),
            ("dialect", "NT LM 0.12\x00"),
            ("StrType1", "\x02"),
            ("dialect1", "SMB 2.002\x00"),
            ("StrType2", "\x02"),
            ("dialect2", "SMB 2.???\x00"),
        ]
    )


##################################################################
# SMB2 Finger                                                    #
##################################################################


class SMB2NegoData(Packet):
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
            ("separator7", "\x02"),
            ("dialect7", "\x53\x4d\x42\x20\x32\x2e\x30\x30\x32\x00"),
            ("separator8", "\x02"),
            ("dialect8", "\x53\x4d\x42\x20\x32\x2e\x3f\x3f\x3f\x00"),
        ]
    )


class SMBv2Head(Packet):
    fields = OrderedDict(
        [
            ("Server", "\xfe\x53\x4d\x42"),
            ("HeadLen", "\x40\x00"),
            ("CreditCharge", "\x00\x00"),
            ("NTStatus", "\x00\x00\x00\x00"),
            ("SMBv2Command", "\x00\x00"),
            ("CreditRequested", "\x00\x00"),
            ("Flags", "\x00\x00\x00\x00"),
            ("ChainOffset", "\x00\x00\x00\x00"),
            ("CommandSequence", "\x01\x00\x00\x00\x00\x00\x00\x00"),
            ("ProcessID", "\xff\xfe\x00\x00"),
            ("TreeID", "\x00\x00\x00\x00"),
            ("SessionID", "\x00\x00\x00\x00\x00\x00\x00\x00"),
            (
                "Signature",
                "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
            ),
        ]
    )

    def calculate(self):
        data1 = (
            str(self.fields["Server"])
            + str(self.fields["HeadLen"])
            + str(self.fields["CreditCharge"])
            + str(self.fields["NTStatus"])
            + str(self.fields["SMBv2Command"])
            + str(self.fields["CreditRequested"])
            + str(self.fields["Flags"])
            + str(self.fields["ChainOffset"])
            + str(self.fields["CommandSequence"])
            + str(self.fields["ProcessID"])
            + str(self.fields["TreeID"])
            + str(self.fields["SessionID"])
            + str(self.fields["Signature"])
        )

        self.fields["HeadLen"] = StructWithLenPython2or3("<h", len(data1))


class SMBv2Negotiate(Packet):
    fields = OrderedDict(
        [
            ("Len", "\x24\x00"),
            ("DialectCount", "\x02\x00"),
            ("SecurityMode", "\x01\x00"),
            ("Reserved", "\x00\x00"),
            ("Capabilities", "\x00\x00\x00\x00"),
            ("ClientGUID", urandom(16).decode("latin-1")),
            ("ClientStartTime", "\x00\x00\x00\x00\x00\x00\x00\x00"),
            ("Dialect1", "\x02\x02"),
            ("Dialect2", "\x10\x02"),
        ]
    )

    def calculate(self):
        data1 = (
            str(self.fields["Len"])
            + str(self.fields["DialectCount"])
            + str(self.fields["SecurityMode"])
            + str(self.fields["Reserved"])
            + str(self.fields["Capabilities"])
            + str(self.fields["ClientGUID"])
            + str(self.fields["ClientStartTime"])
        )

        self.fields["Len"] = StructWithLenPython2or3("<h", len(data1))


class SMBv2Session1(Packet):
    fields = OrderedDict(
        [
            ("Len", "\x19\x00"),
            ("VCNumber", "\x00"),
            ("SecurityMode", "\x01"),
            ("Capabilities", "\x01\x00\x00\x00"),
            ("Channel", "\x00\x00\x00\x00"),
            ("SecurityBufferOffset", "\x58\x00"),
            ("SecurityBufferLen", "\x4a\x00"),
            ("PreviousSessionId", "\x00\x00\x00\x00\x00\x00\x00\x00"),
            ("ApplicationHeaderTag", "\x60"),
            ("ApplicationHeaderLen", "\x48"),
            ("AsnSecMechType", "\x06"),
            ("AsnSecMechLen", "\x06"),
            ("AsnSecMechStr", "\x2b\x06\x01\x05\x05\x02"),
            ("ChoosedTag", "\xa0"),
            ("ChoosedTagStrLen", "\x3e"),
            ("NegTokenInitSeqHeadTag", "\x30"),
            ("NegTokenInitSeqHeadLen", "\x3c"),
            ("NegTokenInitSeqHeadTag1", "\xa0"),
            ("NegTokenInitSeqHeadLen1", "\x0e"),
            ("NegTokenInitSeqNLMPTag", "\x30"),
            ("NegTokenInitSeqNLMPLen", "\x0c"),
            ("NegTokenInitSeqNLMPTag1", "\x06"),
            ("NegTokenInitSeqNLMPTag1Len", "\x0a"),
            ("NegTokenInitSeqNLMPTag1Str", "\x2b\x06\x01\x04\x01\x82\x37\x02\x02\x0a"),
            ("NegTokenInitSeqNLMPTag2", "\xa2"),
            ("NegTokenInitSeqNLMPTag2Len", "\xa2"),
            ("NegTokenInitSeqNLMPTag2Octet", "\x04"),
            ("NegTokenInitSeqNLMPTag2OctetLen", "\x28"),
            ("NegTokenInitSeqMechSignature", "\x4e\x54\x4c\x4d\x53\x53\x50\x00"),
            ("NegTokenInitSeqMechMessageType", "\x01\x00\x00\x00"),
            ("NegTokenInitSeqMechMessageFlags", "\x97\x82\x08\xe2"),
            ("NegTokenInitSeqMechMessageDomainNameLen", "\x00\x00"),
            ("NegTokenInitSeqMechMessageDomainNameMaxLen", "\x00\x00"),
            ("NegTokenInitSeqMechMessageDomainNameBuffOffset", "\x00\x00\x00\x00"),
            ("NegTokenInitSeqMechMessageWorkstationNameLen", "\x00\x00"),
            ("NegTokenInitSeqMechMessageWorkstationNameMaxLen", "\x00\x00"),
            ("NegTokenInitSeqMechMessageWorkstationNameBuffOffset", "\x00\x00\x00\x00"),
            ("NegTokenInitSeqMechMessageVersionHigh", "\x06"),
            ("NegTokenInitSeqMechMessageVersionLow", "\x01"),
            ("NegTokenInitSeqMechMessageVersionBuilt", "\xb1\x1d"),
            ("NegTokenInitSeqMechMessageVersionReserved", "\x00\x00\x00"),
            ("NegTokenInitSeqMechMessageVersionNTLMType", "\x0f"),
        ]
    )

    def calculate(self):

        data1 = (
            str(self.fields["Len"])
            + str(self.fields["VCNumber"])
            + str(self.fields["SecurityMode"])
            + str(self.fields["Capabilities"])
            + str(self.fields["Channel"])
            + str(self.fields["SecurityBufferOffset"])
            + str(self.fields["SecurityBufferLen"])
            + str(self.fields["PreviousSessionId"])
        )

        data2 = (
            str(self.fields["ApplicationHeaderTag"])
            + str(self.fields["ApplicationHeaderLen"])
            + str(self.fields["AsnSecMechType"])
            + str(self.fields["AsnSecMechLen"])
            + str(self.fields["AsnSecMechStr"])
            + str(self.fields["ChoosedTag"])
            + str(self.fields["ChoosedTagStrLen"])
            + str(self.fields["NegTokenInitSeqHeadTag"])
            + str(self.fields["NegTokenInitSeqHeadLen"])
            + str(self.fields["NegTokenInitSeqHeadTag1"])
            + str(self.fields["NegTokenInitSeqHeadLen1"])
            + str(self.fields["NegTokenInitSeqNLMPTag"])
            + str(self.fields["NegTokenInitSeqNLMPLen"])
            + str(self.fields["NegTokenInitSeqNLMPTag1"])
            + str(self.fields["NegTokenInitSeqNLMPTag1Len"])
            + str(self.fields["NegTokenInitSeqNLMPTag1Str"])
            + str(self.fields["NegTokenInitSeqNLMPTag2"])
            + str(self.fields["NegTokenInitSeqNLMPTag2Len"])
            + str(self.fields["NegTokenInitSeqNLMPTag2Octet"])
            + str(self.fields["NegTokenInitSeqNLMPTag2OctetLen"])
            + str(self.fields["NegTokenInitSeqMechSignature"])
            + str(self.fields["NegTokenInitSeqMechMessageType"])
            + str(self.fields["NegTokenInitSeqMechMessageFlags"])
            + str(self.fields["NegTokenInitSeqMechMessageDomainNameLen"])
            + str(self.fields["NegTokenInitSeqMechMessageDomainNameMaxLen"])
            + str(self.fields["NegTokenInitSeqMechMessageDomainNameBuffOffset"])
            + str(self.fields["NegTokenInitSeqMechMessageWorkstationNameLen"])
            + str(self.fields["NegTokenInitSeqMechMessageWorkstationNameMaxLen"])
            + str(self.fields["NegTokenInitSeqMechMessageWorkstationNameBuffOffset"])
            + str(self.fields["NegTokenInitSeqMechMessageVersionHigh"])
            + str(self.fields["NegTokenInitSeqMechMessageVersionLow"])
            + str(self.fields["NegTokenInitSeqMechMessageVersionBuilt"])
            + str(self.fields["NegTokenInitSeqMechMessageVersionReserved"])
            + str(self.fields["NegTokenInitSeqMechMessageVersionNTLMType"])
        )

        data3 = (
            str(self.fields["AsnSecMechType"])
            + str(self.fields["AsnSecMechLen"])
            + str(self.fields["AsnSecMechStr"])
            + str(self.fields["ChoosedTag"])
            + str(self.fields["ChoosedTagStrLen"])
            + str(self.fields["NegTokenInitSeqHeadTag"])
            + str(self.fields["NegTokenInitSeqHeadLen"])
            + str(self.fields["NegTokenInitSeqHeadTag1"])
            + str(self.fields["NegTokenInitSeqHeadLen1"])
            + str(self.fields["NegTokenInitSeqNLMPTag"])
            + str(self.fields["NegTokenInitSeqNLMPLen"])
            + str(self.fields["NegTokenInitSeqNLMPTag1"])
            + str(self.fields["NegTokenInitSeqNLMPTag1Len"])
            + str(self.fields["NegTokenInitSeqNLMPTag1Str"])
            + str(self.fields["NegTokenInitSeqNLMPTag2"])
            + str(self.fields["NegTokenInitSeqNLMPTag2Len"])
            + str(self.fields["NegTokenInitSeqNLMPTag2Octet"])
            + str(self.fields["NegTokenInitSeqNLMPTag2OctetLen"])
            + str(self.fields["NegTokenInitSeqMechSignature"])
            + str(self.fields["NegTokenInitSeqMechMessageType"])
            + str(self.fields["NegTokenInitSeqMechMessageFlags"])
            + str(self.fields["NegTokenInitSeqMechMessageDomainNameLen"])
            + str(self.fields["NegTokenInitSeqMechMessageDomainNameMaxLen"])
            + str(self.fields["NegTokenInitSeqMechMessageDomainNameBuffOffset"])
            + str(self.fields["NegTokenInitSeqMechMessageWorkstationNameLen"])
            + str(self.fields["NegTokenInitSeqMechMessageWorkstationNameMaxLen"])
            + str(self.fields["NegTokenInitSeqMechMessageWorkstationNameBuffOffset"])
            + str(self.fields["NegTokenInitSeqMechMessageVersionHigh"])
            + str(self.fields["NegTokenInitSeqMechMessageVersionLow"])
            + str(self.fields["NegTokenInitSeqMechMessageVersionBuilt"])
            + str(self.fields["NegTokenInitSeqMechMessageVersionReserved"])
            + str(self.fields["NegTokenInitSeqMechMessageVersionNTLMType"])
        )

        data4 = (
            str(self.fields["NegTokenInitSeqHeadTag"])
            + str(self.fields["NegTokenInitSeqHeadLen"])
            + str(self.fields["NegTokenInitSeqHeadTag1"])
            + str(self.fields["NegTokenInitSeqHeadLen1"])
            + str(self.fields["NegTokenInitSeqNLMPTag"])
            + str(self.fields["NegTokenInitSeqNLMPLen"])
            + str(self.fields["NegTokenInitSeqNLMPTag1"])
            + str(self.fields["NegTokenInitSeqNLMPTag1Len"])
            + str(self.fields["NegTokenInitSeqNLMPTag1Str"])
            + str(self.fields["NegTokenInitSeqNLMPTag2"])
            + str(self.fields["NegTokenInitSeqNLMPTag2Len"])
            + str(self.fields["NegTokenInitSeqNLMPTag2Octet"])
            + str(self.fields["NegTokenInitSeqNLMPTag2OctetLen"])
            + str(self.fields["NegTokenInitSeqMechSignature"])
            + str(self.fields["NegTokenInitSeqMechMessageType"])
            + str(self.fields["NegTokenInitSeqMechMessageFlags"])
            + str(self.fields["NegTokenInitSeqMechMessageDomainNameLen"])
            + str(self.fields["NegTokenInitSeqMechMessageDomainNameMaxLen"])
            + str(self.fields["NegTokenInitSeqMechMessageDomainNameBuffOffset"])
            + str(self.fields["NegTokenInitSeqMechMessageWorkstationNameLen"])
            + str(self.fields["NegTokenInitSeqMechMessageWorkstationNameMaxLen"])
            + str(self.fields["NegTokenInitSeqMechMessageWorkstationNameBuffOffset"])
            + str(self.fields["NegTokenInitSeqMechMessageVersionHigh"])
            + str(self.fields["NegTokenInitSeqMechMessageVersionLow"])
            + str(self.fields["NegTokenInitSeqMechMessageVersionBuilt"])
            + str(self.fields["NegTokenInitSeqMechMessageVersionReserved"])
            + str(self.fields["NegTokenInitSeqMechMessageVersionNTLMType"])
        )

        data5 = (
            str(self.fields["NegTokenInitSeqHeadTag1"])
            + str(self.fields["NegTokenInitSeqHeadLen1"])
            + str(self.fields["NegTokenInitSeqNLMPTag"])
            + str(self.fields["NegTokenInitSeqNLMPLen"])
            + str(self.fields["NegTokenInitSeqNLMPTag1"])
            + str(self.fields["NegTokenInitSeqNLMPTag1Len"])
            + str(self.fields["NegTokenInitSeqNLMPTag1Str"])
            + str(self.fields["NegTokenInitSeqNLMPTag2"])
            + str(self.fields["NegTokenInitSeqNLMPTag2Len"])
            + str(self.fields["NegTokenInitSeqNLMPTag2Octet"])
            + str(self.fields["NegTokenInitSeqNLMPTag2OctetLen"])
            + str(self.fields["NegTokenInitSeqMechSignature"])
            + str(self.fields["NegTokenInitSeqMechMessageType"])
            + str(self.fields["NegTokenInitSeqMechMessageFlags"])
            + str(self.fields["NegTokenInitSeqMechMessageDomainNameLen"])
            + str(self.fields["NegTokenInitSeqMechMessageDomainNameMaxLen"])
            + str(self.fields["NegTokenInitSeqMechMessageDomainNameBuffOffset"])
            + str(self.fields["NegTokenInitSeqMechMessageWorkstationNameLen"])
            + str(self.fields["NegTokenInitSeqMechMessageWorkstationNameMaxLen"])
            + str(self.fields["NegTokenInitSeqMechMessageWorkstationNameBuffOffset"])
            + str(self.fields["NegTokenInitSeqMechMessageVersionHigh"])
            + str(self.fields["NegTokenInitSeqMechMessageVersionLow"])
            + str(self.fields["NegTokenInitSeqMechMessageVersionBuilt"])
            + str(self.fields["NegTokenInitSeqMechMessageVersionReserved"])
            + str(self.fields["NegTokenInitSeqMechMessageVersionNTLMType"])
        )

        data6 = (
            str(self.fields["NegTokenInitSeqNLMPTag"])
            + str(self.fields["NegTokenInitSeqNLMPLen"])
            + str(self.fields["NegTokenInitSeqNLMPTag1"])
            + str(self.fields["NegTokenInitSeqNLMPTag1Len"])
            + str(self.fields["NegTokenInitSeqNLMPTag1Str"])
            + str(self.fields["NegTokenInitSeqNLMPTag2"])
            + str(self.fields["NegTokenInitSeqNLMPTag2Len"])
            + str(self.fields["NegTokenInitSeqNLMPTag2Octet"])
            + str(self.fields["NegTokenInitSeqNLMPTag2OctetLen"])
            + str(self.fields["NegTokenInitSeqMechSignature"])
            + str(self.fields["NegTokenInitSeqMechMessageType"])
            + str(self.fields["NegTokenInitSeqMechMessageFlags"])
            + str(self.fields["NegTokenInitSeqMechMessageDomainNameLen"])
            + str(self.fields["NegTokenInitSeqMechMessageDomainNameMaxLen"])
            + str(self.fields["NegTokenInitSeqMechMessageDomainNameBuffOffset"])
            + str(self.fields["NegTokenInitSeqMechMessageWorkstationNameLen"])
            + str(self.fields["NegTokenInitSeqMechMessageWorkstationNameMaxLen"])
            + str(self.fields["NegTokenInitSeqMechMessageWorkstationNameBuffOffset"])
            + str(self.fields["NegTokenInitSeqMechMessageVersionHigh"])
            + str(self.fields["NegTokenInitSeqMechMessageVersionLow"])
            + str(self.fields["NegTokenInitSeqMechMessageVersionBuilt"])
            + str(self.fields["NegTokenInitSeqMechMessageVersionReserved"])
            + str(self.fields["NegTokenInitSeqMechMessageVersionNTLMType"])
        )

        data7 = (
            str(self.fields["NegTokenInitSeqNLMPTag2Octet"])
            + str(self.fields["NegTokenInitSeqNLMPTag2OctetLen"])
            + str(self.fields["NegTokenInitSeqMechSignature"])
            + str(self.fields["NegTokenInitSeqMechMessageType"])
            + str(self.fields["NegTokenInitSeqMechMessageFlags"])
            + str(self.fields["NegTokenInitSeqMechMessageDomainNameLen"])
            + str(self.fields["NegTokenInitSeqMechMessageDomainNameMaxLen"])
            + str(self.fields["NegTokenInitSeqMechMessageDomainNameBuffOffset"])
            + str(self.fields["NegTokenInitSeqMechMessageWorkstationNameLen"])
            + str(self.fields["NegTokenInitSeqMechMessageWorkstationNameMaxLen"])
            + str(self.fields["NegTokenInitSeqMechMessageWorkstationNameBuffOffset"])
            + str(self.fields["NegTokenInitSeqMechMessageVersionHigh"])
            + str(self.fields["NegTokenInitSeqMechMessageVersionLow"])
            + str(self.fields["NegTokenInitSeqMechMessageVersionBuilt"])
            + str(self.fields["NegTokenInitSeqMechMessageVersionReserved"])
            + str(self.fields["NegTokenInitSeqMechMessageVersionNTLMType"])
        )

        data8 = (
            str(self.fields["NegTokenInitSeqMechSignature"])
            + str(self.fields["NegTokenInitSeqMechMessageType"])
            + str(self.fields["NegTokenInitSeqMechMessageFlags"])
            + str(self.fields["NegTokenInitSeqMechMessageDomainNameLen"])
            + str(self.fields["NegTokenInitSeqMechMessageDomainNameMaxLen"])
            + str(self.fields["NegTokenInitSeqMechMessageDomainNameBuffOffset"])
            + str(self.fields["NegTokenInitSeqMechMessageWorkstationNameLen"])
            + str(self.fields["NegTokenInitSeqMechMessageWorkstationNameMaxLen"])
            + str(self.fields["NegTokenInitSeqMechMessageWorkstationNameBuffOffset"])
            + str(self.fields["NegTokenInitSeqMechMessageVersionHigh"])
            + str(self.fields["NegTokenInitSeqMechMessageVersionLow"])
            + str(self.fields["NegTokenInitSeqMechMessageVersionBuilt"])
            + str(self.fields["NegTokenInitSeqMechMessageVersionReserved"])
            + str(self.fields["NegTokenInitSeqMechMessageVersionNTLMType"])
        )

        # Buff Offset
        self.fields["SecurityBufferOffset"] = StructWithLenPython2or3(
            "<h", len(data1) + 64
        )
        ##Buff Len
        self.fields["SecurityBufferLen"] = StructWithLenPython2or3("<h", len(data2))
        ##App Header
        self.fields["ApplicationHeaderLen"] = StructWithLenPython2or3("<B", len(data3))
        ##Asn Field 1
        self.fields["AsnSecMechLen"] = StructWithLenPython2or3(
            "<B", len(str(self.fields["AsnSecMechStr"]))
        )
        ##Asn Field 1
        self.fields["ChoosedTagStrLen"] = StructWithLenPython2or3("<B", len(data4))
        ##SpNegoTokenLen
        self.fields["NegTokenInitSeqHeadLen"] = StructWithLenPython2or3(
            "<B", len(data5)
        )
        ##NegoTokenInitcodecs.decode(RandomStr,'hex')
        self.fields["NegTokenInitSeqHeadLen1"] = StructWithLenPython2or3(
            "<B",
            len(
                str(self.fields["NegTokenInitSeqNLMPTag"])
                + str(self.fields["NegTokenInitSeqNLMPLen"])
                + str(self.fields["NegTokenInitSeqNLMPTag1"])
                + str(self.fields["NegTokenInitSeqNLMPTag1Len"])
                + str(self.fields["NegTokenInitSeqNLMPTag1Str"])
            ),
        )
        ## Tag0 Len
        self.fields["NegTokenInitSeqNLMPLen"] = StructWithLenPython2or3(
            "<B",
            len(
                str(self.fields["NegTokenInitSeqNLMPTag1"])
                + str(self.fields["NegTokenInitSeqNLMPTag1Len"])
                + str(self.fields["NegTokenInitSeqNLMPTag1Str"])
            ),
        )
        ## Tag0 Str Len
        self.fields["NegTokenInitSeqNLMPTag1Len"] = StructWithLenPython2or3(
            "<B", len(str(self.fields["NegTokenInitSeqNLMPTag1Str"]))
        )
        ## Tag2 Len
        self.fields["NegTokenInitSeqNLMPTag2Len"] = StructWithLenPython2or3(
            "<B", len(data7)
        )
        ## Tag3 Len
        self.fields["NegTokenInitSeqNLMPTag2OctetLen"] = StructWithLenPython2or3(
            "<B", len(data8)
        )
