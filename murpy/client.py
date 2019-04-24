import select
import socket
import struct
import traceback
from threading import Thread

from murpy import mumble_pb2
from murpy.channel import Channel
from murpy.constants import ConnectionState, MessageType, PROTOCOL_VERSION, RELEASE_STRING, OS_STRING, \
    OS_VERSION_STRING, EventType
from murpy.event import Event


class Client:
    def __init__(self, server, client_socket, address):
        """
        An object for keeping track of client connections to the server.

        Args:
            server(Murpy): the server object
            client_socket(SSLSocket): the TCP socket
            address(tuple): the client's connection info (address, port)
        """
        self.connected = True
        self._server = server
        self._socket = client_socket
        self._address = address
        self._message_handlers = {MessageType.VERSION: self._message_handler_version,
                                  MessageType.AUTHENTICATE: self._message_handler_authenticate,
                                  MessageType.UDPTUNNEL: self._message_handler_udp_tunnel,
                                  MessageType.PING: self._message_handler_ping,
                                  MessageType.CHANNELREMOVE: self._message_handler_channel_remove,
                                  MessageType.CHANNELSTATE: self._message_handler_channel_state,
                                  MessageType.USERREMOVE: self._message_handler_user_remove,
                                  MessageType.USERSTATE: self._message_handler_user_state,
                                  MessageType.BANLIST: self._message_handler_ban_list,
                                  MessageType.TEXTMESSAGE: self._message_handler_text_message,
                                  MessageType.ACL: self._message_handler_acl,
                                  MessageType.QUERYUSERS: self._message_handler_query_users,
                                  MessageType.CRYPTSETUP: self._message_handler_crypt_setup,
                                  MessageType.USERLIST: self._message_handler_user_list,
                                  MessageType.PERMISSIONQUERY: self._message_handler_permission_query,
                                  MessageType.USERSTATS: self._message_handler_user_stats
                                  }
        self._listen_tcp_thread = Thread(target=self._listen_tcp)
        self._listen_tcp_thread.start()
        # immediately send Version message when a client connects
        version_response = mumble_pb2.Version()
        version_response.version = struct.unpack('>I', struct.pack('>HBB', *PROTOCOL_VERSION))[0]
        version_response.release = RELEASE_STRING
        version_response.os = OS_STRING
        version_response.os_version = OS_VERSION_STRING
        self._send_payload(MessageType.VERSION, version_response)

    # message type 0
    def _message_handler_version(self, payload):
        message = mumble_pb2.Version()
        message.ParseFromString(payload)
        client_version = struct.unpack('>HBB', struct.pack('>I', message.version))
        self._server._log.debug('Client {} version: {}.{}.{}'.format(self._address, *client_version))
        if client_version < (1, 2, 4):
            self._server._log.error('Version mismatch! Our version is {}.{}.{}. Killing connection...'.format(*PROTOCOL_VERSION))
            # TODO: send Reject message
            self.disconnect()

    # message type 1 -- UDPTunnel
    def _message_handler_udp_tunnel(self, payload):
        # TODO: handle receiving these on the server
        pass

    # message type 2 -- Authenticate
    def _message_handler_authenticate(self, payload):
        message = mumble_pb2.Authenticate()
        message.ParseFromString(payload)
        username = message.username
        password = message.password
        celt_versions = message.celt_versions
        opus = message.opus

    # message type 3
    def _message_handler_ping(self, payload):
        message = mumble_pb2.Ping()
        message.ParseFromString(payload)
        # TODO: handle receiving these on the server
        pass

    # message type 4 -- Reject
    # not sent by clients

    # message type 5 -- ServerSync
    # not sent by clients

    # message type 6
    def _message_handler_channel_remove(self, payload):
        message = mumble_pb2.ChannelRemove()
        message.ParseFromString(payload)
        # TODO: handle receiving these on the server
        pass

    # message type 7
    def _message_handler_channel_state(self, payload):
        message = mumble_pb2.ChannelState()
        message.ParseFromString(payload)
        # TODO: handle receiving these on the server
        pass

    # message type 8
    def _message_handler_user_remove(self, payload):
        """
        Murmur sends two UserRemove messages when someone is kicked or banned.
        The first one contains the session, actor, reason, and ban fields.
        The second message contains only the session ID of the victim.
        However, when someone simply leaves the server, only the second message is sent.
        """
        message = mumble_pb2.UserRemove()
        message.ParseFromString(payload)
        # TODO: handle receiving these on the server
        pass

    # message type 9
    def _message_handler_user_state(self, payload):
        message = mumble_pb2.UserState()
        message.ParseFromString(payload)
        # TODO: handle receiving these on the server
        pass

    # message type 10
    def _message_handler_ban_list(self, payload):
        message = mumble_pb2.BanList()
        message.ParseFromString(payload)
        # TODO: handle receiving these on the server
        pass

    # message type 11
    def _message_handler_text_message(self, payload):
        message = mumble_pb2.TextMessage()
        message.ParseFromString(payload)
        # TODO: handle receiving these on the server
        pass

    # message type 12 -- PermissionDenied
    # not sent by clients

    # message type 13
    def _message_handler_acl(self, payload):
        message = mumble_pb2.ACL()
        message.ParseFromString(payload)
        # TODO: handle receiving these on the server
        pass

    # message type 14
    def _message_handler_query_users(self, payload):
        message = mumble_pb2.QueryUsers()
        message.ParseFromString(payload)
        # TODO: handle receiving these on the server
        pass

    # message type 15
    def _message_handler_crypt_setup(self, payload):
        message = mumble_pb2.CryptSetup()
        message.ParseFromString(payload)
        # TODO: handle receiving these on the server
        pass

    # message type 16 -- ContextActionModify
    # TODO: handle receiving these on the server, what does this do?

    # message type 17 -- ContextAction
    # TODO: handle receiving these on the server, what does this do?

    # message type 18
    def _message_handler_user_list(self, payload):
        message = mumble_pb2.UserList()
        message.ParseFromString(payload)
        # TODO: handle receiving these on the server
        pass

    # message type 19 -- VoiceTarget
    # TODO: handle receiving these on the server

    # message type 20
    def _message_handler_permission_query(self, payload):
        message = mumble_pb2.PermissionQuery()
        message.ParseFromString(payload)
        # TODO: handle receiving these on the server
        pass

    # message type 21 -- CodecVersion
    # not sent by clients

    # message type 22
    def _message_handler_user_stats(self, payload):
        # TODO: handle receiving these on the server
        pass

    # message type 23 -- RequestBlob
    # TODO: handle receiving these on the server

    # message type 24 -- ServerConfig
    # not sent by clients

    # message type 25 -- SuggestConfig
    # not sent by clients

    def _listen_tcp(self):
        self._tcp_message_buffer = b""
        while self.connected:
            inputs, outputs, exceptions = select.select([self._socket], [], [])
            for input_socket in inputs:
                try:
                    self._tcp_message_buffer += input_socket.recv(4096)
                except OSError:
                    self._server._log.debug(f"TCP socket died for client {self._address}")
                    self.connected = False
                    continue
                except socket.timeout:
                    self._server._log.debug(f"Client {self._address} timed out")
                    self.connected = False
                    continue
                if len(self._tcp_message_buffer) == 0:  # connection closed by server
                    self._server._log.debug(f"Client {self._address} disconnected")
                    self.connected = False
                    continue

                while len(self._tcp_message_buffer) >= 6:  # message header present
                    message_type = int.from_bytes(self._tcp_message_buffer[0:2], byteorder='big')
                    message_length = int.from_bytes(self._tcp_message_buffer[2:6], byteorder='big')
                    if len(self._tcp_message_buffer) >= 6 + message_length:
                        message_payload = self._tcp_message_buffer[6:6 + message_length]
                    else:  # need to read more, buffer only contains partial packet
                        self._tcp_message_buffer += input_socket.recv(4096)
                        continue
                    self._tcp_message_buffer = self._tcp_message_buffer[6 + message_length:]

                    try:
                        self._message_handlers[message_type](message_payload)
                    except Exception as e:
                        self._server._log.warning(f'Caught exception ({e}) while handling message type {message_type}, \n'
                                                  f'message = {message_payload} \n',
                                                  f'exception = {traceback.format_exc()}')

    def _send_payload(self, message_type, payload):
        packet = struct.pack('!HL', message_type, payload.ByteSize()) + payload.SerializeToString()
        try:
            self._socket.send(packet)
        except OSError:
            return False

    def disconnect(self):
        self.connected = False
        self._socket.shutdown(socket.SHUT_RDWR)
        self._socket.close()
