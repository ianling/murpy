import logging
import socket
from ssl import SSLContext, PROTOCOL_TLS
from threading import Thread

from murpy.client import Client


class Server:
    def __init__(self, certfile, keyfile, keypassword=None, host='0.0.0.0', port=64738):
        self.running = True
        self.clients = {}
        self._last_session_id = -1
        self.channels = [{'name': 'Root'}]
        self._registered_users = []
        self._host = host
        self._port = port
        self._log = logging.getLogger(f'Murpy@{self._host}:{self._port}')
        self._certfile = certfile
        self._keyfile = keyfile
        self._keypassword = keypassword
        self._ssl_context = SSLContext(PROTOCOL_TLS)
        self._ssl_context.load_cert_chain(certfile=self._certfile, keyfile=self._keyfile, password=self._keypassword)
        self._tcp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._tcp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._tcp_socket.bind((self._host, self._port))
        self._udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._udp_socket.bind((self._host, self._port))
        self._listen_tcp_thread = Thread(target=self._listen_tcp)
        self._listen_tcp_thread.start()
        self._listen_udp_thread = Thread(target=self._listen_udp)
        self._listen_udp_thread.start()

    def _listen_tcp(self):
        self._tcp_socket.listen(socket.SOMAXCONN)
        while self.running:
            try:
                client_socket, address = self._tcp_socket.accept()
                client_socket = self._ssl_context.wrap_socket(client_socket, server_side=True)
                print("SSL established. Peer: {}".format(client_socket.getpeercert()))
                client_socket.settimeout(60)
                self.add_user(client_socket, address)
            except OSError:
                # socket closed; probably ran self.stop()
                self.running = False

    def _listen_udp(self):
        pass

    def _send_payload(self, message_type, payload, clients=()):
        """
        Sends a message to the specified clients. If no clients are specified, sends the message to all clients.

        Args:
            message_type(int): protocol message type defined in MessageType enum
            payload(protobuf message): the protobuf message object to send
            clients(iterable): list of Clients to send the mssage to

        Returns:
            None
        """
        if len(clients) == 0:
            clients = self.clients
        for client in clients:
            try:
                client._send_payload(message_type, payload)
            except OSError:
                return False

    def add_user(self, socket, address):
        """
        Adds a user to the list of users.
        """
        session_id = self._last_session_id + 1
        self._last_session_id = session_id
        new_client = Client(session_id, self, socket, address)
        self.clients[session_id] = new_client

    def remove_user(self, client):
        """
        Removes a user from the list of users.
        """
        del(self.clients[client._session_id])

    def is_alive(self):
        return self.running

    def stop(self):
        self.running = False
        self._tcp_socket.shutdown(socket.SHUT_RDWR)
        self._tcp_socket.close()
