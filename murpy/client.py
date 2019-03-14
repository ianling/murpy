import socket
from threading import Thread


class Client:
    def __init__(self, server, client_socket, address):
        self.connected = True
        self._server = server
        self._socket = client_socket
        self._address = address
        self._listen_tcp_thread = Thread(target=self._listen_tcp)
        self._listen_tcp_thread.start()

    def _listen_tcp(self):
        while self.connected:
            try:
                data = self._socket.recv(1024)
                if data:
                    print(data)
                else:
                    self._server._log.warning(f"Client {self._address} disconnected.")
                    self.connected = False
            except socket.timeout:
                self._server._log.warning(f"Client {self._address} timed out.")
                self.connected = False
