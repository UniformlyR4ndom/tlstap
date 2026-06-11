import logging
import socket
import threading

from .interceptor import Interceptor
from .conn_handler import ConnHandler

class Server:
    def __init__(self, interceptor : Interceptor, ip : str, port : str) -> None:
        self.interceptor = interceptor
        self.ip = ip
        self.port = port

    
    def serve(self):
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.bind((self.ip, int(self.port)))

        logging.info(f"Listening at {self.ip}:{self.port}")
        server.listen()
        while True:
            conn, addr = server.accept()
            logging.info(f"Accepted connection from {addr[0]}:{addr[1]}")
            handler = ConnHandler(conn, self.interceptor)
            threading.Thread(target=handler.handleConn).start()   
