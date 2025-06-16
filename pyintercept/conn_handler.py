import logging
import socket
import struct

from .interceptor import Interceptor

class ConnHandler:
    FRAME_TYPE_DATA = 0
    FRAME_TYPE_INFO = 1

    EVENT_CONN_ESTABLISHED = 0x10
    EVENT_CONN_TERMINATED = 0x11


    def __init__(self, conn : socket.socket, interceptor : Interceptor) -> None:
        self.conn = conn
        self.interceptor = interceptor


    def handleConn(self) -> None:
        try:
            while True:
                frameType = _read_n(self.conn, 1)[0]
                if frameType == ConnHandler.FRAME_TYPE_DATA:
                    self._handleData()
                elif frameType == ConnHandler.FRAME_TYPE_INFO:
                    self._handleInfo()
                else:
                    logging.error(f"Unhandled frame type {frameType}. Dropping connection.")
                    return
        except EOFError as e:
            logging.info("Connection terminated")
        

    def _handleData(self) -> None:
        # read data header: size (uint32), connection ID (uint32)
        headerBuf = _read_n(self.conn, 8)
        size = struct.unpack_from("<I", headerBuf)[0]
        connId = struct.unpack_from("<I", headerBuf, 4)[0]

        # read data 
        data = _read_n(self.conn, size)

        # intercept data
        data = self.interceptor.intercept(connId, data)

        # forward data frame
        self.conn.send(headerBuf)
        if len(data) > 0:
            self.conn.send(data)


    def _handleInfo(self) -> None:
        # read info event type (1 byte) and connection ID (uint32)
        headerBuf = _read_n(self.conn, 5)
        eventId = headerBuf[0]
        connId = struct.unpack("<I", headerBuf[1:])[0]

        # read string length (uint32) and then string
        lenBytes = _read_n(self.conn, 4)
        l = struct.unpack("<I", lenBytes)[0]
        src = str(_read_n(self.conn, l), "utf-8")

        # read string length (uint32) and then string
        lenBytes = _read_n(self.conn, 4)
        l = struct.unpack("<I", lenBytes)[0]
        dst = str(_read_n(self.conn, l), "utf-8")

        if eventId == ConnHandler.EVENT_CONN_ESTABLISHED:
            self.interceptor.conn_established(connId, src, dst)
        elif eventId == ConnHandler.EVENT_CONN_TERMINATED:
            self.interceptor.conn_terminated(connId, src, dst)



def _read_n(conn : socket.socket, n : int) -> bytearray:
    buf = bytearray(n)
    pos = 0
    while pos < n:
        cr = conn.recv_into(memoryview(buf)[pos:])
        if cr == 0:
            raise EOFError
        pos += cr
    return buf