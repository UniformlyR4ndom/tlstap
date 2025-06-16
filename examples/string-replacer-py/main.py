import argparse
import logging
import os
import sys

# dirty trick to enable python to find the package locally
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../../')))
from pyintercept.cli import start_with_cli
from pyintercept.interceptor import Interceptor


def main():
    start_with_cli(StringReplacer())


class StringReplacer(Interceptor):
    def intercept(self, connId : int, data : bytearray) -> bytearray:
        data = data.replace(b'ping', b'pong')
        data = data.replace(b'hello', b'byeee')
        return data
    

    def conn_established(self, connId : int, src : str, dst : str) -> None:
        logging.info(f"Established connection {connId} ({src} <-> {dst})")


    def conn_terminated(self, connId : int, src : str, dst : str) -> None:
        logging.info(f"Terminated connection {connId} ({src} <-> {dst})")

    
if __name__ == "__main__":
    main()
