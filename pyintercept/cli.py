import argparse
import logging
import sys

from .interceptor import Interceptor
from .server import Server

def start_with_cli(interceptor : Interceptor):
    parser = argparse.ArgumentParser(
    prog="bridge-interceptor-py",
    description="Bridge-interceptor implementation in python. Useful to write custom interceptors for tlstap in python.")
    parser.add_argument("-p", "--listen-port")
    parser.add_argument("-ip", "--listen-ip")
    args = parser.parse_args()

    logging.basicConfig()
    logging.getLogger().setLevel(logging.INFO)

    if args.listen_ip is None:
        logFatal("listen IP must be provided")

    if args.listen_port is None:
        logFatal("listen port must be provided")

    server = Server(interceptor, args.listen_ip, args.listen_port)
    server.serve()


def logFatal(msg):
    logging.critical(msg)
    sys.exit(1)