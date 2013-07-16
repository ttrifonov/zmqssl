import logging
from StringIO import StringIO

FORMAT = "%(name)s %(message)s"
logging.basicConfig(format=FORMAT)

LOGS = logging.getLogger('SERVER')
LOGC = logging.getLogger('CLIENT')
LOGS.setLevel(logging.DEBUG)
LOGC.setLevel(logging.DEBUG)

PROTOCOL = 'sslv3'  # or 'tlsv1'

from server import ZMQTLSServer
from client import ZMQTLSClient


def Main():

    cert, key = ('server.crt', 'server.key')
    socket_uri = 'tcp://0.0.0.0:5556'

    server = ZMQTLSServer(LOGS, socket_uri, PROTOCOL, cert, key)
    client = ZMQTLSClient(LOGC, socket_uri, PROTOCOL)

    server.start()
    client.start()

    client.join()
    server.join()


if __name__ == '__main__':
    Main()

