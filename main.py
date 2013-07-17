import logging
from StringIO import StringIO

FORMAT = "%(name)s %(message)s"
logging.basicConfig(format=FORMAT)

LOGS = logging.getLogger('SERVER')
LOGS.setLevel(logging.DEBUG)

LOGC1 = logging.getLogger('CLIENT')
LOGC1.setLevel(logging.DEBUG)

LOGC2 = logging.getLogger('CLIENT2')
LOGC2.setLevel(logging.DEBUG)

LOGC3 = logging.getLogger('CLIENT3')
LOGC3.setLevel(logging.DEBUG)

PROTOCOL = 'sslv3'  # or 'tlsv1'

from server import ZMQTLSServer
from client import ZMQTLSClient


def Main():

    cert, key = ('server.crt', 'server.key')
    socket_uri = 'tcp://0.0.0.0:5556'

    server = ZMQTLSServer(LOGS, socket_uri, PROTOCOL, cert, key)
    client1 = ZMQTLSClient('client1', LOGC1, socket_uri, PROTOCOL)
    client2 = ZMQTLSClient('client2', LOGC2, socket_uri, PROTOCOL)
    client3 = ZMQTLSClient('000012345678901234561234567890123456', LOGC3, socket_uri, PROTOCOL)

    server.start()
    client1.start()
    client2.start()
    client3.start()

    client1.join()
    client2.join()
    client3.join()
    server.join()


if __name__ == '__main__':
    Main()

