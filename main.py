import logging
from StringIO import StringIO
import time
import zmq

LOG_LEVEL = logging.INFO
FORMAT = "%(name)s %(message)s"
logging.basicConfig(format=FORMAT)

CLIENT_COUNT = 100

LOGS = logging.getLogger('SERVER')
LOGS.setLevel(LOG_LEVEL)

PROTOCOL = 'sslv3'  # or 'tlsv1'

from server import ZMQTLSServer
from client import ZMQTLSClient


def Main():

    print "=" * 50
    print
    print "=" * 50
    cert, key, ca = ('CA/server.crt', 'CA/server.key', 'CA/ca.crt')
    client_cert, client_key = ('CA/node.crt', 'CA/node.key')
    #client_cert, client_key = (None, None)
    # Pass None for cert, key, if no client cert is used,
    # but check the tlszmq for verify_peer flag
    socket_uri = 'tcp://0.0.0.0:5556'

    server = ZMQTLSServer(LOGS, socket_uri, PROTOCOL, cert, key, ca)
    server.start()

    clients = []

    ctx = zmq.Context(1)
    for i in range(1, CLIENT_COUNT+1):
        LOGC = logging.getLogger('Client %i' %i)
        LOGC.setLevel(LOG_LEVEL)
        client = ZMQTLSClient('client %i' % i, LOGC, socket_uri,
                              PROTOCOL, client_cert, client_key, ctx=ctx)
        clients.append(client)

    for i in range(CLIENT_COUNT):
        clients[i].start()
        time.sleep(0.05)
    for i in range(CLIENT_COUNT):
        clients[i].join()

    server.join()


if __name__ == '__main__':
    Main()

