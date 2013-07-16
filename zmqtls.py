import logging
import M2Crypto as m
from StringIO import StringIO
import threading
import zmq

from TLSZMQ import TLSZmq

FORMAT = "%(name)s %(message)s"
logging.basicConfig(format=FORMAT)

LOG = logging.getLogger('MAIN')
LOGS = logging.getLogger('SERVER')
LOGC = logging.getLogger('CLIENT')
LOG.setLevel(logging.INFO)
LOGS.setLevel(logging.INFO)
LOGC.setLevel(logging.INFO)
PROTOCOL = 'sslv3'  # or 'tlsv1'


def Main():

    cert, key = ('server.crt', 'server.key')

    server = threading.Thread(target=server_thread, args=(cert, key))
    client = threading.Thread(target=client_thread)

    server.start()
    client.start()

    server.join()
    client.join()


def client_thread():

    ctx = zmq.Context()

    socket = ctx.socket(zmq.REQ)
    socket.connect('tcp://localhost:5556')

    tls = TLSZmq(LOGC)

    tls.send('Hello world !!!')

    while True:
        tls.update()

        if tls.needs_write():
            enc_msg = tls.get_data()
            socket.send(enc_msg)

            enc_req = socket.recv()
            tls.put_data(enc_req)
            tls.update()

        if tls.can_recv(): 
            rep = tls.recv()
            LOGC.info("Received: %s" % rep)
            break

    tls.shutdown()
    LOGC.info("Client exited")


def server_thread(cert, key):

    ctx = zmq.Context()
    socket = ctx.socket(zmq.ROUTER)
    socket.bind('tcp://0.0.0.0:5556')
    conns = {}

    try:
        while True:
            (ident, _, enc_req) = socket.recv_multipart()
            # For REP socket, just recv()
            #enc_req = socket.recv()
            #ident = 1
            if ident not in conns:
                conns[ident] = TLSZmq(LOGS, cert, key)
            tls = conns[ident]
            tls.put_data(enc_req)
            tls.update()

            if tls.can_recv():
                data = tls.recv()

                LOGS.info('Received: %s' % data)

                tls.send('%s: Got it!' % data)
                tls.update()

            if tls.needs_write():
                enc_rep = tls.get_data()
                socket.send_multipart([ident, _, enc_rep])
                # For REP socket, just send()
                #socket.send(enc_rep)
    except Exception, ex:
        LOG.exception(ex)

    tls.shutdown()        
    LOGS.info("Server exited")


if __name__ == '__main__':
    Main()

