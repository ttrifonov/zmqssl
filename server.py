import zmq
import time

from threading import Thread
from tlszmq import TLSZmq

MAX_CACHE_SIZE = 50


class ZMQTLSServer(Thread):

    def __init__(self, log, uri, proto, cert, key, ca):
        super(ZMQTLSServer, self).__init__()
        ctx = zmq.Context()
        self.socket = ctx.socket(zmq.ROUTER)  # or zmq.REP, or zmq.DEALER
        self.socket.bind(uri)
        self.proto = proto
        self.LOG = log
        self.cert = cert
        self.key = key
        self.ca = ca
        self.conns = {}

    def run(self):

        while True:
            try:
                if self.socket.type == zmq.ROUTER:
                    (ident, _, enc_req) = self.socket.recv_multipart()
                elif self.socket.type == zmq.DEALER:
                    (_, enc_req) = self.socket.recv_multipart()
                    ident = 'some if from enc_req'
                elif self.socket.type == zmq.REP:
                    enc_req = self.socket.recv()
                    ident = 'some id from enc_req'
                else:
                    raise Exception('Unsupported socket type: %s' %
                                    self.socket.type)
                if ident not in self.conns:
                    self.conns[ident] = [time.time(),
                                         TLSZmq('identity_' + 
                                                 str(len(self.conns.items())),
                                                 self.LOG, self.proto,
                                                 self.cert, self.key, self.ca)]
                tls = self.conns[ident][1]

                if len(self.conns) > MAX_CACHE_SIZE:
                    _cache = sorted(self.conns.values(), key=lambda t: t[0])
                    oldest = _cache[0][1]
                    oldest.shutdown()

                tls.put_data(enc_req)
                tls.update()

                if tls.can_recv():
                    data = tls.recv()
                    x509 = tls.ssl.get_peer_cert()
                    if x509:
                        self.LOG.info("Client [%s]:" % x509.get_subject().CN)
                        self.LOG.info('Received: %s' % data)

                    tls.send('%s: Got it!' % data)
                    tls.update()

                if tls.needs_write():
                    enc_rep = tls.get_data()
                    if self.socket.type == zmq.ROUTER:
                        self.socket.send_multipart([ident, _, enc_rep])
                    elif self.socket.type == zmq.DEALER:
                        self.socket.send_multipart([_, enc_rep])
                    elif self.socket.type == zmq.REP:
                        self.socket.send(enc_rep)
            except Exception, ex:
                self.LOG.exception(ex)
                break

        self.terminate()
        self.LOG.info("Server exited")

    def terminate(self):
        print "Closing Server"
        for conn in self.conns:
            print 'Terminating', conn

