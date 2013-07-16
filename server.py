import zmq
from threading import Thread
from tlszmq import TLSZmq


class ZMQTLSServer(Thread):

    def __init__(self, log, uri, proto, cert, key):
        super(ZMQTLSServer, self).__init__()
        ctx = zmq.Context()
        self.socket = ctx.socket(zmq.ROUTER)  # or zmq.REP, or zmq.DEALER
        self.socket.bind(uri)
        self.proto = proto
        self.LOG = log
        self.cert = cert
        self.key = key

    def run(self):

        conns = {}
        _ = ''
        ident = 1
        try:
            while True:
                if self.socket.type == zmq.ROUTER:
                    (ident, _, enc_req) = self.socket.recv_multipart()
                elif self.socket.type == zmq.DEALER:
                    (ident, enc_req) = self.socket.recv_multipart()
                elif self.socket.type == zmq.REP:
                    enc_req = self.socket.recv()
                else:
                    raise Exception('Unsupported socket type: %s' %
                                    self.socket.type)
                if ident not in conns:
                    conns[ident] = TLSZmq(self.LOG, self.proto,
                                          self.cert, self.key)
                tls = conns[ident]
                tls.put_data(enc_req)
                tls.update()

                if tls.can_recv():
                    data = tls.recv()

                    self.LOG.info('Received: %s' % data)

                    tls.send('%s: Got it!' % data)
                    tls.update()

                if tls.needs_write():
                    enc_rep = tls.get_data()
                    if self.socket.type == zmq.ROUTER:
                        self.socket.send_multipart([ident, _, enc_rep])
                    elif self.socket.type == zmq.DEALER:
                        self.socket.send_multipart([ident, enc_rep])
                    elif self.socket.type == zmq.REP:
                        self.socket.send(enc_rep)
        except Exception, ex:
            self.LOG.exception(ex)

        for conn in conns.values():
            conn.shutdown()

        self.LOG.info("Server exited")

