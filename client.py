import zmq
from threading import Thread
from tlszmq import TLSZmq


class ZMQTLSClient(Thread):

    def __init__(self, name, log, uri, proto):
        super(ZMQTLSClient, self).__init__()
        ctx = zmq.Context()

        self.socket = ctx.socket(zmq.REQ)
        self.name = name
        self.socket.setsockopt(zmq.IDENTITY, self.name)
        self.socket.connect(uri)
        self.LOG = log
        self.proto = proto

    def run(self):
        tls = TLSZmq(self.name, self.LOG, self.proto)
        tls.send(self.name)

        while True:
            tls.update()

            if tls.needs_write():
                enc_msg = tls.get_data()
                self.socket.send(enc_msg)

                enc_req = self.socket.recv()
                tls.put_data(enc_req)
                tls.update()

            if tls.can_recv(): 
                rep = tls.recv()
                self.LOG.info("Received: %s" % rep)
                break

        tls.shutdown()
        self.LOG.info("Client exited")

