import logging
import M2Crypto as m
from StringIO import StringIO
import zmq

PROTOCOL = 'sslv3'  # or 'tlsv1'


class TLSZmq(object):

    def __init__(self, log, proto, cert=None, key=None):
        self.DEPTH = 5
        self.BUF_LEN = 1024
        self.LOG = log
        self.proto = proto
        self.init_ctx()
        self.ctx.set_allow_unknown_ca(True)

        def vf_callback(ctx, cert, a, b, ok):
            return ok

        if cert:
            self.type = 'Server'
            # Server constructor
            self.ctx.load_cert(cert, keyfile=key)
        else:
            # Client constructor
            self.type = 'Client'

        #self.ctx.set_verify(m.SSL.verify_peer |
        #                    m.SSL.verify_fail_if_no_peer_cert,
        #                    self.DEPTH, vf_callback)
        self.ctx.set_verify(m.SSL.verify_none, self.DEPTH, vf_callback)
        self.init_ssl()
        if self.type == 'Server':
            self.ssl.set_accept_state()
        else:
            self.ssl.set_connect_state()

    def init_ctx(self):
        self.ctx = m.SSL.Context(self.proto)

    def init_ssl(self):
        self.rbio = m.BIO.MemoryBuffer()
        self.wbio = m.BIO.MemoryBuffer()

        self.ssl = m.SSL.Connection(self.ctx)
        self.ssl.set_bio(self.rbio, self.wbio)

        self.app_to_ssl = StringIO()
        self.ssl_to_zmq = StringIO()
        self.zmq_to_ssl = StringIO()
        self.ssl_to_app = StringIO()

    def update(self):
        if self.zmq_to_ssl.len:
            rc = self.rbio.write(self.flush(self.zmq_to_ssl))
            self.LOG.info('%s written to BIO' % (rc))
        if self.app_to_ssl.len:
            rc = self.ssl.write(self.app_to_ssl.getvalue())
            if rc == self.app_to_ssl.len:
                self.app_to_ssl.truncate(0)
            self.LOG.info("%s written to SSL" % (rc))

        self.net_read()
        self.net_write()

    def continue_ssl(self):
        # Not sure how to read the error here..
        #err = m.m2.err_get_error() ??
        #if err != ????
        #    self.LOG.error(err)
        #    return False
        return True

    def net_read(self):
        while True:
            rc = self.ssl.read(self.BUF_LEN)
            if rc is None:
                break
            if not self.continue_ssl():
                raise Exception('SSL Error')
            self.ssl_to_app.write(rc)

    def net_write(self):
        while True:
            read = self.wbio.read()
            if read is None:
                break
            self.ssl_to_zmq.write(read)
        if self.ssl_to_zmq.len:
            self.LOG.info("%s read from BIO" % (self.ssl_to_zmq.len))

    def can_recv(self):
        return self.ssl_to_app.len

    def needs_write(self):
        return self.ssl_to_zmq.len

    def recv(self):
        return self.flush(self.ssl_to_app)

    def get_data(self):
        return self.flush(self.ssl_to_zmq)

    def put_data(self, data):
        self.zmq_to_ssl.write(data)

    def send(self, data):
        self.app_to_ssl.write(data)

    def flush(self, io):
        ret = io.getvalue()
        io.truncate(0)
        return ret

    def shutdown(self):
        self.ssl.close()
        self.ctx.close()
        self.ssl.shutdown(m.SSL.SSL_RECEIVED_SHUTDOWN | m.SSL.SSL_SENT_SHUTDOWN)

