import logging
import M2Crypto as m
from StringIO import StringIO
import zmq

PROTOCOL = 'tlsv1' #'sslv3'  # or 'tlsv1'

UNKNOWN_ISSUER = [
    m.m2.X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT,
    m.m2.X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY,
    m.m2.X509_V_ERR_UNABLE_TO_VERIFY_LEAF_SIGNATURE,
    m.m2.X509_V_ERR_CERT_UNTRUSTED,
]


class TLSZmq(object):

    _ctx = None

    def __init__(self, identity, log, proto, cert=None, key=None, ca=None):
        self.DEPTH = 5
        self.BUF_LEN = 1024
        self.identity = identity
        self.LOG = log
        self.proto = proto
        self.cert = cert
        self.key = key
        self.ca = ca

        if ca:
            self.type = 'Server'
        else:
            self.type = 'Client'

        self.init_ctx()
        self.init_ssl()

    def verify_callback(self, ctx, cert, errnum, errdepth, ok):
        return 1
        x509 = m.X509.X509(cert)

        if errnum in UNKNOWN_ISSUER: 
            if self.ctx.get_allow_unknown_ca():
                self.LOG.error("policy: %s: permitted..." %
                               (m.m2.x509_get_verify_error(errnum)))
                ok = 1
        if ok:
            if self.ctx.get_verify_depth() >= errdepth:
                ok = 1
            else:
                ok = 0
        return True

    def init_ctx(self):
        if TLSZmq._ctx is None:
            TLSZmq._ctx = m.SSL.Context(self.proto)
            if self.cert:
                TLSZmq._ctx.load_cert(self.cert, keyfile=self.key)
        self.ctx = TLSZmq._ctx  # m.SSL.Context(self.proto)

        self.ctx.set_options(m.SSL.op_no_sslv2)
        if self.ca:
            self.ctx.set_verify(m.SSL.verify_peer
                                #| m.SSL.verify_client_once | m.SSL.verify_fail_if_no_peer_cert
                                | m.SSL.verify_fail_if_no_peer_cert
                                , self.DEPTH, self.verify_callback)
            self.ctx.set_client_CA_list_from_file(self.ca)
            self.ctx.load_verify_locations(self.ca)
        #else:
        #    self.ctx.set_verify(m.SSL.verify_peer,
        #                        self.DEPTH)
        #self.ctx.set_allow_unknown_ca(True)    
        #self.ctx.set_info_callback()

    def init_ssl(self):
        self.rbio = m.BIO.MemoryBuffer()
        self.wbio = m.BIO.MemoryBuffer()

        self.ssl = m.SSL.Connection(self.ctx, sock=None)
        self.ssl.set_bio(self.rbio, self.wbio)

        self.app_to_ssl = StringIO()
        self.ssl_to_zmq = StringIO()
        self.zmq_to_ssl = StringIO()
        self.ssl_to_app = StringIO()

        if self.type == 'Server':
            assert len(self.identity) <= 32
            self.ssl.set_client_CA_list_from_context()
            self.ctx.set_session_id_ctx(self.identity)
            self.ssl.set_session_id_ctx(self.identity)
            self.ssl.set_accept_state()
        else:
            self.ssl.set_connect_state()

    def update(self):
        if self.zmq_to_ssl.len:
            rc = self.rbio.write(self.flush(self.zmq_to_ssl))
            self.LOG.debug('%s written to BIO' % (rc))
        if self.app_to_ssl.len:
            rc = self.ssl.write(self.app_to_ssl.getvalue())
            if not self.continue_ssl(rc):
                raise Exception('SSL Error')
            if rc == self.app_to_ssl.len:
                self.app_to_ssl.truncate(0)
            self.LOG.debug("%s written to SSL" % (rc))

        self.net_read()
        self.net_write()

    def continue_ssl(self, rc):
        err = self.ssl.ssl_get_error(rc)
        if err == 2:
            # Negotiate, continue
            return True
        if err:
            self.LOG.error("SSL Error: [%s] %s" % (err,
                          (m.m2.err_reason_error_string(err))))
            return False
        return True

    def net_read(self):
        while True:
            rc = self.ssl.read(self.BUF_LEN)
            if rc is None:
                break
            self.ssl_to_app.write(rc)

    def net_write(self):
        while True:
            read = self.wbio.read()
            if read is None:
                break
            self.ssl_to_zmq.write(read)
        if self.ssl_to_zmq.len:
            self.LOG.debug("%s read from BIO" % (self.ssl_to_zmq.len))

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
        self.ssl.set_ssl_close_flag(m.m2.bio_close)
        self.ssl.shutdown(m.SSL.SSL_RECEIVED_SHUTDOWN | m.SSL.SSL_SENT_SHUTDOWN)
        if hasattr(self, 'rbio'):
            self.rbio.close()
            self.wbio.close()
        #if self.type == 'Server': self.ctx.close()
        self.ssl.close()
        if hasattr(self, 'rbio'):
            del self.rbio
            del self.wbio
