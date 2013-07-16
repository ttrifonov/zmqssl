zmqssl
======

SSL/TLS wrapper for ZMQ sockets

Python implementation of the nice example given from Ian Barber:
http://www.riskcompletefailure.com/2012/09/tls-and-zeromq.html

Can be used for REQ-REP and REQ-ROUTER sockets (and probably DEALERs).
Cannot be used for PUB-SUB sockets as SSL/TLS is
end-to-end protocol, while zmq sockets are an abstraction
over classic sockets and cannot negotiate with multiple endpoints.


Usage
======


```python

LOGS = logging.getLogger('SERVER')
LOGC = logging.getLogger('CLIENT')

PROTOCOL = 'sslv3'  # or 'tlsv1'

from server import ZMQTLSServer
from client import ZMQTLSClient


cert, key = ('server.crt', 'server.key')
socket_uri = 'tcp://0.0.0.0:5556'

server = ZMQTLSServer(LOGS, socket_uri, PROTOCOL, cert, key)
client = ZMQTLSClient(LOGC, socket_uri, PROTOCOL)

server.start()
client.start()

```
