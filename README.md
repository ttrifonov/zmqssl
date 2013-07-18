zmqssl
======

A brief example of an SSL/TLS wrapper for ZMQ sockets using M2Crypto.

Python implementation of the nice C++ example given by Ian Barber:

- http://www.riskcompletefailure.com/2012/09/tls-and-zeromq.html

- https://github.com/ianbarber/TLSZMQ


Can be used for REQ-REP and REQ-ROUTER and REQ-DEALER sockets.
Cannot be used for PUB-SUB sockets as SSL/TLS is
end-to-end protocol, while zmq sockets are an abstraction
over classic sockets and cannot negotiate with multiple endpoints.


Usage
======

Run

`python main.py`

or see contents of `main.py`


```python

LOGS = logging.getLogger('SERVER')
LOGC = logging.getLogger('CLIENT')

PROTOCOL = 'sslv3'  # or 'tlsv1'

from server import ZMQTLSServer
from client import ZMQTLSClient

cert, key, ca = ('CA/server.crt', 'CA/server.key', 'CA/ca.crt')
client_cert, client_key = ('CA/node.crt', 'CA/node.key')

socket_uri = 'tcp://0.0.0.0:5556'

server = ZMQTLSServer(LOGS, socket_uri, PROTOCOL, cert, key, ca)
client = ZMQTLSClient('clientId', LOGC, socket_uri, PROTOCOL,
                      client_cert, client_key)

server.start()
client.start()

```
