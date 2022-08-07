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

import requests, json, re, os, threading, time

from python_socks.sync import Proxy as proxsocks
from random import choice, shuffle
from threading import Lock

from src.useragent import *

class Proxy():
    def __init__(self):
        self.http_sources = [
            'http://worm.rip/http.txt',
            'http://sheesh.rip/http.txt',
            'https://api.proxyscrape.com/?request=displayproxies&proxytype=http',
            'https://www.proxy-list.download/api/v1/get?type=http',
            'https://www.proxyscan.io/download?type=http',
            'https://raw.githubusercontent.com/TheSpeedX/SOCKS-List/master/http.txt',
            'https://api.openproxylist.xyz/http.txt',
            'https://raw.githubusercontent.com/shiftytr/proxy-list/master/proxy.txt',
            'http://alexa.lr2b.com/proxylist.txt',
            'http://rootjazz.com/proxies/proxies.txt',
            'https://www.freeproxychecker.com/result/http_proxies.txt',
            'http://proxysearcher.sourceforge.net/Proxy%20List.php?type=http',
            'https://raw.githubusercontent.com/jetkai/proxy-list/main/online-proxies/txt/proxies-http.txt',
            'https://raw.githubusercontent.com/clarketm/proxy-list/master/proxy-list-raw.txt',
            'https://raw.githubusercontent.com/sunny9577/proxy-scraper/master/proxies.txt',
            'https://raw.githubusercontent.com/opsxcq/proxy-list/master/list.txt'
            'https://proxy-spider.com/api/proxies.example.txt',
            'https://multiproxy.org/txt_all/proxy.txt',
            'https://raw.githubusercontent.com/roosterkid/openproxylist/main/HTTPS_RAW.txt',
            'https://raw.githubusercontent.com/UserR3X/proxy-list/main/online/http.txt',
            'https://raw.githubusercontent.com/UserR3X/proxy-list/main/online/https.txt',
            'https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/http.txt',
            'https://www.proxy-list.download/api/v1/get?type=https',
            'https://raw.githubusercontent.com/UptimerBot/proxy-list/main/proxies/http.txt',
            'https://raw.githubusercontent.com/almroot/proxylist/master/list.txt',
            'https://raw.githubusercontent.com/clarketm/proxy-list/master/proxy-list-raw.txt',
            'https://raw.githubusercontent.com/ShiftyTR/Proxy-List/master/http.txt',
            'https://openproxy.space/list/http',
            'https://raw.githubusercontent.com/mmpx12/proxy-list/master/http.txt',
            'https://raw.githubusercontent.com/mmpx12/proxy-list/master/https.txt',
            'http://proxydb.net/?protocol=http&protocol=https&anonlvl=1&anonlvl=2&anonlvl=3&anonlvl=4&country=',
            'http://nntime.com/',
            'https://www.us-proxy.org/',
            'https://raw.githubusercontent.com/rdavydov/proxy-list/main/proxies/http.txt',
            'https://raw.githubusercontent.com/mertguvencli/http-proxy-list/main/proxy-list/data.txt',
            'https://raw.githubusercontent.com/Volodichev/proxy-list/main/http.txt',
            'https://raw.githubusercontent.com/Volodichev/proxy-list/main/http_old.txt',
            'https://spys.me/proxy.txt',
            'https://www.my-proxy.com/free-elite-proxy.html'
            'https://www.my-proxy.com/free-anonymous-proxy.html',
            'https://www.my-proxy.com/free-transparent-proxy.html',
            'http://proxysearcher.sourceforge.net/Proxy%20List.php?type=http',
            'https://www.my-proxy.com/free-proxy-list.html',
            'https://www.my-proxy.com/free-proxy-list-1.html',
            'https://www.my-proxy.com/free-proxy-list-2.html',
            'https://www.my-proxy.com/free-proxy-list-3.html',
            'https://www.my-proxy.com/free-proxy-list-4.html',
            'https://www.my-proxy.com/free-proxy-list-5.html',
            'https://www.my-proxy.com/free-proxy-list-6.html',
            'https://www.my-proxy.com/free-proxy-list-7.html',
            'https://www.my-proxy.com/free-proxy-list-8.html',
            'https://www.my-proxy.com/free-proxy-list-9.html',
            'https://www.my-proxy.com/free-proxy-list-10.html',
            'https://proxyspace.pro/http.txt',
            'https://proxyspace.pro/https.txt',
            'https://www.httptunnel.ge/ProxyListForFree.aspx'
        ]

        self.socks4_sources = [
            'https://api.proxyscrape.com/?request=displayproxies&proxytype=socks4&country=all',
            'https://www.proxy-list.download/api/v1/get?type=socks4',
            'https://www.proxyscan.io/download?type=socks4',
            'https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/socks4.txt',
            'https://raw.githubusercontent.com/jetkai/proxy-list/main/online-proxies/txt/proxies-socks4.txt',
            'https://api.openproxylist.xyz/socks4.txt',
            'https://raw.githubusercontent.com/ShiftyTR/Proxy-List/master/socks4.txt',
            'https://www.freeproxychecker.com/result/socks4_proxies.txt',
            'https://raw.githubusercontent.com/roosterkid/openproxylist/main/SOCKS4_RAW.txt',
            'http://worm.rip/socks4.txt',
            'https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/socks4.txt',
            'https://raw.githubusercontent.com/UptimerBot/proxy-list/main/proxies/socks4.txt',
            'https://openproxy.space/list/socks4',
            'http://proxydb.net/?socks4&anonlvl=1&anonlvl=2&anonlvl=3&anonlvl=4&country=',
            'https://raw.githubusercontent.com/rdavydov/proxy-list/main/proxies/socks4.txt',
            'https://www.my-proxy.com/free-socks-4-proxy.html',
            'http://www.socks24.org/feeds/posts/default'
        ]

        self.socks5_sources = [
            'https://api.proxyscrape.com/v2/?request=getproxies&protocol=socks5&timeout=10000&country=all&simplified=true',
            'https://www.proxy-list.download/api/v1/get?type=socks5',
            'https://www.proxyscan.io/download?type=socks5',
            'https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/socks5.txt',
            'https://raw.githubusercontent.com/hookzof/socks5_list/master/proxy.txt',
            'https://raw.githubusercontent.com/ShiftyTR/Proxy-List/master/socks5.txt',
            'https://raw.githubusercontent.com/jetkai/proxy-list/main/online-proxies/txt/proxies-socks5.txt',
            'https://api.openproxylist.xyz/socks5.txt',
            'https://www.freeproxychecker.com/result/socks5_proxies.txt',
            'http://worm.rip/socks5.txt',
            'https://alexa.lr2b.com/socks5.txt',
            'https://raw.githubusercontent.com/ryanhaticus/superiorproxy.com/main/proxies.txt',
            'https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/socks5.txt',
            'https://raw.githubusercontent.com/hookzof/socks5_list/master/proxy.txt',
            'https://raw.githubusercontent.com/UptimerBot/proxy-list/main/proxies/socks5.txt',
            'https://openproxy.space/list/socks5',
            'http://proxydb.net/?protocol=socks4&protocol=socks5&anonlvl=1&anonlvl=2&anonlvl=3&anonlvl=4&country=',
            'https://raw.githubusercontent.com/rdavydov/proxy-list/main/proxies/socks5.txt',
            'https://spys.me/socks.txt',
            'https://www.my-proxy.com/free-socks-5-proxy.html',
            'http://proxysearcher.sourceforge.net/Proxy%20List.php?type=socks'
        ]

        self.testing = [ # domains to request when testing the proxies
            '1.1.1.1:80',
            '1.0.0.1:80',
            '8.8.8.8:80',
            '8.8.4.4:80'
        ]

        self.lock = Lock() # file lock
        self.proxy_dict = {'good': [], 'bad': []}
        self.threads = []
        self.protolist = ['http','socks4','socks5']
        self.threadcounter = 0
        self.urls = {
            'http': self.http_sources,
            'socks4': self.socks4_sources,
            'socks5': self.socks5_sources
        }

        [shuffle(x) for x in [self.http_sources, self.socks4_sources, self.socks5_sources, self.testing]]
    
    def get(self, url) -> str:
        '''
        get(proxy url) -> page output

        Grabs the given sites page, and returns it

        :param url str: Url to request
        :returns str: Page contents
        '''

        try:
            req = requests.get(
                url, 
                headers=Core.default_headers,
                allow_redirects=False,
                verify=False,
                timeout=5
            )
        except Exception:
            return ''

        return req.text
    
    def check_proxies(self, proto='http', file=None) -> dict:
        '''
        check_proxies(protocol, filename) -> proxies sorted in a dict by status

        Filters proxies in a dictionary

        :param proto str: Proxy protocol (HTTP, SOCKS4 or SOCKS5)
        :param file str: File to save to
        :returns dict: Dictionary with the good and bad proxies sorted
        '''

        if not file:
            file = f'{proto}.txt'

        def check(proxy) -> None:
            '''
            check(proxy) -> None

            Checks the proxy's status

            :param proxy str: Proxy in the `ip:port` format
            '''

            err_counter, socket = 0, None

            while 1:

                if err_counter >= 3:

                    if socket:
                        socket.close()

                    with self.lock:
                        self.proxy_dict['bad'].append(proxy)

                    break

                try:

                    testhost, testport = choice(self.testing).split(':')
                    socket = proxsocks.from_url(f'{proto}://{proxy}').connect(testhost, testport)
                    
                    with self.lock:
                        self.proxy_dict['good'].append(proxy)
                    
                    socket.sendall(b'GET / HTTP/1.1\r\n\r\n')
                    
                    if socket:
                        socket.close()

                except Exception:
                    err_counter += 1
                
            if socket:
                socket.close()

            self.threadcounter -= 1

        if not os.path.isfile(file):
            return self.proxy_dict
        
        with self.lock:
            with open(file) as fd:
                proxies = [line.rstrip() for line in fd.readlines()]
        
        shuffle(proxies)
        for proxy in proxies:
            if self.threadcounter > 600:
                time.sleep(0.1); continue

            kaboom = threading.Thread(target=check, args=(proxy,))
            self.threads.append(kaboom)

            kaboom.start()
            self.threadcounter += 1
        
        for thread in self.threads:
            thread.join()
        
        return self.proxy_dict
    
    def get_proxies(self, proto='http') -> list:
        '''
        get_proxies(protocol) -> list of proxies

        Scrapes proxies

        :param proto str: Proxy protocol (HTTP, SOCKS4 or SOCKS5)
        :returns list: List of scraped proxies
        '''
        
        proto = proto.lower() # just incase
        proxies = []

        # protocol specific urls that need different parsing (such as json or regex)
        if proto == 'http':
            page = self.get('https://cool-proxy.net/proxies.json')
            for line in page.splitlines():
                line = json.loads(line)

                try: proxies.append(f'{line["ip"]}:{str(line["port"])}')
                except Exception: pass

        page = self.get('http://proxylist.fatezero.org/proxy.list')
        for line in page.splitlines():
            line = json.loads(line)
            if 'http' in line['type'].lower():
                try: proxies.append(f'{line["host"]}:{str(line["port"])}')
                except Exception: pass
        
        page = self.get('https://raw.githubusercontent.com/stamparm/aux/master/fetch-some-list.txt')
        for obj in json.loads(page):
            if proto in obj['proto']:
                proxies.append(f'{obj["ip"]}:{obj["port"]}')
        
        page = self.get('https://scrapingant.com/proxies')
        for line in re.findall(r'<tr><td>\d+\.\d+\.\d+\.\d+<\/td><td>\d+<\/td><td>.*?<\/td>', page):
            line=line.replace('<tr><td>','').replace('</td>','')

            ip,port,ptype = line.split('<td>')

            if proto in ptype.lower():
                proxies.append(f'{ip}:{port}')
        
        page = self.get('https://hidemy.name/en/proxy-list/#list')
        try:
            part = page.split("<tbody>")[1].split("</tbody>")[0].split("<tr><td>")

            for line in part:
                proxtype = None
                line = line.replace('</td><td>', ':')
                found = re.findall(r'</div></div>:(.*?):', line)

                if found != None and len(found) != 0: proxtype = found[0]
                else: continue

                if proto in proxtype.lower():
                    try:
                        proxy = ':'.join(line.split(':', 2)[:2]).rstrip()
                        if proxy != None and len(proxy) != 0 and proxy != '' and bool(re.match(r'\d+\.\d+\.\d+\.\d+\:\d+', proxy)):
                            proxies.append(proxy)
                    except Exception: pass
        except Exception:
            pass

        page = self.get('https://raw.githubusercontent.com/stamparm/aux/master/fetch-some-list.txt')
        for obj in json.loads(page):
            if proto in obj['proto'].lower():
                proxies.append(f'{obj["ip"]}:{obj["port"]}')
        
        page = self.get('https://raw.githubusercontent.com/proxyips/proxylist/main/proxylistfull.json')
        for obj in json.loads(page):
            if proto in obj['Type'].lower():
                proxies.append(f'{obj["Ip"]}:{obj["Port"]}')

        http_sources = self.urls.get(proto)
        if not http_sources:
            return []

        for url in http_sources:
            try:
                contents = self.get(url)
                for ipfound in Core.ipregex.findall(contents):
                    ipfound = ipfound.rstrip()

                    if ipfound and len(ipfound) != 0 and not ipfound in proxies:
                        proxies.append(ipfound)

            except Exception:
                pass
        
        final = []
        for proxy in proxies:
            if not proxy in final:
                final.append(proxy)

        return final