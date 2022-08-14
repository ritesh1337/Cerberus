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

import re, requests
from threading import Lock

class Core:
    threadLock = Lock()
    socklock = Lock()
    methods = {}
    infodict = {}
    attackrunning = False
    killattack = False
    threadcount = 0
    bypass_cache = True
    session = requests.session
    ddosguard_cookies_grabbed = False
    blazingfast_ids_grabbed = False
    target_host = None
    target_port = None
    target_netloc = ''
    is_tor_active = False
    attack_id = ''
    attack_method = 'GET'
    change_identity = 0
    proxy_pool = None
    proxy_proto = None
    reflectors = None
    targets = []
    referer_list = []
    headers = {}
    post_buffer = ''
    random_headers = []
    useragent_list = []
    recursive_urls = []
    sockets = []
    cf_check_done = False
    cf_check_busy = False
    http_proto_ver = '1.1'
    file_buffer = (16*1024*1024)
    ipregex = re.compile(r'([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})|(([a-f0-9:]+:+)+[a-f0-9]+)')
    default_headers = {
        "Upgrade-Insecure-Requests": "1",
        "Dnt": "1",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.61 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9",
        "Sec-Fetch-Site": "same-origin",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-User": "?1",
        "Sec-Fetch-Dest": "document",
        "Referer": "https://google.com",
        "Accept-Encoding": "gzip, deflate, br",
        "Accept-Language": "en-GB,en-US;q=0.9,en;q=0.8",
        "Cache-Control": "no-cache"
    }