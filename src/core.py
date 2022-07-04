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

from threading import Lock

class Core:
    threadLock = Lock()
    methods = {}
    infodict = {}
    attackrunning = False
    killattack = False
    threadcount = 0
    bypass_cache = True
    session = None
    ddosguard_cookies_grabbed = False
    blazingfast_ids_grabbed = False
    target_host = None
    target_port = None
    is_tor_active = False
    attack_id = None
    change_identity = 0 # once the counter reached 2000 we will change to a new tor circuit
    #cloudflare_cookies_grabbed = False
    #driver_engine = None
    proxy_pool = []
    proxy_proto = None
    targets = None
    referer_list = None
    headers = None
    post_buffer = None
    random_headers = None
    useragent_list = None
    recursive_urls = None