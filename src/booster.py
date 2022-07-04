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

'''
HOIC booster file parser, just "translates" them into python code them executes them
Also, be warned. The code is a bloody mess
'''

import re
from src.core import *

class Booster():
    def __init__(self, booster):
        self.booster = booster

        with open(self.booster) as fd:
            self.contents = fd.read()
        
        self.final = ''
        
    def get(self) -> str:

        new_data = self.contents
        replace_list = [
            ('.Append ', '.Append('),
            ('.Append', '.append'),
            ('true', 'True'),
            ('false', 'False'),
        ]

        [replace_list.append((x[0], f'global {x[1]}; {x[0]}')) for x in re.findall(r'((.*) = )', new_data)]

        for variable in re.findall(r'([dD]im (.*) as (.*))', new_data):
            varname, vartype = variable[1].replace('()',''), variable[2].lower()[:3]
            if vartype == 'str':
                vartype = 'list'

            replace_list.append((variable[0], f'global {varname}; {varname} = {vartype}()'))

        [replace_list.append((x[0], f'[randint({x[1]},len({x[2]}))-1]')) for x in re.findall(r'(\(RndNumber\((.*), (.*)\.UBound\)\))', new_data)]

        for old, new in replace_list:
            new_data=new_data.replace(old, new)

        final = [
            'from random import randint',
            'global Headers; Headers = []',
        ]

        if not 'URL =' in new_data:
            final.append('global URL; URL = "$TARGETURL"')

        for line in new_data.splitlines():
            newline = line

            if '.append' in newline and not newline.endswith(')'): newline += ')'
            if line.startswith('//'): continue
            
            final.append(newline)

        self.final = '\n'.join(final)
        return self.final
    
    def args(self):
        exec(self.final) # execute the config, can be very dangerous

        try: targets = randURLs
        except: 
            try: targets = [URL]
            except: targets = None

        try: usepost = UsePost
        except: usepost = False

        try: postbuff = PostBuffer
        except: postbuff = None

        try: headers = Headers
        except: headers = None

        try: userAgents = useragents
        except: userAgents = None

        try: Referers = referers
        except: Referers = None

        try: randHeaders = randheaders
        except: randHeaders = None

        return {
            'target_url': targets,
            'method': 'POST' if usepost else 'GET',
            'post_buffer': postbuff,
            'headers': headers,
            'useragent_list': userAgents,
            'referer_list': Referers,
            'random_headers': randHeaders
        }