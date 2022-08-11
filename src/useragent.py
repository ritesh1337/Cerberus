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

'''
Python module to generate random useragents
'''

from random import randint, choice
from json import load
from os.path import dirname, abspath, join

from src.core import *

with open(join(dirname(abspath(__file__)), 'files', 'agents.json'), buffering=Core.file_buffer) as file:
    agents = load(file)

def getAgent() -> str:
    '''
    getAgent() -> useragent

    Creates the useragent

    :returns str: Randomly created useragent
    '''

    agent = ''
    if not Core.useragent_list:

        browsers = ['chrome', 'firefox', 'opera', 'edge', 'explorer', 'brave']
        other = ['pyrequests','curl','wget', 'apt']

        agent = ''
        if randint(0,3) != 1:

            i = randint(0,3)
            if i == 0: agent = f'Mozilla/{choice(agents["mozilla"])}'
            elif i == 1 or i == 2: agent = f'Opera/{choice(agents["operav"])}'
            else: agent = 'Mozilla/5.0'

            browser = choice(browsers)

            if browser != 'explorer':
                agent = f'{agent} ({choice(agents["os"])})'

            if 'Opera' in agent:
                browser = 'opera'
                agent = f'{agent} Presto/{choice(agents["presto"])} Version/{choice(agents["opera"])}'

            else:
                if browser in ['opera', 'firefox']: agent = f'{agent} Gecko/{choice(agents["gecko"])}'
                elif browser == 'explorer': agent = f'{agent} ({choice(agents["os"])} Trident/{str(randint(1, 7))}.0)'
                else: agent = f'{agent} AppleWebKit/{choice(agents["kits"])} (KHTML, like Gecko)'

            if 'Gecko' in agent and browser == 'opera': agent = f'{agent} Opera {choice(agents["opera"])}'
            if browser == 'chrome': agent = f'{agent} Chrome/{choice(agents["chrome"])} Safari/{choice(agents["safari"])}'
            elif browser == 'firefox': agent = f'{agent} Firefox/{choice(agents["firefox"])}'
            elif browser == 'edge': agent = f'{agent} Chrome/{choice(agents["chrome"])} Safari/{choice(agents["safari"])} Edge/{choice(agents["edge"])}'
            elif browser == 'brave': agent = f'{agent} Brave Chrome/{choice(agents["chrome"])} Safari/{choice(agents["safari"])}'
            else: pass

        else:
            agent = {
                'pyrequests': f'python-requests/{choice(agents["pyrequests"])}',
                'curl': f'Curl/{choice(agents["curl"])}',
                'wget': f'Wget/{choice(agents["wget"])}',
                'apt': choice([f'Debian APT-HTTP/{choice(["0","1"])}.{str(randint(1,9))} ({choice(agents["apt"])})', f'Debian APT-HTTP/{choice(["0","1"])}.{str(randint(1,9))} ({choice(agents["apt"])}) non-interactive'])
            }[choice(other)]
    else:
        agent = choice(Core.useragent_list)

    return agent