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
Python module to generate random referers
'''

from random import randint, choice
from os.path import dirname, abspath, join

from src.core import *

with open(join(dirname(abspath(__file__)), 'files', 'referers.txt'), buffering=Core.file_buffer) as file:
    referers = file.read().splitlines()

def getReferer() -> str:
    '''
    getRefefer() -> str

    Creates the random referer

    :returns str: Randomly picked referer
    '''
    
    return choice([
        choice(['http://', 'https://']) +  '.'.join([str(randint(1,255)) for _ in range(4)]), # sadly we can't use utils().genip here, due to circular imports
        choice(referers).rstrip() # pick one from the referers.txt file
    ]) if not Core.referer_list else choice(Core.referer_list)