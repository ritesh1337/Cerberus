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

import os, sqlite3, hashlib
from src.core import *
from src.utils import *

class database():
    def __init__(self):
        self.db, self.cursor = None, None
        self.connect()
    
    def connect(self) -> object:
        '''
        Returns a sqlite database object, and cursor object
        '''

        if not os.path.isfile(os.path.join('database', 'db.db')):
            print('Failed to find database, making one.')
            self.make()

        self.db = sqlite3.connect(os.path.join('database', 'db.db'), check_same_thread=False)
        self.cursor = self.db.cursor()

        self.cursor.execute("PRAGMA journal_mode = WAL")
        self.cursor.execute("PRAGMA synchronous = OFF")
        self.cursor.execute("PRAGMA cache_size = -40960")
    
    def disconnect(self) -> None:
        '''
        Disconnects from the database
        '''

        self.db.commit()
        self.db.close()
    
    def query(self, query, args=None, commit=False) -> list:
        '''
        Executes a single query
        '''
        with Core.threadLock:
            output = self.cursor.execute(query) if args is None else self.cursor.execute(query, args)

            if commit:
                self.db.commit()
        return output
    
    def make(self) -> None:
        '''
        Creates a new database
        '''

        with open(os.path.join('database', 'db.db'), 'w+') as fd: # first, we create the file
            pass

        self.connect() # then we connect

        # and now we make the tables
        self.query('''CREATE TABLE logs (timestamp txt,
            identifier txt,
            target_url txt,
            duration int,
            method txt,
            workers int,
            proxy_file str,
            proxy_proto str,
            bypass_cache bool,
            yes_to_all bool,
            http_ver str
        )''', commit=True)

        self.disconnect() # and finally we disconnect
    
    def parse_log(self, log) -> dict:
        '''
        Parses a log into a nice and easy2edit dictionary
        '''

        return {
            'timestamp': utils().unix2posix(log[0]), # converts the timestamp from a unix one, to a human readable one
            'identifier': log[1], # attack identifier
            'target_url': log[2], # target url(s)
            'duration': log[3], # attack duration
            'method': log[4], # method
            'workers': log[5], # amount of threads
            'proxy_file': log[6], # file with proxies
            'proxy_proto': log[7], # proxy protocol
            'bypass_cache': log[8] == 1, # bypass caching systems
            'yes_to_all': log[9] == 1, # ignore prompts
            'http_ver': str(log[10]) # http versiom
        }
    
    def save_log(self, log) -> None:
        '''
        Saves a dictionary into the database
        '''

        self.query(
            'INSERT INTO logs VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)', # query
            (
                utils().posix2unix(log['timestamp']), 
                Core.attack_id, 
                log['target'],
                log['duration'],
                log['attack_vector'], 
                log['workers'],
                log['proxy_file'],
                log['proxy_proto'],
                log['bypass_cache'],
                log['yes_to_all'],
                log['http_ver']
            ), # arguments
            True # save after we insert this data in the table
        )
    
    def get_logs(self) -> list:
        '''
        Gets all the logs from the database
        '''

        if self.db is None: # maybe not connected yet
            self.connect()

        logs = []
        for row in self.query('SELECT * FROM logs').fetchall():
            logs.append(self.parse_log(row))
        
        return logs
    
    def get_log(self, identifier) -> tuple:
        '''
        Gets a single log from the database
        '''

        if self.db is None:
            self.connect()

        logs = []
        for row in self.query('SELECT * FROM logs WHERE identifier=?', (identifier,)).fetchall():
            logs.append(self.parse_log(row))
        
        return logs[0]