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

import os, sqlite3

from src.core import *
from src.utils import *

class database():
    def __init__(self):
        self.db, self.cursor = None, None
        self.connect()
    
    def connect(self) -> None:
        '''
        connect() -> nothing

        Sets the SQLite3 database, and cursor for future usage

        :returns None: Nothing
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
        disconnect() -> nothing

        Disconnects from the database

        :returns None: Nothing
        '''

        if not self.db:
            return

        self.db.commit()
        self.db.close()
    
    def query(self, query, args=None, commit=False) -> list:
        '''
        query(query, extra arguments, commit after finished) -> list

        Executes a single query

        :param query str: Query to execute
        :param args tuple: Tuple of arguments to pass
        :param commit bool: Wether to commit when finished
        :returns list: Output
        '''

        output = []
        with Core.threadLock:
            output = self.cursor.execute(query) if not args else self.cursor.execute(query, args)

            if commit:
                self.db.commit()

        return output
    
    def make(self) -> None:
        '''
        make() -> nothing

        Creates a new database

        :returns None: Nothing
        '''

        with open(os.path.join('database', 'db.db'), 'w+', buffering=Core.file_buffer) as fd: # first, we create the file
            pass

        self.connect() # then we connect

        # and now we make the tables
        self.query('''CREATE TABLE logs (timestamp txt,
            identifier txt,
            target_url txt,
            referer txt,
            useragent txt,
            duration int,
            method txt,
            workers int,
            proxy_file str,
            proxy_proto str,
            bypass_cache bool,
            yes_to_all bool,
            http_ver str,
            random_headers str
        )''', commit=True)

        self.disconnect() # and finally we disconnect
    
    def parse_log(self, log) -> dict:
        '''
        parse_log(log tuple) -> dictionary

        Parses a log into a nice and easy to edit dictionary

        :param log tuple: Tuple of items
        :returns dict: Parsed dictionary
        '''

        return {
            'timestamp': utils().unix2posix(log[0]), # converts the timestamp from a unix one, to a human readable one
            'identifier': log[1], # attack identifier
            'target_url': log[2], # target url(s)
            'referer_list': log[3], # referer(s)
            'useragent_list': log[4], # useragent(s)
            'duration': log[5], # attack duration
            'method': log[6], # method
            'workers': log[7], # amount of threads
            'proxy_file': log[8], # file with proxies
            'proxy_proto': log[9], # proxy protocol
            'bypass_cache': log[10] == 1, # bypass caching systems
            'yes_to_all': log[11] == 1, # ignore prompts
            'http_ver': str(log[12]), # http version
            'random_headers': log[13] # random other headers
        }
    
    def save_log(self, log) -> None:
        '''
        save_log(log dictionary) -> nothing

        Saves a dictionary into the database

        :param log dictionary: Dictionary with items
        :returns None: Nothing
        '''

        self.query(
            'INSERT INTO logs VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)', # query
            (
                utils().posix2unix(log['timestamp']), 
                Core.attack_id, 
                log['target'],
                log['referer'],
                log['useragent'],
                log['duration'],
                log['attack_vector'], 
                log['workers'],
                log['proxy_file'],
                log['proxy_proto'],
                log['bypass_cache'],
                log['yes_to_all'],
                log['http_ver'],
                log['random_headers']
            ), # arguments
            True # save after we insert this data in the table
        )
    
    def get_logs(self) -> list:
        '''
        get_logs() -> list of logs

        Gets all the logs from the database

        :returns list: List of logs
        '''

        if self.db is None: # maybe not connected yet
            self.connect()

        logs = []
        for row in self.query('SELECT * FROM logs').fetchall():
            logs.append(self.parse_log(row))
        
        return logs
    
    def get_log(self, identifier) -> list:
        '''
        get_log(log identifier) -> list

        Gets a single log from the database

        :param identifier str: The logs unique identifier
        :returns list: List of logs that matched the identifier
        '''

        if self.db is None:
            self.connect()

        logs = []
        for row in self.query('SELECT * FROM logs WHERE identifier=?', (identifier,)).fetchall():
            logs.append(self.parse_log(row))
        
        return logs[0]