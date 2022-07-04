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

# import all non-stdlib modules, just to check if they are actually installed
try:
    import requests # for sending the actual requests
    from colorama import Fore, init # fancy colors :O
    import cloudscraper # cloudflare bypass
    import argparse # needed for command line argument parsing
    import tabulate # pretty tables
    import dns.resolver # dns watertorture attack
    import websocket # websocket flooder
except Exception as e:
    print(' - Error, it looks like i\'m missing some modules. Did you try "pip install -r requirements"?')
    print(f' - Stacktrace: \n{str(e).rstrip()}')
    exit()

# import the standard library modules, should have no problems importing them
try:
    import sys # checking the python version
    import urllib # url parsing
    import threading # threaded attacks
    import json # parsing json, and creating json objects
    import time # delay between attacks and time calculation
    from random import choice # picking random stuff
    import netaddr # stuff with ip addresses
    import sqlite3 # database
    import textwrap # for the argparser module
    import ssl # secure socket layer stuff
    import asyncio # asynchronous stuff
    import re # regex
    from timeit import default_timer as timer
    from http.client import HTTPConnection # setting the "HTTP/" value
    from urllib3.exceptions import InsecureRequestWarning # to disable that annoying "Insecure request!" warning
except Exception as e:
    print(' - Error, failed to import standard library module.')
    print(f' - Stacktrace: \n{str(e).rstrip()}')
    exit()

if sys.version_info[0] < 3 and sys.version_info[1] < 6:
    sys.exit(' - Error, please run Cerberus with Python 3.6 or higher.') # now that we've import sys, we can exit and print with a single function, awesome!

# import all custom modules from the "src" directory
try:
    from src.utils import * # import all utilities
    from src.core import * # import the "bridge", basically used to store variables editable by all core modules
    from src.database import * # database stuff
    from src.argparser import *
    from src.methods import *
    from src.booster import *
except Exception as e:
    print(' - Error, failed to import core modules.')
    sys.exit(f' - Stacktrace: \n{str(e).rstrip()}')

# initialize colorama
init(autoreset=True) # makes it so i don't need to do Fore.RESET at the end of every print()
urllib3.disable_warnings(InsecureRequestWarning) # disables the warning

def main(args):
    if not args['target_url']: # check if the "-t/--target-url" argument has been passed
        sys.exit('\n - Please specify your target.\n')
    
    if ',' in args['target_url']: Core.targets = args['target_url'].split(',') # multiple targets specified
    else: Core.targets = args['target_url']
    
    if args['referer_list']:
        if ',' in args['referer_list']: Core.referer_list = args['referer_list'].split(',')
        elif args['referer_list'] != None:  Core.referer_list = args['referer_list']
        else: Core.referer_list = None
    else: Core.referer_list = None

    if args['useragent_list']:
        if ',' in args['useragent_list']: Core.useragent_list = args['useragent_list'].split(',')
        elif args['useragent_list'] != None: Core.useragent_list = args['useragent_list']
        else: Core.useragent_list = None
    else: Core.useragent_list = None

    if args['random_headers']:
        if ',' in args['random_headers']: Core.random_headers = args['random_headers'].split(',')
        elif args['random_headers'] != None: Core.random_headers = args['random_headers']
        else: Core.random_headers = None
    else: Core.random_headers = None

    attack_method = args['method'].upper()
    if not Core.methods.get(attack_method): # if the method does not exist
        sys.exit(f'\n - Error, method "{attack_method}" does not exist.\n')
    
    Core.bypass_cache = args['bypass_cache']
    Core.proxy_proto = args['proxy_proto']
    Core.attack_method = args['method']
    Core.post_buffer = args['post_buffer']

    if args['proxy_file']:
        Core.proxy_pool = []
        if not os.path.isfile(args['proxy_file']):
            sys.exit(f'\n - Error, "{args["proxy_file"]}" not found\n')
        
        with open(args['proxy_file'], buffering=(2048*2048)) as fd:
            [Core.proxy_pool.append(x.rstrip()) for x in fd.readlines() if bool(re.match(r'\d+\.\d+\.\d+\.\d+', x))] # sadly no ipv6 supported (yet)
        
        if Core.proxy_pool == []:
            sys.exit(f'\n - Error, no proxies collected, maybe wrong file?\n')

    print(' + Current attack configuration:')

    if not Core.targets: print(f'   - Target: {args["target_url"]}')
    else: print(f'   - Targets: {", ".join(Core.targets) if len(Core.targets) < 3 else len(Core.targets)}')
    
    if not Core.referer_list: print(f'   - Referer: randomly chosen')
    else: print(f'   - Referers: {", ".join(Core.referer_list) if len(Core.referer_list) < 3 else len(Core.referer_list)}')
    
    if not Core.useragent_list: print(f'   - Useragent: randomly chosen')
    else: print(f'   - Useragents: {", ".join(Core.useragent_list) if len(Core.useragent_list) < 3 else len(Core.useragent_list)}')

    if not Core.random_headers: print(f'   - Random headers: randomly chosen')
    else: print(f'   - Random headers: {", ".join(Core.random_headers) if len(Core.random_headers) < 3 else len(Core.random_headers)}')

    if args['headers']:
        headersdict = {}
        for header in args['headers']:
            key, value = header.split(':', 1)

            headersdict.update({key: value})

        Core.headers = headersdict
    
    if args['random_headers']:
        rand_headerslist = []
        for header in args['random_headers']:
            key, value = header.split(': ', 1)

            rand_headerslist.append({key: value})

        Core.random_headers = rand_headerslist

    print(f'   - Duration: {utils().Sec2Str(args["duration"])}')
    print(f'   - Workers: {str(args["workers"])}')
    print(f'   - Method/Vector: {args["method"]}')
    print(f'   - Cache bypass? {str(Core.bypass_cache)}')
    print(f'   - HTTP protocol version: {str(args["http_ver"])}')

    if args['proxy_file']:
        print(f'   - Proxies loaded: {str(len(Core.proxy_pool))}')
        print(f'   - Global proxy protocol: {str(Core.proxy_proto)}')

    if not args['yes_to_all']:
        if not input('\n + Correct? (Y/n) ').lower().startswith('y'):
            sys.exit('\n')

    if not args.get('IS_FROM_ID') and not args.get('IS_FROM_BOOSTER'): # skip if we are running the attack from a pre-existing id or from a hoic booster
        print('\n + Creating unique identifier for attack')
        tohash = args['target_url'] + str(args['duration']) + args['method'] + str(args['workers']) + str(args['bypass_cache']) + str(args['yes_to_all'])
        Core.attack_id = attack_id = hashlib.sha1(tohash.encode()).hexdigest()

        print('\n + Saving attack configuration in database')
        database().save_log({
            'timestamp': datetime.now().strftime('%m/%d/%Y, %H:%M:%S'),
            'target': args['target_url'],
            'referer': args['referer_list'],
            'useragent': args['useragent_list'],
            'duration': args['duration'],
            'attack_vector': args['method'],
            'workers': args['workers'],
            'proxy_file': args['proxy_file'],
            'proxy_proto': args['proxy_proto'],
            'bypass_cache': args['bypass_cache'],
            'yes_to_all': args['yes_to_all'],
            'http_ver': args['http_ver'],
            'rand_headers': args['rand_headers']
        })
    else:
        attack_id = args['UNIQUE_ATTACK_ID']
    
    print(f' + Attack ID: {attack_id}')
    Core.infodict[attack_id] = {
        'req_sent': 0, # requests sent (OPTIONAL)
        'req_fail': 0, # requests failed (OPTIONAL)
        'conn_opened': 0, # connections opened (OPTIONAL)
        'identities_changed': 0, # amount of times we switched identities (OPTINAL)
        'req_total': 0 # total amount of requests/packets sent (REQUIRED)
    }

    # before we create the session, we need to set the HTTP protocol version
    HTTPConnection._http_vsn_str = f'HTTP/{args["http_ver"]}'

    print(' + Creating requests session.')
    session = utils().buildsession()
    Core.session = session

    if not args['yes_to_all']:
        input('\n + Ready? (Press ENTER) ')

    print('\n + Building threads, this could take a while.')
    stoptime, threadbox = time.time() + args['duration'], []
    for _ in range(args["workers"]):
        try:
            kaboom = threading.Thread(
                target=Core.methods[Core.attack_method]['func'], # parse the function
                args=(
                    attack_id, # attack id
                    choice(Core.targets), # pick a random target from the list
                    stoptime, # stop time
                )
            )
            
            threadbox.append(kaboom)
            kaboom.start()
            Core.threadcount += 1

        except KeyboardInterrupt:
            Core.attackrunning = False
            Core.killattack = True
            sys.exit('\n + Bye!\n')
        
        except Exception as e:
            print(f' - Failed to launch thread: {str(e).rstrip()}')
    
    print('\n + Starting attack')
    Core.attackrunning = True # all threads have launched, lets start the attack

    s_start = timer()
    while 1:
        try:
            utils().clear()

            sent = str(Core.infodict[attack_id].get('req_sent'))
            failed = str(Core.infodict[attack_id].get('req_fail'))
            conn_opened = str(Core.infodict[attack_id].get('conn_opened'))
            total = str(Core.infodict[attack_id].get('req_total'))
            ids_changed = str(Core.infodict[attack_id].get('identities_changed'))
            threads = str(Core.threadcount)

            print(f'\n + Target(s): {", ".join(Core.targets)}')

            if sent != '0': print(f' + Requests sent: {sent}')
            if failed != '0': print(f' + Requests failed: {failed}')
            if conn_opened != '0': print(f' + Connections opened: {conn_opened}')
            if ids_changed != '0': print(f' + Identities changed: {ids_changed}')

            print(f' + Total: {total}')
            print(f' + Threads alive: {threads}')

            time.sleep(2)

        except KeyboardInterrupt:
            Core.attackrunning = False
            Core.killattack = True
            break
    
    utils().clear()
    if args["workers"] > 500:
        print(' + You selected a LOT of threads, this can take a long time. \nIf you want to just quit the progrem without ending the threads the proper way Press CTRL-C')
    
    print(' + Killing all threads, hold on.')
    for thread in threadbox:
        try: thread.join()
        except KeyboardInterrupt: sys.exit('\n + Bye!\n')
        except Exception as e: print(f' - Failed to kill thread: {str(e).rstrip()}')

    s_took = "%.2f" % (timer() - s_start) # count after we stopped all threads, because some threads might still be sending some rogue requests
    
    print(' + Threads killed')
    
    sent = str(Core.infodict[attack_id]['req_sent'])
    print(f' + Average Requests Per Second: {str(float(sent)/float(s_took))}')
    print(' + Attack finished.')

if __name__ == '__main__':
    utils().print_banner() # print banner

    if len(sys.argv) <= 1: # no arguments? just show all logs

        if len(database().get_logs()) == 0:
            print('\n - No running attacks.')

        else:
            print('\n' + utils().table(
                [(row['timestamp'], row['identifier'], row['target_url'], row['duration'], row['method'], row['bypass_cache'], row['yes_to_all'], row['http_ver']) for row in database().get_logs()], 
                ['Timestamp', 'ID', 'Target', 'Duration', 'Method', 'Bypass cache?', 'Skip prompts', 'HTTP version']
            ))

        print(f'\n\n + To view the commands, try this: python3 {sys.argv[0]} -h')
        print('\n + Tip: you can easily re-launch an attack by using the ID like this:')
        print(f'python3 {sys.argv[0]} --launch-from-id <attack id here>\n')

    else: # parse the arguments with argparse

        parser = ArgumentParser(width=100, description='''Cerberus is a layer 7 network stress testing tool that has a wide variety of normal and exotic attack vectors.
    It's written in Python3 and is usable on all systems with Python installed.''',
                                epilog='''Copyright (c) 2022 Nexus/Nexuzzzz

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
    ''', argument_default=argparse.SUPPRESS, allow_abbrev=False)

        # add arguments
        parser.add_argument('-t',       '--target',          action='store',      dest='target_url',    metavar='target url(s)',    type=str,  help='Target url(s) to attack, seperated by ","', default=None)
        parser.add_argument(            '--referers',        action='store',      dest='referer_list',  metavar='referer(s)',       type=str,  help='Referer(s) to use when attacking, seperated by ","', default=None)
        parser.add_argument(            '--useragents',      action='store',      dest='useragent_list',metavar='useragent(s)',     type=str,  help='Useragent(s) to use when attacking, seperated by ","', default=None)
        parser.add_argument('-d',       '--attack-duration', action='store',      dest='duration',      metavar='duration',         type=int,  help='Attack length in seconds', default=100)
        parser.add_argument('-w',       '--workers',         action='store',      dest='workers',       metavar='workers',          type=int,  help='Number of threads/workers to spawn', default=40)
        parser.add_argument('-m',       '--method',          action='store',      dest='method',        metavar='method',           type=str,  help='Attack method/vector to use', default='GET')
        parser.add_argument(            '--proxy-file',      action='store',      dest='proxy_file',    metavar='location',         type=str,  help='Location of the proxy file to use', default=None)
        parser.add_argument(            '--proxy-proto',     action='store',      dest='proxy_proto',   metavar='protocol',         type=str,  help='Proxy protocol (SOCKS4, SOCKS5, HTTP)', default='SOCKS5')
        parser.add_argument('-logs',    '--list-logs',       action='store_true', dest='list_logs',                                            help='List all attack logs', default=False)
        parser.add_argument('-methods', '--list-methods',    action='store_true', dest='list_methods',                                         help='List all the attack methods', default=False)
        parser.add_argument('-bc',      '--bypass-cache',    action='store_true', dest='bypass_cache',                                         help='Try to bypass any caching systems to ensure we hit the main servers', default=True)
        parser.add_argument('-y',       '--yes-to-all',      action='store_true', dest='yes_to_all',                                           help='Skip any user prompts, and just launch the attack', default=False)
        parser.add_argument(            '--http-version',    action='store',      dest='http_ver',      metavar='http version',     type=str,  help='Set the HTTP protocol version', default='1.1')
        parser.add_argument('-id',      '--launch-from-id',  action='store',      dest='launch_from_id',metavar='attack id',        type=str,  help='Attack ID to use, to parse attack configuration from', default=None)
        parser.add_argument(            '--hoic-booster',    action='store',      dest='hoic_booster',  metavar='location',         type=str,  help='HOIC booster file to use when attacking, can result in malicious code execution so make sure its clean!', default=None)
        parser.add_argument(            '--post-data',       action='store',      dest='post_buffer',   metavar='data',             type=str,  help='Data to send with POST floods', default=None)
        parser.add_argument(            '--rand-headers',    action='store',      dest='rand_headers',  metavar='random header(s)', type=str,  help='Random header(s) to choose when attacking, seperated by ","', default=None)
        args = vars(parser.parse_args()) # parse the arguments

        if args['list_logs']:

            if len(database().get_logs()) == 0:
                print('\n - No running attacks.')

            else:
                print('\n' + utils().table(
                    [(row['timestamp'], row['identifier'], row['target_url'], row['duration'], row['method'], row['bypass_cache'], row['yes_to_all'], row['http_ver']) for row in database().get_logs()], 
                    ['Timestamp', 'ID', 'Target', 'Duration', 'Method', 'Bypass cache?', 'Skip prompts', 'HTTP version']
                ))

            print('\n\n + Tip: you can easily re-launch an attack by using the ID like this:')
            sys.exit(f' + python3 {sys.argv[0]} --launch-from-id <attack id here>\n')
        
        if args['list_methods']:
            print('\n')

            for method, items in Core.methods.items():
                print(f'{method}: {items["info"]}')

            sys.exit('\n')
        
        if args['hoic_booster']:
            booster_path = args['hoic_booster']
            if not os.path.isfile(booster_path):
                sys.exit(f'\n - Could not find "{booster_path}"\n')

            print('\n + Parsing booster file')
            booster = Booster(booster_path)

            booster.get()
            args.update(booster.args())

            args['IS_FROM_BOOSTER'] = True
            args['UNIQUE_ATTACK_ID'] = utils().make_id()

        if args['launch_from_id']: # id has been specified
            attack_id = args['launch_from_id']
            print(f' + Parsing attack configuration from ID {attack_id}')

            args = database().get_log(attack_id)
            args['IS_FROM_ID'] = True
            args['UNIQUE_ATTACK_ID'] = attack_id
        
        main(args)