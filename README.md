```
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
                SP          SP                  SP                                 
                Y           Y                   Y                                  
```                                                                                

<!-- yes i did steal some of these from MHDDoS, lel -->
<p align="center">
    <img alt="button-code-size-mb" src="https://img.shields.io/github/languages/code-size/Nexuzzzz/Cerberus" />
    <img alt="button-license" src="https://img.shields.io/github/license/Nexuzzzz/Cerberus">
    <img alt="button-file-count" src="https://img.shields.io/github/directory-file-count/Nexuzzzz/Cerberus">
    <img alt="button-forks" src="https://img.shields.io/github/forks/Nexuzzzz/Cerberus">
    <img alt="button-stars" src="https://img.shields.io/github/stars/Nexuzzzz/Cerberus">
    <img alt="button-issues" src="https://img.shields.io/github/issues/Nexuzzzz/Cerberus">
    <img alt="button-last-commit" src="https://img.shields.io/github/last-commit/Nexuzzzz/Cerberus/main">
</p>

# Cerberus
Cerberus is a layer 7 network stress testing tool that has a wide variety of normal and exotic attack vectors. <br>
It's written in Python (3.10) and is usable on all systems with Python installed.

# Attack methods/vectors
```
GOLDENEYE: GoldeneEye dos tool, written by Jan Seidl
MIX: HTTP flood that randomly picks a http method
PROXY: HTTP GET flood, using a specified file with proxies
TORSHAMMER: Slowloris attack using the TOR network
ARME: HTTP Apache Remote Memory Exhaustation (ARME) flood
HEAD: HTTP HEAD flood
SLOWLORIS: Low and slow attack that eats up the connection pool of the target
APACHEDOS: Exploit which abuses a vulnerability which targets Apache 2.2.x
OVERLOAD: HTTP GET flood that fills the headers dictionary with lots of junk data
FAST: HTTP GET flood that just targets "/", good for volumetric attacks
WEBSOCK: Websocket flood, supports SSL (wss://)
XMLRPC: Reflection attack abusing XML-RPC pingback endpoints
WATERTORTURE: DNS watertorture attack
COOKIE: HTTP GET flood with large cookies, tasty!
LEECH: Exotic bandwidth draining flood, keep the thread count below <5 and use residential proxies for better results
RECURSIVE: Recursive HTTP GET flood, very nasty
GHP: HTTP GET/HEAD/POST flood
BLAZINGFAST: Blazingfast bypass, impersonates the analytics bot which is allowed by default. Credits to 0x44F and mSQL
CLOUDFLARE: Cloudflare UAM/IUAM bypass using cloudscraper
SUBDOMAIN: A Cloudflare bypass attack, which checks for unprotected subdomains
POST: HTTP POST flood
XERXES: TCP connection flood, abusing the TOR network
HULK: HTTP Unbearable Load King
TOR2WEB: HTTP GET flood abusing Tor 2 Web proxies
MIMICK: HTTP GET flood that impersonates common web scrapers like Googlebot, Yahoo! Slurp or BaiduSpider
CONNECT: HTTP CONNECT flood
TOR: HTTP GET flood abusing Tor 2 Web proxies
DDG: HTTP GET DDoSGuard bypass
OPENREDIRECT: HTTP flood which abuses the Open Redirect vulnerability
HEX: HTTP GET flood that has a huge HEX string in the Host: header
GET: HTTP GET flood
```

# Notes
- CLOUDFLARE attack can't solve v2 challenges
- SUBDOMAIN attack is very slow, will look into speeding that up in the future
- XMLRPC needs a reflector list
- XERXES attack might be a bit unstable

# Usage
1. Clone the repository
```
git clone https://github.com/Nexuzzzz/Cerberus
```

2. Install the depencies
```
python3 setup.py
```

3. Run the tool
```
python3 main.py --help
```

4. Profit.

# Depencies
- Python 3.10
- Everything can be installed with the `setup.py` script:
    - `python3 setup.py`

# Contributing
You can support this project by:
 - Creating a new method, more information can be found in `src/methods`
 - Opening a pull request
 - Making an issue with a new idea, a code enhancement or anything else. I'll gladly look into them.
 - Donating to me:
    <!--Monero FTW-->
    - With Monero/XMR: `4BFpJ8hEUBBUE8vKUq6arUhRNkmQbPFMG38tDJHroAiTcENF2oCjYgoeHRJg6ULcs42EZ1ynCGj6RVhBTBQ3BcRmKAP1ZRb`
    - With Bitcoin/BTC: `bc1qp8k7yltrc446c4ywyu0uyplkcp2s5ejmx9d2c`
    - With Litecoin/LTC: `ltc1qkyc5s7nkpgthdjfdfcnqjevrkjz79r4jc05nkd`

# License
```sh
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
```