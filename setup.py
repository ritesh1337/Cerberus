import os, sys, re, requests, zipfile

if sys.version_info[0] < 3 and sys.version_info[1] < 9:
    sys.exit(' - Error, please run the setup with Python 3.9 or higher.')

def main() -> None:
    '''
    main() -> none

    Main function

    :returns None: Nothing
    '''

    print('Setting Cerberus up, please be patient...')

    print(' + Installing python depencies')
    os.system('python3 -m pip install -r requirements.txt')

    print(' + Downloading TOR')
    tor_path = os.path.join('src','files','tor.zip')
    if os.name == 'nt':
        # grab the most recent download to the TOR bundle
        download_url = re.findall(
            r'<a class=\"downloadLink\" href=\"(.*?)\">Download</a>', 
            requests.get('https://www.torproject.org/download/tor/').text
        )[0].replace('/dist/','')

        with requests.get(f'https://dist.torproject.org/{download_url}', stream=True) as req:
            with open(tor_path, 'wb', buffering=(16*1024*1024)) as fd:
                fd.write(req.content)
        
        with zipfile.ZipFile(tor_path, "r") as zip_ref:
            zip_ref.extract('Tor/tor.exe', os.path.join('src','files')) # this will extract it to "/src/files/Tor/tor.exe"
    else:
        os.system('sudo apt install tor -y')

    print(' + Cleaning up.')
    os.system('sudo apt autoremove -y; sudo apt autoclean -y')
    if os.name == 'nt': os.remove(tor_path)

    print(' + Done')

if __name__ == '__main__':
    main()