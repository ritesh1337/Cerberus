import os, sys

if sys.version_info[0] < 3 and sys.version_info[1] < 6:
    sys.exit(' - Error, please run the setup with Python 3.6 or higher.')

def main():
    '''
    Main function
    '''

    print('Setting Cerberus up, please be patient...')

    print(' + Installing python depencies')
    os.system('python3 -m pip install -r requirements.txt')

    print(' + Cleaning up.')
    os.system('sudo apt autoremove -y; sudo apt autoclean -y')

    print(' + Done')

if __name__ == '__main__':
    main()