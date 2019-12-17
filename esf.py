import shodan
import time
import requests
import argparse
import configparser

from termcolor import colored

__license__ = "GPLv3"
__version__ = "1.0.0"
SHODAN_API_KEY ="Shodan_API_Key_here"

def banner():
    print('''
          ______  _____ ______ 
        |  ____|/ ____|  ____|
        | |__  | (___ | |__   
        |  __|  \___ \|  __|  
        | |____ ____) | |     
        |______|_____/|_|                                         
        ''')
    print(colored("Author: @Z4ck404"))
    print(colored("Version {} \n\n").format(__version__))

def parse_args():
    parser = argparse.ArgumentParser(formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument('-o','--output',
                        dest = "output",
                        help = "Name of the file where results will be stored.",
                        default = "es.txt",
                        required = False)
    parser.add_argument('-c','--country',
                        dest = "country",
                        help = "The country you want to scan.",
                        required = False)
    parser.add_argument('-k','--keyword',
                        dest = "keyword",
                        help = "add a keyword to your search like a specific indice name",
                        required = False)
    return parser.parse_args()

def write(entry, filename):
    out = open(filename, "a")
    out.write(entry + "\n")
    out.close()

def getHosts(filename):
    secret = configparser.RawConfigParser()
    secret.read('.env')
    api = shodan.Shodan(SHODAN_API_KEY)
    if parse_args().country is not None:
        query = 'port:9200 json country:'+ '"'+ str(parse_args().country)+'"'
    else:
        query = 'port:9200 json'
    try:
        for p in range(1, 2):
            results = api.search(query, page=p)
            for result in results['matches']:
                //print (result)
                host = str(result['ip_str'])
                print(colored("[+] INFO: Found " + host ,'green'))
                write(host, filename)
            time.sleep(1)
    except shodan.APIError as e:
        print('Error: {}'.format(e))
        pass

def main():
    banner()
    filename = parse_args().output
    getHosts(filename)

if __name__ == '__main__':
    main()
