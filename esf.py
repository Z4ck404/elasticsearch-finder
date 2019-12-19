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

ddef parse_args():
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

def write(entries, filename):
    out = open(filename, "a")
    out.writelines(entries)
    out.close()

def getHosts(filename):
    api = shodan.Shodan(SHODAN_API_KEY)
    if parse_args().country is not None:
        query = 'port:9200 json country:'+ '"'+ str(parse_args().country)+'"'
    else:
        query = 'port:9200 json'
    try:
        for p in range(1, 150):
            results = api.search(query, page=p)
            for result in results['matches']:
                host = str(result['ip_str'])
                print(colored("[+] INFO: Found " + host ,'green'))
                try:
                    cluster_name = result['elastic']['cluster']['cluster_name']
                    status = result['elastic']['cluster']['status']
                    data = result['data']
                    number_nodes = result['elastic']['cluster']['_nodes']['total']
                    if data.find('kibana') != -1 :
                        print(colored("[++] kibana is found", "magenta"))
                    else:
                        print(colored("[--] kibana is  not found", "magenta"))
                    print("cluster name : ", cluster_name)
                    print("status : ", colored(status,status))
                    print("number of nodes : ", number_nodes)
                    print (data[data.find('Elastic Indices'):])
                    write([host + "\n",cluster_name+ "\n",status+ "\n",data[data.find('Elastic Indices'):]," ----- \n"], filename)
                except KeyError as e:
                    write([host + " ----- \n"], filename)
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
