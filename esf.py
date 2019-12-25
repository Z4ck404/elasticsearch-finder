import shodan
import time
import requests
import argparse
from termcolor import colored
from hurry.filesize import size
from colorama import Fore
import json
import sys
import argparse
from bs4 import BeautifulSoup
import requests
from pybinaryedge import BinaryEdge
from urllib.parse import urlparse
from datetime import datetime
__license__ = "GPLv3"
__version__ = "1.0.0"
SHODAN_API_KEY =""
BINARYEDGE_API_KEY = ''
be = BinaryEdge(BINARYEDGE_API_KEY)
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

def reverse_dns(ip):
    api = shodan.Shodan(SHODAN_API_KEY)
    info = api.host(ip)['org']
    return info
def parse_args():
    parser = argparse.ArgumentParser(formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument('-o','--output',
                        dest = "output",
                        help = "Name of the file where results will be stored. Default will be es(timedate).txt",
                        required = False)
    parser.add_argument('-c','--country',
                        dest = "country",
                        help = "The country you want to scan.",
                        required = False)
    parser.add_argument('-k','--keyword',
                        dest = "keyword",
                        help = "add a keyword to your search like a specific indice name",
                        required = False)
    parser.add_argument('-f','--first',
                        dest = "first",
                        help = "the first page to check for binary edge, default will be 1",
                        default= 1,
                        type= int,
                        required = False)
    parser.add_argument('-l','--last',
                        dest = "last",
                        help = "the last page to check for binary edge, default will be 3",
                        default= 3,
                        type= int,
                        required = False)
    parser.add_argument('-s','--shodan',
                        action='store_true',
                        dest="shodan",
                        help = "pull data from shodan")
    parser.add_argument('-b','--be',
                        dest="binaryedge",
                        action='store_true',
                        help = "pull data from binary edge")
    return parser.parse_args()

def write(entries, filename):
    out = open(filename, "a")
    out.writelines(entries)
    out.close()

def output_name(output):
    now = datetime.now()
    dt_string = now.strftime("%d%m%Y%H%M%S")
    filename = "es" + dt_string +".txt"
    if parse_args().output is not None : 
        filename = output
    return filename
    
def binaryedge_query(query,page):
    headers = {'X-Key': BINARYEDGE_API_KEY}
    end = 'https://api.binaryedge.io/v2/query/search?query='+query+'&page='+str(page)
    req = requests.get(end,headers=headers)
    req_json = json.loads(req.content)
    try:
        print("Total results: " + Fore.GREEN + str(req_json['total']) + Fore.RESET)
    except:
        print("Error with your query")
        print(req_json)
        sys.exit()

    return req_json['events']

def getHosts_binaryedge(first,last,filename):
    for page in range(first, last) :
        if parse_args().country is not None:
            query = "type:%22elasticsearch%22" +" " + "country:"+'"'+ str(parse_args().country)+'"'
        else:
            query = "type:%22elasticsearch%22" +" "
        elastic_results = binaryedge_query(query,page)
        for service in elastic_results:
                #print (service)
                #print('http://' + service['target']['ip'] + ":" + str(service['target']['port']) + "/_cat/indices")
                host = service['target']['ip']
                port_number = str(service['target']['port'])
                country = service['origin']['country']
                cluster_name = service['result']['data']['cluster_name']
                #organization = reverse_dns(host)
                organization = "test"
                number_nodes = service['result']['data']['cluster_nodes']
                print(colored("[+] INFO: Found " + host ,'green'))
                print("Port number :",port_number)
                print("Source : BinaryEdge ")
                print ("country : ", country)
                print("Cluster name: ",cluster_name)
                print ("organization :", organization)
                print("number of nodes : ",number_nodes)
                print("Elastic Indices :")
                sizee = 0
                indices = []
                try:
                    for indice in service['result']['data']['indices']:
                        #indices that have more than 1Gb od data ! 
                        #if indice['size_in_bytes'] > 1000000000:
                        print("Name: " + Fore.GREEN + indice['index_name'] + Fore.RESET)
                        indices.append(indice['index_name'])
                        print("No. of documents: " +Fore.BLUE + str(indice['docs']) + Fore.RESET)
                        print("Size: " + Fore.LIGHTCYAN_EX + str(size(indice['size_in_bytes'])) + Fore.RESET)
                        sizee = sizee + indice['size_in_bytes']
                    print ("cluster size : ",size(sizee))
                except:
                    print("No indices")
                write( ["host:" + host + "\n", 
                "source : binary edge" + "\n", 
                "cluster name :" + cluster_name+ "\n",
                "organization :"+ organization +"\n",
                " number of nodes : "+ str(number_nodes)+ "\n",
                "size of the cluster :"  + str(size(sizee)) + "\n",
                "indices" + str(indices)," \n ----------------------------- \n"], filename)
                print(" \n ----------------------------- \n")

        break
def getHosts_shodan(filename):
    api = shodan.Shodan(SHODAN_API_KEY)
    if parse_args().country is not None:
        query = 'port:9200 json country:'+ '"'+ str(parse_args().country)+'"'
    else:
        query = 'port:9200 json'
    try:
        for p in range(1, 150):
            results = api.search(query, page=p)
            for result in results['matches']:
                #print(result)
                host = str(result['ip_str'])
                print(colored("[+] INFO: Found " + host ,'green'))
                try:
                    cluster_name = result['elastic']['cluster']['cluster_name']
                    port_number = 9200
                    source = "shodan"
                    status = result['elastic']['cluster']['status']
                    data = result['data']
                    country = result['location']['country_code']
                    number_nodes = result['elastic']['cluster']['nodes']['count']['total']
                    organization = result['org']
                    sizee = size(result['elastic']['cluster']['indices']['store']['size_in_bytes'])
                    print("Port number :",port_number)
                    print("Source :",source)
                    print ("country : ",country)
                    print("cluster name : ", cluster_name)
                    print ("organization : ", organization)
                    print("status : ", colored(status,status))
                    print ("cluster size : ",sizee)
                    print("number of nodes : ", number_nodes)
                    print (data[data.find('Elastic Indices'):])
                    print("-----------------------------")
                     write( ["host:" + host + "\n", 
                    "source : binary edge" + "\n", 
                    "cluster name :" + cluster_name+ "\n",
                    "organization :"+ organization +"\n",
                    " number of nodes : "+ str(number_nodes)+ "\n",
                    "size of the cluster :"  + str(size(sizee)) + "\n",
                    "indices" + data[data.find('Elastic Indices'):]," \n ----------------------------- \n"], filename)
                except KeyError as e:
                    print (e)
                    pass
            time.sleep(1)
            break
    except shodan.APIError as e:
        print('Error: {}'.format(e))
        pass

def main():
    banner()
    filename = output_name(parse_args().output)
    first = parse_args().first
    last = parse_args().last
    shodan = parse_args().shodan
    be = parse_args().binaryedge
    
    if ((not shodan) and (not be)) :
        print("Please specify a data source by adding -s and/or -b")
        sys.exit()
    #if shodan :
        #getHosts_shodan(filename)
    if be:
        getHosts_binaryedge(first,last,filename)
   
if __name__ == '__main__':
    main()
