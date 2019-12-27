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
import xlsxwriter
__version__ = "1.0.1"
SHODAN_API_KEY =""
BINARYEDGE_API_KEY = ''
be = BinaryEdge(BINARYEDGE_API_KEY)
def banner():
    print('''

            ___________       ___________   ______  __________ 
           / ____/ ___/      / ____/  _/ | / / __ \/ ____/ __ 
          / __/  \__ \______/ /_   / //  |/ / / / / __/ / /_/ /
         / /___ ___/ /_____/ __/ _/ // /|  / /_/ / /___/ _, _/ 
        /_____//____/     /_/   /___/_/ |_/_____/_____/_/ |_|  

     **** Find elastic search instances available in the web ****                                                                               
        ''')
        
    print(colored("Author: Zakaria EL BAZI (@Z4ck404)", "magenta"))
    print(colored("Version {} \n\n", "magenta").format(__version__))

def reverse_dns(ip):
    api = shodan.Shodan(SHODAN_API_KEY)
    hoster = api.host(ip)['org']
    organization = 'unkown'
    result = api.host(ip)
    for element in result['data'] :
        #print (element)
        if element['port'] == 443 :
            organization = element['ssl']['cert']['subject']['CN']
            break
    return hoster,organization

#export data to excel :
def create_workbook(filename):
    name = str(filename) + ".xlsx"
    return xlsxwriter.Workbook(name)
#separate shodan and binary edge data in different sheets :
def create_worksheet(workbook,worksheet_name):
    worksheet = workbook.add_worksheet(str(worksheet_name))
    bold = workbook.add_format({'bold': 1})
    worksheet.set_column(1, 1, 15)
    worksheet.write('A1', 'Host IP', bold)
    worksheet.write('B1', 'Port number', bold)
    worksheet.write('C1', 'Source', bold)
    worksheet.write('D1', 'Country', bold)
    worksheet.write('E1', 'Cluster name', bold)
    worksheet.write('F1', 'Hosting provider', bold)
    worksheet.write('G1', 'organization', bold)
    worksheet.write('H1', 'Number of nodes', bold)
    worksheet.write('I1', 'Cluster size', bold)
    worksheet.write('J1', 'Indices', bold)
    return worksheet

def parse_args():
    parser = argparse.ArgumentParser(formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument('-o','--output',dest = "output",help = "Name of the file where results will be stored. Default will be es(timedate).txt",required = False)
    parser.add_argument('-c','--country', dest = "country",help = "The country you want to scan.",required = False)
    parser.add_argument('-k','--keyword',dest = "keyword",help = "add a keyword to your search like a specific indice name",required = False)
    parser.add_argument('-f','--first', dest = "first",help = "the first page to check for binary edge, default will be 1",default= 1,type= int, required = False)
    parser.add_argument('-l','--last',dest = "last",help = "the last page to check for binary edge, default will be 3",default= 2,type= int,required = False)
    parser.add_argument('-s','--shodan',action='store_true',dest="shodan", help = "pull data from shodan")
    parser.add_argument('-b','--be',dest="binaryedge",action='store_true',help = "pull data from binary edge")
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

def getHosts_binaryedge(first,last,filename,workbook):
    worksheet = create_worksheet(workbook,'binaryedge')
    for page in range(first, last) :
        if parse_args().country is not None:
            query = "type:%22elasticsearch%22" +" " + "country:"+'"'+ str(parse_args().country)+'"'
        else:
            query = "type:%22elasticsearch%22" +" "
        elastic_results = binaryedge_query(query,page)
        row = 1
        for service in elastic_results:
                #print (service)
                #print('http://' + service['target']['ip'] + ":" + str(service['target']['port']) + "/_cat/indices")
                host = service['target']['ip']
                port_number = str(service['target']['port'])
                country = service['origin']['country']
                cluster_name = service['result']['data']['cluster_name']
                hoster = reverse_dns(host)[0]
                #hoster = "test"
                organization = reverse_dns(host)[1]
                #organization = "test"
                number_nodes = service['result']['data']['cluster_nodes']
                print(colored("[+] INFO: Found " + host ,'green'))
                print("Port number :",port_number)
                print("Source : BinaryEdge ")
                print ("country : ", country)
                print("Cluster name: ",cluster_name)
                print ("hosting provider :", hoster)
                print ("organization :", organization)
                print("number of nodes : ",number_nodes)
                print("Elastic Indices :")
                sizee = 0
                indices = []
                try:
                    for indice in service['result']['data']['indices']:
                        #indices that have more than 1Gb od data ! 
                        if indice['size_in_bytes'] > 1000000000:
                            print("Name: " + Fore.GREEN + indice['index_name'] + Fore.RESET)
                            indices.append(indice['index_name'])
                            print("No. of documents: " +Fore.BLUE + str(indice['docs']) + Fore.RESET)
                            print("Size: " + Fore.LIGHTCYAN_EX + str(size(indice['size_in_bytes'])) + Fore.RESET)
                        sizee = sizee + indice['size_in_bytes']
                    print ("cluster size : ",size(sizee))
                except:
                    print("No indices")
                worksheet.write(row, 0,host)
                worksheet.write(row, 1,port_number)
                worksheet.write(row, 2,"binary edge")
                worksheet.write(row, 3,country)
                worksheet.write(row, 4,cluster_name)
                worksheet.write(row, 5,hoster)
                worksheet.write(row, 6,organization)
                worksheet.write(row, 7,number_nodes)
                worksheet.write(row, 8,str(size(sizee)))
                worksheet.write(row, 9,str(indices))
                row = row + 1
                write( ["host:" + host + "\n", 
                "Port number :" + port_number+ "\n",
                "source : binary edge" + "\n", 
                "cluster name :" + cluster_name+ "\n",
                "hosting provider :"+ hoster +"\n",
                "organization :"+ organization +"\n",
                "number of nodes : "+ str(number_nodes)+ "\n",
                "size of the cluster :"  + str(size(sizee)) + "\n",
                "indices" + str(indices)," \n ----------------------------- \n"], filename)
                print(" \n ----------------------------- \n")

        break
def getHosts_shodan(filename,workbook):
    api = shodan.Shodan(SHODAN_API_KEY)
    worksheet = create_worksheet(workbook,'shodan')
    if parse_args().country is not None:
        query = 'port:9200 json country:'+ '"'+ str(parse_args().country)+'"'
    else:
        query = 'port:9200 json'
    try:
        for p in range(1, 150):
            results = api.search(query, page=p)
            row = 1
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
                    #organization = result['org']
                    organization = reverse_dns(host)[1]
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
                    "Port number :" + port_number+ "\n",
                    "source : Shodan" + "\n", 
                    "cluster name :" + cluster_name+ "\n",
                    "organization :"+ organization +"\n",
                    " number of nodes : "+ str(number_nodes)+ "\n",
                    "size of the cluster :"  + str(size(sizee)) + "\n",
                    "indices" + data[data.find('Elastic Indices'):]," \n ----------------------------- \n"], filename)
                    worksheet.write(row, 0,host)
                    worksheet.write(row, 1,port_number)
                    worksheet.write(row, 2,"shodan")
                    worksheet.write(row, 3,country)
                    worksheet.write(row, 4,cluster_name)
                    worksheet.write(row, 5,"")
                    worksheet.write(row, 6,organization)
                    worksheet.write(row, 7,number_nodes)
                    worksheet.write(row, 8,str(size(sizee)))
                    worksheet.write(row, 9,str(data[data.find('Elastic Indices'):]))
                    row = row + 1
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
    wk = create_workbook(filename)
    if ((not shodan) and (not be)) :
        print("Please specify a data source by adding -s and/or -b")
        sys.exit()
    if shodan :
        getHosts_shodan(filename,wk)
        #to_excel()
    if be:
        getHosts_binaryedge(first,last,filename,wk)
    wk.close()
if __name__ == '__main__':
    main()
