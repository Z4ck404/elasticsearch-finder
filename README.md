# elasticsearch-finder
A tool to find open instances of elastic search  for bug bounty

## Installation
Requirements:
- Python3 
- Shodan API Key

Steps to install:
- Replace SHODANAPIKEY in .env file with your SHODAN API KEY.
- Run `pip3 install -r requirements.txt` to install dependencies.
- Run `python3 esf.py -o file.txt -c US -k products` where : 
    -`file.txt`is the output file. (optional)
    -`US`is the code of the country you want to scan.(optional)
    -`producs`is a key word in the results, an indice name for example.(optional)

## How it works?
The script gets the data from Shodan. It will output a file in comma-seperated format in which you will find *open* elasticsearch instances.

## Elastic search security 
There is an open source plugin available with a free/community edition called [Search Guard](https://github.com/floragunncom/search-guard) 

## Credits 
- Inspired from [Kibanarec](https://github.com/Lekssays/kibanarec) by [Ahmed Lessays](https://github.com/Lekssays)
- This readme format and repo templete is also inspired from [Kibanarec](https://github.com/Lekssays/kibanarec).

