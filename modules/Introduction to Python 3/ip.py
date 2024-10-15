import requests

resp = requests.get('http://httpbin.org/ip')
print(resp.content.decode()) #Since the resp.content variable is a byte-string, a string of bytes that may or may not be printable, we have to call decode() on the object
