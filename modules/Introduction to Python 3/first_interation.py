import requests
from rich import print #Cores no print
from bs4 import BeautifulSoup
import re

requests.packages.urllib3.disable_warnings()

PAGE_URL = 'http://94.237.59.63:59009/'

def get_html_of(url):

    resp = requests.get(PAGE_URL)
    status = resp.status_code

    if status != 200:
        print(f'[bold red]HTTP status code of {resp.status_code} returned, but 200 was expected. Exiting...[/bold red]')
        exit(1)
    else:
        return resp.content.decode()

html = get_html_of(PAGE_URL)
soup = BeautifulSoup(html, 'html.parser')
raw_text = soup.get_text()
all_words = re.findall(r'\w+', raw_text)

word_count = {}

for word in all_words:
    if word not in word_count:
        word_count[word] = 1
    else:
        current_count = word_count.get(word)
        word_count[word] = current_count + 1

top_words = sorted(word_count.items(), key=lambda item: item[1], reverse=True)

for i in range(10):
    print(top_words[i][0])
