import requests
import ssl
import socket
from urllib.parse import urlparse
from prettytable import PrettyTable
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from datetime import datetime

def check_ssl(url, output):
    parsed_url = urlparse(url)
    host = parsed_url.hostname
    port = 443
    context = ssl.create_default_context()

    try:
        with socket.create_connection((host, port)) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert(binary_form=True)
                x509_cert = x509.load_der_x509_certificate(cert, default_backend())
                issuer = x509_cert.issuer.rfc4514_string()
                subject = x509_cert.subject.rfc4514_string()
                not_before = x509_cert.not_valid_before
                not_after = x509_cert.not_valid_after

                days_remaining = (not_after - datetime.now()).days
                warning = ""
                if days_remaining <= 60:
                    warning = f"Dikkat! Sertifika süresi {days_remaining} gün içinde bitecektir."

                table = PrettyTable(["SSL Sertifikası", "Bilgi"])
                table.add_row(["Verilen Kuruluş", subject])
                table.add_row(["Sertifika Zinciri", issuer])
                table.add_row(["Geçerlilik Başlangıcı", not_before])
                table.add_row(["Geçerlilik Bitişi", not_after])
                if warning:
                    table.add_row(["Uyarı", warning])

                output.write(f"\n--- SSL Kontrolü: {url} ---\n")
                output.write(table.get_string() + "\n")
                print(f"\n--- SSL Kontrolü: {url} ---")
                print(table)
    except ssl.SSLError as e:
        output.write(f"{url} internet üzerinden erişim sağlanamadı\n")
        print(f"{url} internet üzerinden erişim sağlanamadı")
    except Exception as e:
        output.write(f"{url} SSL Yok\n")
        print(f"{url} SSL Yok")

def check_headers(url, output):
    try:
        response = requests.get(url)
        headers = response.headers
        security_headers = {
            "Strict-Transport-Security": "HSTS",
            "Content-Security-Policy": "CSP",
            "X-Content-Type-Options": "X-Content-Type",
            "X-Frame-Options": "X-Frame",
            "X-XSS-Protection": "XSS Koruması",
            "Referrer-Policy": "Referrer Policy",
            "Access-Control-Allow-Origin": "CORS"
        }

        table = PrettyTable(["Güvenlik Başlığı", "Durum"])
        for header, name in security_headers.items():
            if header in headers:
                table.add_row([name, headers[header]])
            else:
                table.add_row([name, "Bulunamadı"])

        output.write(f"\n--- HTTP Başlık Kontrolleri: {url} ---\n")
        output.write(table.get_string() + "\n")
        print(f"\n--- HTTP Başlık Kontrolleri: {url} ---")
        print(table)
    except requests.exceptions.RequestException:
        output.write(f"{url} internet üzerinden erişim sağlanamadı\n")
        print(f"{url} internet üzerinden erişim sağlanamadı")

def check_security(url, output):
    if not url.startswith('http://') and not url.startswith('https://'):
        print(f"\nURL'nin protokolü belirtilmemiş. http ve https olarak kontrol ediliyor: {url}")
        output.write(f"\nURL'nin protokolü belirtilmemiş. http ve https olarak kontrol ediliyor: {url}\n")
        check_ssl(f"http://{url}", output)
        check_headers(f"http://{url}", output)
        check_ssl(f"https://{url}", output)
        check_headers(f"https://{url}", output)
    else:
        print(f"\n--- {url} için Güvenlik Kontrolleri ---")
        output.write(f"\n--- {url} için Güvenlik Kontrolleri ---\n")
        check_ssl(url, output)
        check_headers(url, output)

def process_single_url(output):
    url = input("Kontrol edilecek URL'yi girin: ")
    print("\n--- Güvenlik Kontrolleri ---")
    check_security(url, output)

def process_url_list(output):
    path = input("URL listesi dosyasının yolunu girin: ")
    try:
        with open(path, 'r') as file:
            urls = [line.strip() for line in file.readlines()]
            for url in urls:
                check_security(url, output)
    except FileNotFoundError:
        output.write(f"Hata: '{path}' dosyası bulunamadı.\n")
        print(f"Hata: '{path}' dosyası bulunamadı.")

def main():
    output_filename = f"security_check_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
    with open(output_filename, 'w') as output:
        choice = input("Tek URL mi kontrol etmek istiyorsunuz? (evet/hayir): ").strip().lower()
        if choice == 'evet':
            process_single_url(output)
        elif choice == 'hayir':
            process_url_list(output)
        else:
            print("Geçersiz seçim. Lütfen 'evet' veya 'hayir' olarak yanıt verin.")
    print(f"\nSonuçlar '{output_filename}' dosyasına kaydedildi.")

if __name__ == "__main__":
    main()
