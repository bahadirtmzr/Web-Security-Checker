# Web-Security-Checker

**Web Security Checker** is a Python script that checks the SSL certificates and HTTP security headers of one or more websites. The script accepts either a single URL or a list of URLs from a file and performs the following checks for each URL:

# Web Security Checker

**Web Security Checker** is a Python script that checks the SSL certificates and HTTP security headers of one or more websites. The script accepts either a single URL or a list of URLs from a file and performs the following checks for each URL:

## Features

1. **SSL Certificate Check**:
   - Verifies the validity of the SSL certificate.
   - Reports the certificate's validity period and expiration date.
   - If the certificate expires in 60 days or less, it provides a warning: 
     "Dikkat! Sertifika süresi X gün içinde bitecektir" (Warning! The certificate will expire in X days).
   - For websites without SSL or with SSL errors, it reports "SSL Yok" (No SSL) or "internet üzerinden erişim sağlanamadı" (Could not be accessed).

2. **HTTP Security Headers Check**:
   - Checks for important security headers like HSTS, CSP, X-Content-Type-Options, X-Frame-Options, X-XSS-Protection, and Referrer-Policy.
   - Reports the presence and value of each header.

3. **Reporting**:
   - Displays the results for each URL in a readable table format in the terminal using PrettyTable.
   - Saves the results to a `txt` file created at runtime, named `security_check_results_YYYYMMDD_HHMMSS.txt`.
   - Reports inaccessible websites with a simple message: "internet üzerinden erişim sağlanamadı".

## Installation

1. Ensure you have **Python 3** installed.
2. Install the required Python packages using:
   ```bash
   pip install requests cryptography prettytable
Usage
Clone the repository or download the script.
Run the script:
bash
Kodu kopyala
python web_security_checker.py
The script will ask if you want to check a single URL or a list of URLs from a file:
For a single URL, enter the URL directly.
For a list of URLs, provide the path to a file containing URLs (one per line).
The results will be displayed in the terminal and saved to a txt file.
Example Output
lua
Kodu kopyala
--- SSL Kontrolü: https://example.com ---
+---------------------+--------------------------------+
| SSL Sertifikası     | Bilgi                          |
+---------------------+--------------------------------+
| Verilen Kuruluş     | CN=example.com, O=Example Ltd. |
| Sertifika Zinciri   | CN=Example CA                  |
| Geçerlilik Başlangıcı | 2024-01-01                    |
| Geçerlilik Bitişi   | 2024-12-31                     |
| Uyarı               | Dikkat! Sertifika süresi 45 gün içinde bitecektir |
+---------------------+--------------------------------+

--- HTTP Başlık Kontrolleri: https://example.com ---
+-------------------------+------------------------------------+
| Güvenlik Başlığı        | Durum                              |
+-------------------------+------------------------------------+
| HSTS                    | max-age=31536000; includeSubDomains|
| CSP                     | default-src 'self'                 |
| X-Content-Type          | nosniff                            |
| X-Frame                 | SAMEORIGIN                         |
| XSS Koruması            | 1; mode=block                      |
| Referrer Policy         | Bulunamadı                         |
| CORS                    | Bulunamadı                         |
+-------------------------+------------------------------------+
License
This project is licensed under the MIT License - see the LICENSE file for details.

Contributions
Contributions are welcome! If you find a bug or have a feature request, feel free to open an issue or submit a pull request.

Author

Bahadır TEMİZER
