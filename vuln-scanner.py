import requests
import socket
import sys
import re
import colorama
from urllib.parse import urlparse
from colorama import Fore, Style
from concurrent.futures import ThreadPoolExecutor, as_completed

# Nonaktifkan peringatan SSL
requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)

class WebVulnerabilityScanner:
    def __init__(self, url):
        """
        Inisialisasi scanner dengan URL target
        """
        self.url = url.rstrip('/')
        # Parse URL untuk mendapatkan host dan skema
        self.parsed_url = urlparse(url)
        self.host = self.parsed_url.netloc
        self.scheme = self.parsed_url.scheme

    def send_request(self, url, timeout=5):
        """
        Kirim permintaan HTTP dengan penanganan kesalahan
        """
        try:
            return requests.get(
                url, 
                timeout=timeout, 
                verify=False,  # Nonaktifkan verifikasi SSL untuk menghindari kesalahan
                allow_redirects=True,
                headers={
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
                }
            )
        except requests.RequestException as e:
            print(f"{Fore.YELLOW}[!] Kesalahan permintaan: {e}{Style.RESET_ALL}")
            return None

    def check_sqli(self):
        """
        Periksa kerentanan SQL Injection dengan beberapa payload
        """
        print(f"{Fore.CYAN}[*] Memeriksa kerentanan SQL Injection...{Style.RESET_ALL}")
        
        # Daftar payload SQL Injection yang berbeda
        payloads = [
            "' OR '1'='1",
            "1' OR '1'='1",
            "1' OR 1=1--+",
            "' OR 1=1--+",
            "admin' --"
        ]

        for payload in payloads:
            target = f"{self.url}?id={requests.utils.quote(payload)}"
            response = self.send_request(target)
            
            if response:
                # Kriteria deteksi yang lebih komprehensif
                indicators = [
                    "mysql error", 
                    "syntax error", 
                    "unexpected token", 
                    "sql syntax", 
                    "you have an error in your sql syntax"
                ]
                
                for indicator in indicators:
                    if indicator in response.text.lower():
                        print(f"{Fore.RED}[!] Potensi SQL Injection ditemukan di: {target}{Style.RESET_ALL}")
                        return True
        
        print(f"{Fore.GREEN}[+] Tidak ditemukan kerentanan SQL Injection{Style.RESET_ALL}")
        return False

    def check_xss(self):
        """
        Periksa kerentanan Cross-Site Scripting (XSS)
        """
        print(f"{Fore.CYAN}[*] Memeriksa kerentanan Cross-Site Scripting (XSS)...{Style.RESET_ALL}")
        
        # Daftar payload XSS yang berbeda
        payloads = [
            "<script>alert('XSS')</script>",
            "'\"><script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "javascript:alert('XSS')"
        ]

        for payload in payloads:
            # Gunakan parameter yang berbeda
            test_params = ['q', 'search', 'id', 's']
            
            for param in test_params:
                target = f"{self.url}?{param}={requests.utils.quote(payload)}"
                response = self.send_request(target)
                
                if response and payload in response.text:
                    print(f"{Fore.RED}[!] Potensi XSS ditemukan di: {target}{Style.RESET_ALL}")
                    return True
        
        print(f"{Fore.GREEN}[+] Tidak ditemukan kerentanan XSS{Style.RESET_ALL}")
        return False

    def check_sensitive_files(self):
        """
        Periksa file sensitif yang mungkin terbuka
        """
        print(f"{Fore.CYAN}[*] Memeriksa file sensitif...{Style.RESET_ALL}")
        
        # Daftar file sensitif yang lebih komprehensif
        files = [
            "/robots.txt", 
            "/.env", 
            "/config.php", 
            "/wp-config.php",  # WordPress
            "/admin", 
            "/backup",
            "/.git/config",
            "/server-status",
            "/phpinfo.php",
            "/info.php"
        ]

        found_files = []
        for file in files:
            target = f"{self.url}{file}"
            response = self.send_request(target)
            
            if response and response.status_code == 200:
                print(f"{Fore.RED}[!] File sensitif ditemukan: {target}{Style.RESET_ALL}")
                found_files.append(target)
        
        if not found_files:
            print(f"{Fore.GREEN}[+] Tidak ada file sensitif yang ditemukan{Style.RESET_ALL}")
        
        return found_files

    def check_open_ports(self):
        """
        Periksa port yang terbuka
        """
        print(f"{Fore.CYAN}[*] Memindai port yang terbuka...{Style.RESET_ALL}")
        
        # Daftar port yang akan dipindai
        ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3306, 3389, 8080]
        
        # Port yang dikenal
        port_names = {
            21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 
            53: 'DNS', 80: 'HTTP', 110: 'POP3', 143: 'IMAP', 
            443: 'HTTPS', 445: 'SMB', 3306: 'MySQL', 
            3389: 'RDP', 8080: 'HTTP Alternatif'
        }

        open_ports = []
        
        # Gunakan ThreadPoolExecutor untuk pemindaian port yang lebih cepat
        with ThreadPoolExecutor(max_workers=20) as executor:
            # Simpan futures untuk setiap port
            future_to_port = {
                executor.submit(self._check_port, self.host, port): port 
                for port in ports
            }
            
            # Proses hasil
            for future in as_completed(future_to_port):
                port = future_to_port[future]
                try:
                    is_open = future.result()
                    if is_open:
                        print(f"{Fore.RED}[!] Port {port} ({port_names.get(port, 'Tidak dikenal')}) terbuka{Style.RESET_ALL}")
                        open_ports.append(port)
                except Exception as exc:
                    print(f"{Fore.YELLOW}[!] Kesalahan saat memeriksa port {port}: {exc}{Style.RESET_ALL}")
        
        if not open_ports:
            print(f"{Fore.GREEN}[+] Tidak ada port yang terbuka{Style.RESET_ALL}")
        
        return open_ports

    def _check_port(self, host, port, timeout=1):
        """
        Metode internal untuk memeriksa satu port
        """
        try:
            with socket.create_connection((host, port), timeout=timeout):
                return True
        except (socket.timeout, ConnectionRefusedError, OSError):
            return False

    def run_full_scan(self):
        """
        Jalankan seluruh pemindaian kerentanan
        """
        print(f"{Fore.CYAN}[*] Memulai pemindaian kerentanan untuk {self.url}{Style.RESET_ALL}")
        
        results = {
            'sqli': self.check_sqli(),
            'xss': self.check_xss(),
            'sensitive_files': self.check_sensitive_files(),
            'open_ports': self.check_open_ports()
        }
        
        print(f"\n{Fore.MAGENTA}[RINGKASAN] Hasil Pemindaian:{Style.RESET_ALL}")
        print(f"SQL Injection: {'Rentan' if results['sqli'] else 'Aman'}")
        print(f"Cross-Site Scripting: {'Rentan' if results['xss'] else 'Aman'}")
        print(f"File Sensitif: {len(results['sensitive_files'])} file ditemukan")
        print(f"Port Terbuka: {len(results['open_ports'])} port")

def main():
    """
    Fungsi utama untuk menjalankan alat
    """
    print(f"{Fore.CYAN}{'='*50}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}ALAT PEMINDAI KERENTANAN WEB{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{'='*50}{Style.RESET_ALL}")
    
    # Tambahkan penanganan argumen baris perintah
    if len(sys.argv) > 1:
        url = sys.argv[1]
    else:
        url = input(f"{Fore.CYAN}Masukkan URL target (contoh: https://example.com): {Style.RESET_ALL}")
    
    # Tambahkan skema http jika tidak ada
    if not url.startswith(('http://', 'https://')):
        url = f'http://{url}'
    
    try:
        scanner = WebVulnerabilityScanner(url)
        scanner.run_full_scan()
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}[!] Pemindaian dihentikan oleh pengguna.{Style.RESET_ALL}")
    except Exception as e:
        print(f"{Fore.RED}[!] Kesalahan fatal: {e}{Style.RESET_ALL}")

if __name__ == '__main__':
    # Inisialisasi colorama
    colorama.init(autoreset=True)
    main()
