#!/usr/bin/env python3
import argparse
import asyncio
import aiohttp
import logging
from urllib.parse import urlparse, quote
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from colorama import Fore, Style


class WebScanner:
    """
    Web Vulnerability Scanner yang lebih stealth dan efektif.
    - Mendeteksi SQL Injection, XSS, LFI, SSRF, Open Directories.
    - Output lebih rapi dengan format tabel dan warna.
    """

    def __init__(self, url, verbose=False):
        self.url = url.rstrip('/')
        self.parsed_url = urlparse(url)
        self.host = self.parsed_url.netloc
        self.scheme = self.parsed_url.scheme
        self.console = Console()

        logging.basicConfig(
            level=logging.DEBUG if verbose else logging.INFO,
            format="%(asctime)s - %(levelname)s: %(message)s"
        )
        self.logger = logging.getLogger(__name__)

    async def create_session(self):
        """Buat sesi HTTP dengan headers stealth."""
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Gecko/20100101 Firefox/110.0',
            'Referer': self.url,
            'X-Forwarded-For': '127.0.0.1'
        }
        return aiohttp.ClientSession(headers=headers)

    async def scan(self):
        """Jalankan semua metode pemindaian."""
        self.console.print(f"\n[bold cyan]Memulai Pemindaian: {self.url}[/bold cyan]\n")

        async with await self.create_session() as session:
            vulnerabilities = {
                "SQL Injection": await self.scan_sql_injection(session),
                "XSS (Cross-Site Scripting)": await self.scan_xss(session),
                "LFI (Local File Inclusion)": await self.scan_lfi(session),
                "SSRF (Server-Side Request Forgery)": await self.scan_ssrf(session),
                "File Sensitif": await self.scan_sensitive_files(session),
                "Port Terbuka": await self.scan_open_ports()
            }

        # Menampilkan hasil dalam bentuk tabel
        table = Table(title="Hasil Pemindaian Web")
        table.add_column("Jenis Kerentanan", style="cyan", justify="left")
        table.add_column("Status", style="red", justify="center")

        for vuln, result in vulnerabilities.items():
            status = "[bold red]❌ Rentan[/bold red]" if result else "[bold green]✅ Aman[/bold green]"
            table.add_row(vuln, status)

        self.console.print(Panel(table, title="[bold yellow]Ringkasan Pemindaian[/bold yellow]"))

    async def send_request(self, session, url):
        """Mengirim permintaan HTTP dengan error handling."""
        try:
            async with session.get(url, timeout=10, ssl=False) as response:
                return await response.text(), response.status
        except Exception as e:
            self.logger.warning(f"Gagal mengakses {url}: {e}")
            return None, None

    async def scan_sql_injection(self, session):
        """Memeriksa SQL Injection dengan payload canggih."""
        payloads = ["' OR 1=1--", "' UNION SELECT NULL, version(), database(), user()--"]
        for payload in payloads:
            test_url = f"{self.url}?id={quote(payload)}"
            response, status = await self.send_request(session, test_url)
            if response and any(error in response.lower() for error in ["mysql", "syntax error", "sql syntax"]):
                self.console.print(f"[red]SQL Injection Ditemukan:[/red] {test_url}")
                return True
        return False

    async def scan_xss(self, session):
        """Memeriksa Cross-Site Scripting (XSS)."""
        payloads = ["<script>alert('XSS')</script>", "<svg/onload=alert('XSS')>"]
        for payload in payloads:
            test_url = f"{self.url}?q={quote(payload)}"
            response, status = await self.send_request(session, test_url)
            if response and payload in response:
                self.console.print(f"[red]XSS Terdeteksi:[/red] {test_url}")
                return True
        return False

    async def scan_lfi(self, session):
        """Mendeteksi Local File Inclusion (LFI)."""
        payloads = ["../../../../etc/passwd", "php://filter/convert.base64-encode/resource=index.php"]
        for payload in payloads:
            test_url = f"{self.url}?file={quote(payload)}"
            response, status = await self.send_request(session, test_url)
            if response and ("root:x:0:0" in response or "nobody:x:" in response):
                self.console.print(f"[red]LFI Terbuka:[/red] {test_url}")
                return True
        return False

    async def scan_ssrf(self, session):
        """Mendeteksi SSRF dengan mencoba memanggil localhost."""
        payloads = ["http://127.0.0.1", "http://localhost"]
        for payload in payloads:
            test_url = f"{self.url}?url={quote(payload)}"
            response, status = await self.send_request(session, test_url)
            if response and "localhost" in response:
                self.console.print(f"[red]SSRF Ditemukan:[/red] {test_url}")
                return True
        return False

    async def scan_sensitive_files(self, session):
        """Mengecek file sensitif seperti config.php, backup, dll."""
        files = ["robots.txt", "config.php", "admin", "backup", ".git"]
        for file in files:
            test_url = f"{self.url}/{file}"
            response, status = await self.send_request(session, test_url)
            if status == 200:
                self.console.print(f"[red]File Sensitif Ditemukan:[/red] {test_url}")
                return True
        return False

    async def scan_open_ports(self):
        """Memindai port terbuka di host target."""
        ports = [80, 443, 3306, 8080]
        open_ports = []
        for port in ports:
            try:
                reader, writer = await asyncio.open_connection(self.host, port)
                open_ports.append(port)
                writer.close()
            except:
                pass
        if open_ports:
            self.console.print(f"[red]Port Terbuka:[/red] {open_ports}")
            return True
        return False


def main():
    parser = argparse.ArgumentParser(description="Advanced Web Vulnerability Scanner")
    parser.add_argument("url", help="URL target")
    args = parser.parse_args()
    scanner = WebScanner(args.url)
    asyncio.run(scanner.scan())


if __name__ == "__main__":
    main()
