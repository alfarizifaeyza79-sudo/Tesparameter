#!/usr/bin/env python3
"""
INSTANT SQLMAP COMMAND GENERATOR
Cari parameter -> Generate SQLMap command langsung
Author: Security Researcher
"""

import requests
import sys
import re
from urllib.parse import urlparse, urljoin, parse_qs
from bs4 import BeautifulSoup
from colorama import init, Fore, Style

init(autoreset=True)

class SqlmapGenerator:
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        })
        
        self.common_params = ['id', 'page', 'view', 'cat', 'product', 'user', 'search', 'file', 'q']
    
    def find_parameters(self, url):
        """Cari parameter dari URL dan halaman"""
        print(f"\n{Fore.CYAN}[*] Scanning: {url}{Style.RESET_ALL}")
        
        results = []
        
        # 1. Cek parameter di URL sendiri
        url_params = self._get_url_params(url)
        if url_params:
            results.append({
                'url': url,
                'params': url_params,
                'method': 'GET',
                'source': 'URL'
            })
        
        # 2. Cek halaman untuk forms dan link lain
        try:
            resp = self.session.get(url, timeout=10)
            if resp.status_code == 200:
                # Cari forms
                form_params = self._get_form_params(url, resp.text)
                results.extend(form_params)
                
                # Cari link dengan parameter
                link_params = self._get_link_params(url, resp.text)
                results.extend(link_params)
        except:
            pass
        
        # 3. Test common parameters
        common_found = self._test_common_params(url)
        results.extend(common_found)
        
        return results
    
    def _get_url_params(self, url):
        """Ambil parameter dari URL"""
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        
        # Filter parameter yang berarti (bukan tracking)
        meaningful = []
        for param in params:
            param_low = param.lower()
            if not any(t in param_low for t in ['utm_', 'fbclid', 'gclid', '_ga']):
                meaningful.append(param)
        
        return meaningful
    
    def _get_form_params(self, base_url, html):
        """Ambil parameter dari form"""
        forms_data = []
        soup = BeautifulSoup(html, 'html.parser')
        
        for form in soup.find_all('form'):
            action = form.get('action', '')
            method = form.get('method', 'GET').upper()
            
            # Build form URL
            form_url = urljoin(base_url, action) if action else base_url
            
            # Ambil input fields
            inputs = []
            for tag in form.find_all(['input', 'textarea', 'select']):
                name = tag.get('name')
                if name and name not in ['submit', 'btn', 'button']:
                    inputs.append(name)
            
            if inputs:
                forms_data.append({
                    'url': form_url,
                    'params': inputs,
                    'method': method,
                    'source': 'FORM'
                })
        
        return forms_data
    
    def _get_link_params(self, base_url, html):
        """Cari link dengan parameter"""
        link_data = []
        soup = BeautifulSoup(html, 'html.parser')
        
        for a in soup.find_all('a', href=True):
            href = a['href']
            if '?' in href and '=' in href:
                full_url = urljoin(base_url, href)
                params = self._get_url_params(full_url)
                if params:
                    link_data.append({
                        'url': full_url,
                        'params': params,
                        'method': 'GET',
                        'source': 'LINK'
                    })
        
        return link_data
    
    def _test_common_params(self, url):
        """Test parameter umum"""
        results = []
        parsed = urlparse(url)
        base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        
        for param in self.common_params:
            test_url = f"{base_url}?{param}=test"
            if '?' in url:
                test_url = f"{url}&{param}=test"
            
            try:
                resp = self.session.get(test_url, timeout=3)
                if resp.status_code == 200:
                    # Cek apakah parameter diterima
                    if 'test' in resp.text or len(resp.text) > 100:
                        results.append({
                            'url': test_url,
                            'params': [param],
                            'method': 'GET',
                            'source': 'COMMON'
                        })
            except:
                continue
        
        return results
    
    def generate_sqlmap_commands(self, results):
        """Generate SQLMap commands"""
        commands = []
        
        for item in results:
            if item['method'] == 'GET':
                # Untuk GET request
                if len(item['params']) <= 5:  # Jika sedikit parameter
                    param_str = ','.join(item['params'])
                    cmd = f"sqlmap -u \"{item['url']}\" -p \"{param_str}\" --batch"
                else:
                    cmd = f"sqlmap -u \"{item['url']}\" --batch"
                
                commands.append({
                    'url': item['url'],
                    'params': item['params'],
                    'command': cmd,
                    'method': 'GET'
                })
            
            elif item['method'] == 'POST':
                # Untuk POST request
                post_data = '&'.join([f"{p}=FUZZ" for p in item['params']])
                cmd = f"sqlmap -u \"{item['url']}\" --data=\"{post_data}\" --method=POST --batch"
                commands.append({
                    'url': item['url'],
                    'params': item['params'],
                    'command': cmd,
                    'method': 'POST'
                })
        
        return commands
    
    def display_results(self, commands):
        """Tampilkan hasil dalam format yang mudah copy-paste"""
        print(f"\n{Fore.GREEN}{'='*60}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}SQLMAP COMMANDS READY TO COPY:{Style.RESET_ALL}")
        print(f"{Fore.GREEN}{'='*60}{Style.RESET_ALL}")
        
        if not commands:
            print(f"{Fore.RED}No parameters found!{Style.RESET_ALL}")
            return
        
        for i, cmd_info in enumerate(commands, 1):
            print(f"\n{Fore.CYAN}[COMMAND {i}]{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}URL:{Style.RESET_ALL} {cmd_info['url']}")
            print(f"{Fore.YELLOW}Method:{Style.RESET_ALL} {cmd_info['method']}")
            if cmd_info['params']:
                print(f"{Fore.YELLOW}Parameters:{Style.RESET_ALL} {', '.join(cmd_info['params'])}")
            print(f"{Fore.GREEN}Command:{Style.RESET_ALL}")
            print(f"{Back.BLACK}{Fore.WHITE}{cmd_info['command']}{Style.RESET_ALL}")
            print(f"{Fore.CYAN}{'─'*40}{Style.RESET_ALL}")
        
        print(f"\n{Fore.YELLOW}QUICK COPY ALL COMMANDS:{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'─'*40}{Style.RESET_ALL}")
        for i, cmd_info in enumerate(commands, 1):
            print(f"# Command {i}")
            print(cmd_info['command'])
            print()
        
        print(f"{Fore.GREEN}Total commands generated: {len(commands)}{Style.RESET_ALL}")
    
    def quick_scan(self, url):
        """Scan cepat dan generate commands"""
        print(f"{Fore.YELLOW}[*] Quick scanning for parameters...{Style.RESET_ALL}")
        results = self.find_parameters(url)
        
        if not results:
            # Coba scan lebih dalam
            print(f"{Fore.YELLOW}[*] Trying deeper scan...{Style.RESET_ALL}")
            try:
                resp = self.session.get(url, timeout=10)
                soup = BeautifulSoup(resp.text, 'html.parser')
                
                # Cari semua link di halaman
                links = []
                for a in soup.find_all('a', href=True):
                    href = a['href']
                    if href.startswith('/') or url in href:
                        full_url = urljoin(url, href)
                        if '?' in full_url:
                            links.append(full_url)
                
                # Scan 5 link pertama
                for link in links[:5]:
                    link_results = self.find_parameters(link)
                    results.extend(link_results)
                    if len(results) >= 3:  # Stop jika sudah cukup
                        break
            except:
                pass
        
        commands = self.generate_sqlmap_commands(results)
        self.display_results(commands)
        
        return commands

def main():
    print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}INSTANT SQLMAP COMMAND GENERATOR{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
    
    scanner = SqlmapGenerator()
    
    while True:
        print(f"\n{Fore.GREEN}Enter URL (or 'quit' to exit):{Style.RESET_ALL}")
        url = input(f"{Fore.YELLOW}>>> {Style.RESET_ALL}").strip()
        
        if url.lower() in ['quit', 'exit', 'q']:
            print(f"{Fore.YELLOW}Exiting...{Style.RESET_ALL}")
            break
        
        if not url:
            continue
        
        # Validate URL
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url
        
        try:
            commands = scanner.quick_scan(url)
            
            if commands:
                print(f"\n{Fore.GREEN}✓ Ready to copy and paste into terminal!{Style.RESET_ALL}")
            else:
                print(f"\n{Fore.RED}✗ No parameters found. Try another URL.{Style.RESET_ALL}")
                print(f"{Fore.YELLOW}Tip: Try URLs like:{Style.RESET_ALL}")
                print(f"- http://example.com/product.php?id=1")
                print(f"- http://example.com/page.php?cat=news")
                print(f"- http://example.com/search.php?q=test")
        
        except KeyboardInterrupt:
            print(f"\n{Fore.YELLOW}Scan interrupted.{Style.RESET_ALL}")
            continue
        except Exception as e:
            print(f"\n{Fore.RED}Error: {str(e)}{Style.RESET_ALL}")
            continue
        
        print(f"\n{Fore.CYAN}{'='*60}{Style.RESET_ALL}")

if __name__ == "__main__":
    try:
        import requests
        from bs4 import BeautifulSoup
    except ImportError:
        print("Installing dependencies...")
        import subprocess
        subprocess.check_call([sys.executable, "-m", "pip", "install", "requests", "beautifulsoup4"])
        print("Dependencies installed. Please run again.")
        sys.exit(0)
    
    main()
