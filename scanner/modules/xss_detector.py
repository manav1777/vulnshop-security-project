import requests
from bs4 import BeautifulSoup
from colorama import Fore, Style

class XSSDetector:
    def __init__(self, target_url):
        self.target_url = target_url
        self.vulnerabilities = []
    
    def load_payloads(self):
        """Load XSS payloads from file"""
        with open('payloads/xss_payloads.txt', 'r') as f:
            return [line.strip() for line in f if line.strip()]
    
    def test_reviews(self):
        """Test product reviews for Stored XSS"""
        print(f"\n{Fore.CYAN}[*] Testing for Stored XSS in product reviews...{Style.RESET_ALL}")
        
        payloads = self.load_payloads()
        
        # Test on product 1 (Laptop Pro)
        review_url = f"{self.target_url}/product/1/review"
        product_url = f"{self.target_url}/product/1"
        
        for payload in payloads[:3]:  # Test first 3 payloads to avoid spam
            try:
                # Submit review with XSS payload
                data = {
                    'username': 'scanner_test',
                    'rating': '5',
                    'comment': payload
                }
                
                response = requests.post(review_url, data=data, allow_redirects=True)
                
                # Check if payload is reflected in the page without encoding
                if payload in response.text:
                    # Check if it's actually executable (not HTML-encoded)
                    soup = BeautifulSoup(response.text, 'html.parser')
                    scripts = soup.find_all('script')
                    
                    for script in scripts:
                        if 'alert' in script.get_text() or 'XSS' in script.get_text():
                            vuln = {
                                'type': 'Stored XSS',
                                'severity': 'CRITICAL',
                                'location': 'Product Reviews (comment field)',
                                'payload': payload,
                                'description': 'JavaScript code executed in product reviews',
                                'impact': 'Attacker can steal cookies, hijack sessions, or deface pages for all users'
                            }
                            self.vulnerabilities.append(vuln)
                            print(f"{Fore.RED}[!] STORED XSS FOUND! Payload: {payload[:50]}...{Style.RESET_ALL}")
                            return  # Found it, stop testing
                
            except Exception as e:
                print(f"{Fore.RED}[ERROR] {str(e)}{Style.RESET_ALL}")
        
        if not self.vulnerabilities:
            print(f"{Fore.GREEN}[✓] No XSS vulnerabilities found in reviews{Style.RESET_ALL}")
    
    def get_results(self):
        """Return all found vulnerabilities"""
        return self.vulnerabilities