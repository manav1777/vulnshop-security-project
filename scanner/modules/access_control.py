import requests
from colorama import Fore, Style

class AccessControlTester:
    def __init__(self, target_url):
        self.target_url = target_url
        self.vulnerabilities = []
    
    def test_idor(self):
        """Test for Insecure Direct Object References (IDOR)"""
        print(f"\n{Fore.CYAN}[*] Testing for Broken Access Control (IDOR)...{Style.RESET_ALL}")
        
        # First, login as a user to get a session
        login_url = f"{self.target_url}/login"
        session = requests.Session()
        
        try:
            # Login as admin
            data = {'username': 'admin', 'password': 'admin123'}
            response = session.post(login_url, data=data)
            
            if 'dashboard' not in response.url:
                print(f"{Fore.YELLOW}[!] Could not login to test access control{Style.RESET_ALL}")
                return
            
            # Try accessing other users' data
            # User ID 1 is admin, try accessing user ID 2 (bob)
            orders_url = f"{self.target_url}/orders?user_id=2"
            response = session.get(orders_url)
            
            # Check if we can see user_id=2's data while logged in as user_id=1
            if response.status_code == 200 and 'bob' in response.text.lower():
                vuln = {
                    'type': 'Broken Access Control (IDOR)',
                    'severity': 'CRITICAL',
                    'location': '/orders endpoint (user_id parameter)',
                    'payload': '?user_id=2',
                    'description': 'Can view other users\' orders by changing user_id parameter',
                    'impact': 'Any authenticated user can access any other user\'s private data'
                }
                self.vulnerabilities.append(vuln)
                print(f"{Fore.RED}[!] IDOR VULNERABILITY FOUND! Can access other users' orders{Style.RESET_ALL}")
            else:
                print(f"{Fore.GREEN}[✓] Access control properly enforced{Style.RESET_ALL}")
                
        except Exception as e:
            print(f"{Fore.RED}[ERROR] {str(e)}{Style.RESET_ALL}")
    
    def get_results(self):
        """Return all found vulnerabilities"""
        return self.vulnerabilities