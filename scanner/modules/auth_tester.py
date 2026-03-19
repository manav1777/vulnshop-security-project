import requests
import sqlite3
from colorama import Fore, Style

class AuthenticationTester:
    def __init__(self, target_url):
        self.target_url = target_url
        self.vulnerabilities = []
    
    def test_account_enumeration(self):
        """Test if login reveals whether usernames exist"""
        print(f"\n{Fore.CYAN}[*] Testing for Account Enumeration...{Style.RESET_ALL}")
        
        login_url = f"{self.target_url}/login"
        
        # Test with valid username, wrong password
        response1 = requests.post(login_url, data={
            'username': 'admin',
            'password': 'wrongpassword123'
        })
        
        # Test with invalid username
        response2 = requests.post(login_url, data={
            'username': 'nonexistentuser999',
            'password': 'wrongpassword123'
        })
        
        # Check if error messages are different
        if response1.text != response2.text:
            if 'incorrect password' in response1.text.lower() or 'does not exist' in response2.text.lower():
                vuln = {
                    'type': 'Account Enumeration',
                    'severity': 'MEDIUM',
                    'location': 'Login Form',
                    'payload': 'Compare error messages for valid vs invalid usernames',
                    'description': 'Login form reveals whether usernames exist through different error messages',
                    'impact': 'Attackers can enumerate valid usernames to build targeted attack lists'
                }
                self.vulnerabilities.append(vuln)
                print(f"{Fore.YELLOW}[!] ACCOUNT ENUMERATION FOUND! Different error messages detected{Style.RESET_ALL}")
            else:
                print(f"{Fore.GREEN}[✓] No obvious account enumeration detected{Style.RESET_ALL}")
        else:
            print(f"{Fore.GREEN}[✓] Error messages are consistent{Style.RESET_ALL}")
    
    def test_plaintext_passwords(self):
        """Check if passwords are stored in plaintext (requires database access)"""
        print(f"\n{Fore.CYAN}[*] Testing for Plaintext Password Storage...{Style.RESET_ALL}")
        
        try:
            # This assumes scanner is running on same machine as app
            db_path = '../vulnshop-app/vulnshop.db'
            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()
            
            cursor.execute('SELECT username, password FROM users LIMIT 1')
            user = cursor.fetchone()
            conn.close()
            
            if user:
                password = user[1]
                # Check if password looks like plaintext (not a hash)
                # Hashes are typically 60+ characters for bcrypt
                if len(password) < 40 and not password.startswith('$'):
                    vuln = {
                        'type': 'Plaintext Password Storage',
                        'severity': 'CRITICAL',
                        'location': 'Database (users table)',
                        'payload': f'Found plaintext password: {password[:3]}***',
                        'description': 'Passwords are stored in plaintext without hashing',
                        'impact': 'If database is compromised, all user passwords are immediately exposed'
                    }
                    self.vulnerabilities.append(vuln)
                    print(f"{Fore.RED}[!] CRITICAL! Passwords stored in PLAINTEXT!{Style.RESET_ALL}")
                else:
                    print(f"{Fore.GREEN}[✓] Passwords appear to be hashed{Style.RESET_ALL}")
            
        except Exception as e:
            print(f"{Fore.YELLOW}[!] Could not check database: {str(e)}{Style.RESET_ALL}")
    
    def test_session_security(self):
        """Test if sessions use predictable tokens"""
        print(f"\n{Fore.CYAN}[*] Testing Session Security...{Style.RESET_ALL}")
        
        login_url = f"{self.target_url}/login"
        session1 = requests.Session()
        
        # Login and check session
        response = session1.post(login_url, data={
            'username': 'admin',
            'password': 'admin123'
        })
        
        if 'session' in session1.cookies:
            session_value = session1.cookies.get('session')
            
            # Check if session is encrypted/signed (Flask default)
            # or if it's something predictable
            if session_value and len(session_value) < 20:
                vuln = {
                    'type': 'Weak Session Management',
                    'severity': 'HIGH',
                    'location': 'Session cookies',
                    'payload': 'Session tokens may be predictable',
                    'description': 'Session tokens appear to be simple/predictable values',
                    'impact': 'Attackers may be able to guess or brute-force session tokens'
                }
                self.vulnerabilities.append(vuln)
                print(f"{Fore.YELLOW}[!] Session tokens may be weak!{Style.RESET_ALL}")
            else:
                print(f"{Fore.GREEN}[✓] Session tokens appear properly randomized{Style.RESET_ALL}")
        else:
            print(f"{Fore.YELLOW}[!] No session cookie found{Style.RESET_ALL}")
    
    def get_results(self):
        """Return all found vulnerabilities"""
        return self.vulnerabilities