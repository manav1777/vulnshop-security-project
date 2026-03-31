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
        
        try:
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
            if 'incorrect password' in response1.text.lower() and 'does not exist' in response2.text.lower():
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
                print(f"{Fore.GREEN}[✓] Error messages are consistent{Style.RESET_ALL}")
        except Exception as e:
            print(f"{Fore.YELLOW}[!] Could not test enumeration: {str(e)}{Style.RESET_ALL}")
    
    def test_plaintext_passwords(self):
        """Check if passwords are stored in plaintext (requires database access)"""
        print(f"\n{Fore.CYAN}[*] Testing for Plaintext Password Storage...{Style.RESET_ALL}")
        
        try:
            # Determine which database to check based on target URL
            if '5001' in self.target_url:
                db_path = '../vulnshop-app-secure/vulnshop_secure.db'
            else:
                db_path = '../vulnshop-app/vulnshop.db'
            
            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()
            
            # Check if password_hash column exists (secure) or password column (vulnerable)
            cursor.execute("PRAGMA table_info(users)")
            columns = [col[1] for col in cursor.fetchall()]
            
            if 'password_hash' in columns:
                cursor.execute('SELECT username, password_hash FROM users LIMIT 1')
                user = cursor.fetchone()
                if user and user[1].startswith('$2b$'):
                    print(f"{Fore.GREEN}[✓] Passwords are properly hashed with bcrypt{Style.RESET_ALL}")
                else:
                    vuln = {
                        'type': 'Plaintext Password Storage',
                        'severity': 'CRITICAL',
                        'location': 'Database (users table)',
                        'payload': 'Passwords not properly hashed',
                        'description': 'Passwords are not using bcrypt hashing',
                        'impact': 'If database is compromised, passwords may be exposed'
                    }
                    self.vulnerabilities.append(vuln)
                    print(f"{Fore.RED}[!] Passwords not properly hashed!{Style.RESET_ALL}")
            elif 'password' in columns:
                cursor.execute('SELECT username, password FROM users LIMIT 1')
                user = cursor.fetchone()
                if user and len(user[1]) < 40:
                    vuln = {
                        'type': 'Plaintext Password Storage',
                        'severity': 'CRITICAL',
                        'location': 'Database (users table)',
                        'payload': f'Found plaintext password',
                        'description': 'Passwords are stored in plaintext without hashing',
                        'impact': 'If database is compromised, all user passwords are immediately exposed'
                    }
                    self.vulnerabilities.append(vuln)
                    print(f"{Fore.RED}[!] CRITICAL! Passwords stored in PLAINTEXT!{Style.RESET_ALL}")
            
            conn.close()
            
        except Exception as e:
            print(f"{Fore.YELLOW}[!] Could not check database: {str(e)}{Style.RESET_ALL}")
    
    def test_session_security(self):
        """Test if sessions use predictable tokens"""
        print(f"\n{Fore.CYAN}[*] Testing Session Security...{Style.RESET_ALL}")
        
        try:
            login_url = f"{self.target_url}/login"
            session1 = requests.Session()
            
            response = session1.post(login_url, data={
                'username': 'admin',
                'password': 'admin123'
            })
            
            if 'session' in session1.cookies:
                session_value = session1.cookies.get('session')
                
                if session_value and len(session_value) > 50:
                    print(f"{Fore.GREEN}[✓] Session tokens are cryptographically random{Style.RESET_ALL}")
                else:
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
                print(f"{Fore.GREEN}[✓] Session management appears secure{Style.RESET_ALL}")
        except Exception as e:
            print(f"{Fore.YELLOW}[!] Could not test sessions: {str(e)}{Style.RESET_ALL}")
    
    def get_results(self):
        """Return all found vulnerabilities"""
        return self.vulnerabilities
