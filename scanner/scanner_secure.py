#!/usr/bin/env python3
import sys
from colorama import init, Fore, Style
from modules.sqli_detector import SQLiDetector
from modules.xss_detector import XSSDetector
from modules.access_control import AccessControlTester
from modules.auth_tester import AuthenticationTester
from datetime import datetime

init()

def print_banner():
    banner = f"""
{Fore.GREEN}
╔══════════════════════════════════════════════════╗
║                                                  ║
║      VulnShop Security Scanner - SECURE TEST     ║
║              by Manav Patel                      ║
║                 Version 2.0                      ║
║                                                  ║
╚══════════════════════════════════════════════════╝
{Style.RESET_ALL}
"""
    print(banner)

def main():
    print_banner()
    
    # Test SECURE version on port 5001
    target_url = "http://127.0.0.1:5001"
    print(f"{Fore.GREEN}[*] Testing SECURE version: {target_url}{Style.RESET_ALL}\n")
    
    all_vulnerabilities = []
    
    # Run all tests
    print(f"{Fore.YELLOW}{'='*60}{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}  MODULE 1: SQL Injection Detection{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}{'='*60}{Style.RESET_ALL}")
    sqli = SQLiDetector(target_url)
    sqli.test_login()
    all_vulnerabilities.extend(sqli.get_results())
    
    print(f"\n{Fore.YELLOW}{'='*60}{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}  MODULE 2: Cross-Site Scripting (XSS) Detection{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}{'='*60}{Style.RESET_ALL}")
    xss = XSSDetector(target_url)
    xss.test_reviews()
    all_vulnerabilities.extend(xss.get_results())
    
    print(f"\n{Fore.YELLOW}{'='*60}{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}  MODULE 3: Access Control Testing{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}{'='*60}{Style.RESET_ALL}")
    ac = AccessControlTester(target_url)
    ac.test_idor()
    all_vulnerabilities.extend(ac.get_results())
    
    print(f"\n{Fore.YELLOW}{'='*60}{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}  MODULE 4: Authentication & Session Security{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}{'='*60}{Style.RESET_ALL}")
    auth = AuthenticationTester(target_url)
    auth.test_account_enumeration()
    auth.test_plaintext_passwords()
    auth.test_session_security()
    all_vulnerabilities.extend(auth.get_results())
    
    print(f"\n{Fore.YELLOW}{'='*60}{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}  SCAN COMPLETE{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}{'='*60}{Style.RESET_ALL}\n")
    
    if all_vulnerabilities:
        print(f"{Fore.RED}[!] Found {len(all_vulnerabilities)} vulnerabilities!{Style.RESET_ALL}\n")
    else:
        print(f"{Fore.GREEN}🎉 PERFECT! NO VULNERABILITIES FOUND! 🎉{Style.RESET_ALL}")
        print(f"{Fore.GREEN}All security fixes are working correctly!{Style.RESET_ALL}\n")

if __name__ == "__main__":
    main()
