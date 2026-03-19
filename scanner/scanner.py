import sys
from colorama import init, Fore, Style
from modules.sqli_detector import SQLiDetector
from modules.xss_detector import XSSDetector
from modules.access_control import AccessControlTester
from datetime import datetime

# Initialize colorama
init()

def print_banner():
    banner = f"""
{Fore.CYAN}
╔══════════════════════════════════════════════════╗
║                                                  ║
║           VulnShop Security Scanner              ║
║              by Manav Patel                      ║
║                                                  ║
╚══════════════════════════════════════════════════╝
{Style.RESET_ALL}
"""
    print(banner)

def generate_report(all_vulnerabilities, target_url):
    """Generate HTML report"""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    severity_colors = {
        'CRITICAL': '#dc3545',
        'HIGH': '#fd7e14',
        'MEDIUM': '#ffc107',
        'LOW': '#17a2b8'
    }
    
    html = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>Security Scan Report - VulnShop</title>
        <style>
            body {{ font-family: Arial, sans-serif; margin: 40px; background: #f5f5f5; }}
            .header {{ background: #2c3e50; color: white; padding: 30px; border-radius: 5px; }}
            .summary {{ background: white; padding: 20px; margin: 20px 0; border-radius: 5px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
            .vuln {{ background: white; padding: 20px; margin: 20px 0; border-radius: 5px; border-left: 5px solid; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
            .critical {{ border-left-color: #dc3545; }}
            .high {{ border-left-color: #fd7e14; }}
            .severity {{ display: inline-block; padding: 5px 15px; border-radius: 3px; color: white; font-weight: bold; }}
            .metric {{ display: inline-block; margin: 10px 20px 10px 0; }}
            .metric-value {{ font-size: 36px; font-weight: bold; color: #2c3e50; }}
            .metric-label {{ color: #7f8c8d; }}
        </style>
    </head>
    <body>
        <div class="header">
            <h1>🔒 VulnShop Security Scan Report</h1>
            <p>Target: {target_url}</p>
            <p>Scan Date: {timestamp}</p>
            <p>Scanner: VulnShop Security Scanner v1.0</p>
        </div>
        
        <div class="summary">
            <h2>Executive Summary</h2>
            <div class="metric">
                <div class="metric-value">{len(all_vulnerabilities)}</div>
                <div class="metric-label">Total Vulnerabilities</div>
            </div>
            <div class="metric">
                <div class="metric-value">{sum(1 for v in all_vulnerabilities if v['severity'] == 'CRITICAL')}</div>
                <div class="metric-label">Critical</div>
            </div>
            <div class="metric">
                <div class="metric-value">{sum(1 for v in all_vulnerabilities if v['severity'] == 'HIGH')}</div>
                <div class="metric-label">High</div>
            </div>
        </div>
    """
    
    for i, vuln in enumerate(all_vulnerabilities, 1):
        severity_class = vuln['severity'].lower()
        html += f"""
        <div class="vuln {severity_class}">
            <h3>#{i} - {vuln['type']}</h3>
            <p><span class="severity" style="background-color: {severity_colors[vuln['severity']]};">{vuln['severity']}</span></p>
            <p><strong>Location:</strong> {vuln['location']}</p>
            <p><strong>Payload:</strong> <code>{vuln['payload']}</code></p>
            <p><strong>Description:</strong> {vuln['description']}</p>
            <p><strong>Impact:</strong> {vuln['impact']}</p>
        </div>
        """
    
    html += """
    </body>
    </html>
    """
    
    filename = f"reports/scan_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
    with open(filename, 'w') as f:
        f.write(html)
    
    return filename

def main():
    print_banner()
    
    target_url = "http://127.0.0.1:5000"
    print(f"{Fore.GREEN}[*] Target: {target_url}{Style.RESET_ALL}\n")
    
    all_vulnerabilities = []
    
    # Run SQL Injection tests
    print(f"{Fore.YELLOW}{'='*60}{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}  MODULE 1: SQL Injection Detection{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}{'='*60}{Style.RESET_ALL}")
    sqli = SQLiDetector(target_url)
    sqli.test_login()
    all_vulnerabilities.extend(sqli.get_results())
    
    # Run XSS tests
    print(f"\n{Fore.YELLOW}{'='*60}{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}  MODULE 2: Cross-Site Scripting (XSS) Detection{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}{'='*60}{Style.RESET_ALL}")
    xss = XSSDetector(target_url)
    xss.test_reviews()
    all_vulnerabilities.extend(xss.get_results())
    
    # Run Access Control tests
    print(f"\n{Fore.YELLOW}{'='*60}{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}  MODULE 3: Access Control Testing{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}{'='*60}{Style.RESET_ALL}")
    ac = AccessControlTester(target_url)
    ac.test_idor()
    all_vulnerabilities.extend(ac.get_results())
    
    # Generate report
    print(f"\n{Fore.YELLOW}{'='*60}{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}  SCAN COMPLETE{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}{'='*60}{Style.RESET_ALL}\n")
    
    if all_vulnerabilities:
        print(f"{Fore.RED}[!] Found {len(all_vulnerabilities)} vulnerabilities!{Style.RESET_ALL}\n")
        report_file = generate_report(all_vulnerabilities, target_url)
        print(f"{Fore.GREEN}[✓] Report saved to: {report_file}{Style.RESET_ALL}")
    else:
        print(f"{Fore.GREEN}[✓] No vulnerabilities found!{Style.RESET_ALL}")

if __name__ == "__main__":
    main()