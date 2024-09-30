ENFORCER


This script is an API Security Assessment Tool designed to perform comprehensive security tests on RESTful APIs. It automates the process of scanning APIs for common vulnerabilities, generates detailed reports, and assists security professionals and developers in identifying and mitigating potential security risks.

Features
•	Automated Security Checks: Performs a series of predefined security tests covering various OWASP API Security Top 10 vulnerabilities.

•	Authentication Handling: Supports APIs that require authentication, including API Keys, Bearer Tokens, and Basic Authentication.

•	Traffic Capture: Captures network traffic during the assessment and saves it as a PCAP file.

•	Request Logging: Saves all captured API requests and exports them to a Postman collection for further analysis.

•	Comprehensive Reporting: Generates a detailed PDF report of the findings, including remediation steps and code snippets.

•	Extensible: Modular design allows for easy addition of new security checks or customization of existing ones.

•	User-Friendly: Interactive prompts guide the user through the setup process.

Note: The script checks for missing modules at runtime and prompts the user to install them if necessary.

Notes and Warnings
•	Ethical Use Only: Ensure you have explicit permission to perform security testing on the target API. Unauthorized testing may violate laws or regulations.
•	Elevated Privileges Required: The script may need to run with administrator or root privileges to capture network traffic.
•	Resource Intensive: Some tests may consume significant network or system resources. Avoid running against production environments without proper safeguards.
•	Dependencies: Ensure all required Python modules are installed and up to date.
•	No Warranty: This tool is provided "as is" without warranty of any kind. Use at your own risk.

Security Checks Performed
The script performs the following security checks:
1.	Broken Object Level Authorization
2.	Broken Authentication
3.	Broken Object Property Level Authorization
4.	Unrestricted Resource Consumption
5.	Broken Function Level Authorization
6.	Mass Assignment
7.	Security Misconfiguration
8.	Injection Attacks
9.	Improper Assets Management
10.	Unauthorized Password Change
11.	JWT Authentication Bypass
12.	Server Side Request Forgery (SSRF)
13.	Regular Expression Denial of Service (ReDoS)
14.	User Enumeration
15.	Unrestricted Access to Sensitive Business Flows
16.	Excessive Data Exposure
17.	Unsafe Consumption of APIs
Each check includes detailed remediation steps and code examples in the report.
