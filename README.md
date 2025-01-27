# Enforcer

Enforcer is a comprehensive security assessment script designed to perform a variety of checks against an API or web service. It captures network traffic into a PCAP file, records requests for later export into a Postman collection, performs numerous OWASP-style security checks (including TLS/certificate checks), integrates with SQLMap for SQL injection scanning, and generates a final PDF report detailing the results.

---

## Features

1. **Network Traffic Capture**  
   - Uses Scapy to sniff packets and logs HTTP requests.
   - Saves traffic to a `.pcap` file for later analysis.

2. **Request Recording & Postman Export**  
   - Records all requests sent during the assessment.
   - Exports them as a Postman Collection (`.json`), allowing easy replay or sharing.

3. **Extensive Security Checks**  
   - Covers OWASP Top 10 style checks (Broken Auth, BOLA, SSRF, Injection, etc.).
   - Additional TLS/certificate checks (weak ciphers, certificate issuer, protocol version, etc.).

4. **SQLMap Integration**  
   - Optionally runs SQLMap against the target URL, saving detailed output in a designated folder.

5. **PDF Reporting**  
   - Produces a fully formatted PDF containing:
     - Executive summary
     - Technical details (including pass/fail/inconclusive for each check)
     - Risk classification (Critical/High/Medium/Low)
     - Code snippet remediation

6. **Artifact Organization**  
   - Generates a dedicated folder (named after the application) for all artifacts:
     - `captured_traffic.pcap`
     - `captured_requests.postman_collection.json`
     - `sqlmap_results/`
     - `[ApplicationName]_Security_Report.pdf`
     - Any GET/POST request logs

---

## Requirements

Enforcer relies on Python 3.6 or later. The main dependencies are listed in the `requirements.txt` file. In short, you’ll need:

- Python 3.6+  
- Admin/sudo privileges (for packet capture on most OSes)

See the [Installation](#installation) section on how to install these dependencies.

---

## Installation

1. **Clone or Download** this repository:

   git clone https://github.com/YourOrg/Enforcer.git
   cd Enforcer

## Install Python Dependencies:

pip install -r requirements.txt

or (depending on your setup):


python -m pip install -r requirements.txt
Verify the script is executable (on UNIX-like systems):

chmod +x enforcer.py
Usage
Run the Script:

python3 enforcer.py
or (on UNIX-like):

./enforcer.py

---

## You may need sudo (or Run As Administrator on Windows) to capture traffic:

sudo python enforcer.py

---

## Follow Prompts

Enforcer will ask for:

The target URL (including protocol, e.g. https://example.com).
Point-of-contact email.
Application name (used for folder creation and PDF naming).
Any additional endpoints (optional).
Authentication details (API Key, Bearer Token, or Basic Auth).
Let Enforcer Work:

It will capture traffic, perform checks, possibly run SQLMap, and generate artifacts.

---

## Check Output Folder

A folder named after the application (e.g., myapp) is created.
Within that folder, you’ll find:
captured_traffic.pcap
captured_requests.postman_collection.json
[AppName]_Security_Report.pdf
sqlmap_results/ (if SQLMap was run)
Any GET/POST request logs for each captured endpoint

---

## Example Session

$ sudo python enforcer.py

Target format examples:
  https://example.com
  http://192.168.1.1
  https://api.example.com/v1

Please enter the URL of the API to scan (Including Protocol): https://api.supersecure.tld
Please enter the Point of Contact email address: security@company.com
Please enter the Application Name: SuperSecureAPI
Do you have endpoints that you need to scan? (Yes/No): Yes
How many endpoints do you have? (1-10): 2
What's the 1st endpoint URL: https://api.supersecure.tld/users
What's the 2nd endpoint URL: https://api.supersecure.tld/admin
Does the API require authentication? (Yes/No): Yes
Select authentication method (1: API Key, 2: Bearer Token, 3: Basic Auth): 2
Enter the Bearer Token: some-secret-jwt

[Captures traffic, performs checks, runs optional SQLMap, etc.]

Scan completed. Report generated.
Script execution completed.

---

## You will then see a folder named SuperSecureAPI/ containing your PDF report, PCAP file, Postman JSON, etc.

**Notes and Disclaimers** 
Privilege: Packet capture typically requires root/administrator privileges.
Ethical Use: Ensure you have explicit permission to test any target. Enforcer is intended for authorized security testing only.
SQLMap: The script attempts to use SQLMap if present. If not installed, the SQL injection check is marked inconclusive.
Example Code Blocks: Some code snippets in the vulnerability descriptions are purely illustrative. Adjust them according to your environment.
