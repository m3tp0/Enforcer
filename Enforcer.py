#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Standard Library Imports
import base64
import getpass
import json
import logging
import os
import re
import subprocess
import sys
import threading
import time
import warnings
from datetime import datetime
from urllib.parse import urlparse

# Third-Party Imports
import jwt
import requests
import validators
import shutil
from bs4 import BeautifulSoup
from colorama import Fore, Style, init
from cryptography.fernet import Fernet
from dotenv import load_dotenv
from flask import Flask, jsonify, request
from flask_jwt_extended import (
    JWTManager, create_access_token, get_jwt_identity, jwt_required
)
from jwt.exceptions import PyJWTError
from marshmallow import ValidationError
from reportlab.lib import colors
from reportlab.lib.colors import HexColor
from reportlab.lib.enums import TA_CENTER, TA_JUSTIFY, TA_RIGHT
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.lib.utils import ImageReader
from reportlab.pdfgen import canvas
from reportlab.platypus import (
    Flowable, KeepTogether, PageBreak, Paragraph, Preformatted,
    SimpleDocTemplate, Spacer, Table, TableStyle
)
from scapy.all import Raw, sniff, wrpcap
from scapy.layers.http import HTTPRequest
from sqlalchemy import create_engine, text
from werkzeug.security import check_password_hash, generate_password_hash

# Load environment variables
load_dotenv()

# Suppress warnings
warnings.filterwarnings("ignore")

# Initialize colorama
init(autoreset=True)

# Setup logging
logging.basicConfig(filename='security_assessment.log', level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s')

# Check if we are running this on windows platform
is_windows = sys.platform.startswith('win')

# Define custom colors
ORANGE = '\033[38;5;208m'  # Orange color
GREEN = Fore.GREEN
BLUE = Fore.BLUE
RED = Fore.RED
RESET = Style.RESET_ALL

# Configuration
REQUEST_TIMEOUT = 10  # seconds
MAX_RETRIES = 3

required_modules = ['requests', 'validators', 'reportlab', 'colorama', 'scapy', 'jwt', 'shutil']
missing_modules = []

for module in required_modules:
    try:
        __import__(module)
    except ImportError:
        missing_modules.append(module)

if missing_modules:
    print(f"{RED}The following modules are missing: {', '.join(missing_modules)}{RESET}")
    print(f"{GREEN}Please install them using 'pip install {' '.join(missing_modules)}'{RESET}")
    sys.exit(1)

def check_and_elevate_privileges():
    if os.name != 'nt':  # Unix-based systems
        if os.geteuid() != 0:
            try:
                print(f"{ORANGE}Script requires elevated privileges to capture network traffic.{RESET}")
                print(f"{ORANGE}Re-running the script with sudo...{RESET}")
                os.execvp('sudo', ['sudo', sys.executable] + sys.argv)
            except Exception as e:
                print(f"{RED}Failed to elevate privileges: {e}{RESET}")
                sys.exit(1)
    else:
        # Windows platform
        import ctypes
        if not ctypes.windll.shell32.IsUserAnAdmin():
            print(f"{ORANGE}Script requires elevated privileges to capture network traffic.{RESET}")
            print(f"{ORANGE}Re-running the script with administrator privileges...{RESET}")
            # Re-run the script with administrator privileges
            ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, ' '.join(sys.argv), None, 1)
            sys.exit(0)

# Utility functions
def log_error(message):
    logging.error(message)
    print(f"{RED}Error: {message}{RESET}")


def log_info(message):
    logging.info(message)
    print(f"{BLUE}{message}{RESET}")

def validate_url(url):
    if not validators.url(url):
        raise ValueError("Invalid URL format")

def safe_request(url, method='GET', data=None, json=None, headers=None, timeout=REQUEST_TIMEOUT, auth=None):
    for _ in range(MAX_RETRIES):
        try:
            if headers is None:
                headers = {}
            # Include authentication headers
            if auth:
                if auth['type'] == 'api_key':
                    headers['Authorization'] = f"ApiKey {auth['api_key']}"
                elif auth['type'] == 'bearer_token':
                    headers['Authorization'] = f"Bearer {auth['bearer_token']}"
                elif auth['type'] == 'basic_auth':
                    auth_tuple = (auth['username'], auth['password'])
                else:
                    auth_tuple = None
            else:
                auth_tuple = None

            # Use 'json' argument for JSON payloads if provided, otherwise fall back to 'data'
            if json:
                response = requests.request(method, url, json=json, headers=headers, timeout=timeout, auth=auth_tuple)
            else:
                response = requests.request(method, url, data=data, headers=headers, timeout=timeout, auth=auth_tuple)

            response.raise_for_status()  # Raises HTTPError for bad responses (4xx or 5xx)
            return response
        except requests.exceptions.HTTPError as http_err:
            print(f"Error: Request failed: {http_err.response.status_code} {http_err.response.reason} for url: {url}")
            return None
        except Exception as err:
            print(f"An unexpected error occurred: {err}")
            return None

def safe_write_file(filename, content):
    try:
        with open(filename, 'a') as f:
            f.write(content)
    except IOError as e:
        logging.error(f"Error writing to file {filename}: {e}")


def safe_read_file(filename):
    try:
        with open(filename, 'r') as f:
            return f.read()
    except IOError as e:
        logging.error(f"Error reading file {filename}: {e}")
        return ""

def analyze_response(response):
    if response is None:
        return {"type": "Unknown", "status_code": None, "content": None}

    content_type = response.headers.get('Content-Type', '')
    if 'application/json' in content_type:
        try:
            return {"type": "JSON", "status_code": response.status_code, "content": response.json()}
        except json.JSONDecodeError:
            return {"type": "Invalid JSON", "status_code": response.status_code, "content": response.text}
    elif 'text/html' in content_type:
        return {"type": "HTML", "status_code": response.status_code, "content": response.text}
    else:
        return {"type": "Other", "status_code": response.status_code, "content": response.content}

# Traffic capture functionality
class TrafficCapture:
    def __init__(self):
        self.packets = []
        self.captured_requests = []
        self.sniff_thread = None
        self.stop_sniffing = threading.Event()

    def start(self):
        self.sniff_thread = threading.Thread(target=self.sniff_packets)
        self.sniff_thread.start()

    def sniff_packets(self):
        try:
            sniff(
                prn=self.packet_callback,
                store=False,
                stop_filter=lambda x: self.stop_sniffing.is_set()
            )
        except Exception as e:
            print(f"{RED}Packet capture error: {e}{RESET}")

    def stop(self):
        self.stop_sniffing.set()
        if self.sniff_thread is not None:
            self.sniff_thread.join()

    def packet_callback(self, packet):
        # Check for Raw layer (contains HTTP payload) and HTTPRequest layer (GET/POST)
        if packet.haslayer(Raw) and packet.haslayer(HTTPRequest):
            # Extract the HTTP request details
            http_request = packet[HTTPRequest]
            method = http_request.Method.decode(errors='ignore')
            host = http_request.Host.decode(errors='ignore')
            path = http_request.Path.decode(errors='ignore')

            # Combine host and path to get the full URL
            full_url = f"http://{host}{path}"

            # Capture headers and payload
            payload = packet[Raw].load.decode(errors='ignore')

            # Log the GET or POST request
            self.captured_requests.append({
                'method': method,
                'url': full_url,
                'headers': payload
            })
            print(f"Captured {method} request to {full_url}")

        # Store the packet for saving to a PCAP file later
        self.packets.append(packet)

    def save_pcap(self, filename):
        if not self.packets:
            print(f"{ORANGE}Warning: No packets captured.{RESET}")
            return

        try:
            wrpcap(filename, self.packets)
            print(f"{GREEN}PCAP file saved to {filename}{RESET}")
        except Exception as e:
            print(f"{RED}Error saving PCAP: {e}{RESET}")

    def save_requests(self, url):
        # Separate GET and POST requests
        get_requests = []
        post_requests = []

        target_netloc = urlparse(url).netloc

        for request in self.captured_requests:
            # Parse the request URL
            request_netloc = urlparse(request['url']).netloc

            # Check if the request URL matches the target URL's netloc
            if target_netloc == request_netloc:
                if request['method'] == 'GET':
                    get_requests.append(f"GET {request['url']}\nHeaders:\n{request['headers']}")
                elif request['method'] == 'POST':
                    post_requests.append(f"POST {request['url']}\nHeaders:\n{request['headers']}")

        # Generate filenames based on the URL
        safe_url = url.replace('://', '_').replace('/', '_')
        get_filename = f"{safe_url}_get_requests.txt"
        post_filename = f"{safe_url}_post_requests.txt"

        # Save GET requests to a file
        if get_requests:
            with open(get_filename, 'w') as f:
                f.write('\n\n'.join(get_requests))
            print(f"{GREEN}GET requests saved to {get_filename}{RESET}")
        else:
            print(f"{ORANGE}No GET requests captured for {url}{RESET}")

        # Save POST requests to a file
        if post_requests:
            with open(post_filename, 'w') as f:
                f.write('\n\n'.join(post_requests))
            print(f"{GREEN}POST requests saved to {post_filename}{RESET}")
        else:
            print(f"{ORANGE}No POST requests captured for {url}{RESET}")

        # Return both GET and POST requests
        return get_requests + post_requests

# Function to display banner
def banner():
    print(f"""{RED}
⠀⠀⠀⠀⠀⠀⣰⠂⠀⣼⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣠⣀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⡟⢆⢠⢣⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⡘⡇⠹⢦⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠹⣦⣹⢸⡖⠤⢀⠀⠘⢿⠛⢔⠢⡀⠃⠣⠀⠇⢡⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠹⠀⡷⣄⠠⡈⠑⠢⢧⠀⢢⠰⣼⢶⣷⣾⠀⠃⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠤⢖⡆⠰⡙⢕⢬⡢⣄⠀⠑⢼⠀⠚⣿⢆⠀⠱⣸⠀⠀⠀⠀
⠀⠀⠀⠀⠀⢀⣤⡶⠮⢧⡀⠑⡈⢢⣕⡌⢶⠀⠀⣱⣠⠉⢺⡄⠀⢹⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⢀⡸⠀⠈⡗⢄⡈⢆⠙⠿⣶⣿⠿⢿⣷⣴⠉⠹⢶⢾⡆⠀⠀⠀
⠀⠀⠀⢠⠶⠿⡉⠉⠉⠙⢻⣮⡙⢦⣱⡐⣌⠿⡄⢁⠄⠑⢤⣀⠐⢻⡇⠀⠀⠀
⠀⠀⠀⢀⣠⠾⠖⠛⢻⠟⠁⢘⣿⣆⠹⢷⡏⠀⠈⢻⣤⡆⠀⠑⢴⠉⢿⣄⠀⠀
⠀⠀⢠⠞⢃⢀⣠⡴⠋⠀⠈⠁⠉⢻⣷⣤⠧⡀⠀⠈⢻⠿⣿⡀⠀⢀⡀⣸⠀⠀
⠀⠀⢀⠔⠋⠁⡰⠁⠀⢀⠠⣤⣶⠞⢻⡙⠀⠙⢦⠀⠈⠓⢾⡟⡖⠊⡏⡟⠀⠀
⠀⢠⣋⢀⣠⡞⠁⠀⠔⣡⣾⠋⠉⢆⡀⢱⡀⠀⠀⠀⠀⠀⠀⢿⡄⠀⢇⠇⠀⠀
⠀⠎⣴⠛⢡⠃⠀⠀⣴⡏⠈⠢⣀⣸⣉⠦⣬⠦⣀⠀⣄⠀⠀⠈⠃⠀⠀⠙⡀   ⠀ _____                                                    _____ 
⠀⡸⡁⣠⡆⠀⠀⣾⠋⠑⢄⣀⣠⡤⢕⡶⠁⠀⠀⠁⢪⠑⠤⡀⠀⢰⡐⠂⠑⢀  ( ___ )                                                  ( ___ )
⠀⠏⡼⢋⠇⠀⣸⣟⣄⠀⠀⢠⡠⠓⣿⠇⠀⠀⠀⠀⠀⠑⢄⡌⠆⢰⣷⣀⡀⢸   |   |~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~|   | 
⠀⣸⠁⢸⠀⢀⡿⡀⠀⠈⢇⡀⠗⢲⡟⠀⠀⠀⠀⠀⠀⠀⠀⠹⡜⠦⣈⠀⣸⡄   |   |  _____ _   _______ ___________  _____ ___________  |   | 
⠀⣧⠤⣼⠀⢸⠇⠉⠂⠔⠘⢄⣀⢼⠃⡇⠀⠀⠀⠀⠀⠀⠀⠀⠈⠑⠚⠳⠋⠀   |   | |  ___| \ | |  ___|  _  | ___ \/  __ \  ___| ___ \ |   | 
⠐⠇⣰⢿⠀⣾⢂⣀⣀⡸⠆⠁⠀⣹⠀⢡⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀   |   | | |__ |  \| | |_  | | | | |_/ /| /  \/ |__ | |_/ / |   | 
⠀⢀⡏⣸⠀⣟⠁⠀⠙⢄⠼⠁⠈⢺⠀⠘⡆⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀   |   | |  __|| . ` |  _| | | | |    / | |   |  __||    /  |   | 
⠀⠈⡏⣸⢰⡯⠆⢤⠔⠊⢢⣀⣀⡼⡇⠀⠹⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀   |   | | |___| |\  | |   \ \_/ / |\ \ | \__/\ |___| |\ \  |   | 
⠀⠀⢠⢻⢸⡇⠀⠀⠑⣤⠊⠀⠀⠈⣧⠀⠀⠙⣄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀   |   | \____/\_| \_|_|    \___/\_| \_| \____|____/\_| \_| |   | 
⠀⠀⠸⣼⢸⠟⠑⠺⡉⠈⢑⠆⠠⠐⢻⡄⠀⠀⠈⢆⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀   |___|~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~|___| 
⠀⠀⠀⡟⣸⡀⠀⠀⣈⣶⡁⠀⠀⠀⢠⢻⡄⠀⠀⠀⠑⠤⣄⡀⠀⠀⠀⠀⠀⠀  (_____)                                                  (_____)
⠀⠀⢰⠁⣿⡿⠟⢏⠁⠀⢈⠖⠒⠊⠉⠉⠹⣄⠀⠀⠀⠀⠀⠈⠑⠢⡀⠀⠀⠀
⠀⣀⠟⢰⡇⠀⠀⠈⢢⡴⠊⠀⠀⠀⠀⠀⣸⢙⣷⠄⢀⠀⠠⠄⠐⠒⠚⠀⠀⠀
⠘⠹⠤⠛⠛⠲⢤⠐⠊⠈⠂⢤⢀⠠⠔⠊⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠣⢀⡀⠔⠃⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀

    """)

banner()

# User input functions
def get_user_input():
    print(f"{ORANGE}\nTarget format examples:\n  https://example.com\n  http://192.168.1.1\n  https://api.example.com/v1\n{RESET}")
    full_target_url = input(f"{ORANGE}Please enter the URL of the API to scan (Including Protocol): {RESET}")
    try:
        validate_url(full_target_url)
    except ValueError as e:
        log_error(f"Invalid URL: {e}")
        sys.exit(1)

    security_assessor = input(f"{ORANGE}Please enter the Point of Contact email address: {RESET}")
    application_name = input(f"{ORANGE}Please enter the Application Name: {RESET}").replace(" ", "")
    endpoints = get_endpoints()

    # Save user input to a file for future use
    safe_write_file("user_input.txt", f"{full_target_url}\n{security_assessor}\n{application_name}\n")
    for endpoint in endpoints:
        safe_write_file("user_input.txt", f"{endpoint}\n")

    return full_target_url, security_assessor, application_name, endpoints

def get_endpoints():
    has_endpoints = input(f"{ORANGE}Do you have endpoints that you need to scan? (Yes/No): {RESET}").lower()
    if has_endpoints == "yes":
        num_endpoints = get_num_endpoints()
        endpoints = []
        for i in range(num_endpoints):
            endpoint_url = input(f"{ORANGE}What's the {ordinal(i + 1)} endpoint URL: {RESET}")
            try:
                validate_url(endpoint_url)
                endpoints.append(endpoint_url)
            except ValueError as e:
                log_error(f"Invalid URL: {e}")
        return endpoints
    else:
        return []

def get_num_endpoints():
    while True:
        try:
            num_endpoints = int(input("How many endpoints do you have? (1-10): "))
            if 1 <= num_endpoints <= 10:
                return num_endpoints
            else:
                print("Invalid number of endpoints. Please enter a number between 1 and 10.")
        except ValueError:
            print("Invalid input. Please enter a number.")

def ordinal(n):
    suffix = ['th', 'st', 'nd', 'rd', 'th'][min(n % 10, 4)]
    if 11 <= (n % 100) <= 13:
        suffix = 'th'
    return str(n) + suffix

def read_user_input_from_file():
    try:
        with open("user_input.txt", "r") as f:
            lines = f.readlines()
        if len(lines) >= 3:
            full_target_url = lines[0].strip()
            security_assessor = lines[1].strip()
            application_name = lines[2].strip()
            endpoints = [line.strip() for line in lines[3:]]
            return full_target_url, security_assessor, application_name, endpoints
        else:
            # Not enough data, return None values
            return None, None, None, None
    except FileNotFoundError:
        # File not found, return None values without logging an error
        return None, None, None, None

def get_authentication_details():
    auth_type = input(f"{ORANGE}Does the API require authentication? (Yes/No): {RESET}").strip().lower()
    if auth_type == 'yes':
        auth_method = input(f"{ORANGE}Select authentication method (1: API Key, 2: Bearer Token, 3: Basic Auth): {RESET}").strip()
        if auth_method == '1':
            api_key = input(f"{ORANGE}Enter the API Key: {RESET}").strip()
            return {'type': 'api_key', 'api_key': api_key}
        elif auth_method == '2':
            bearer_token = input(f"{ORANGE}Enter the Bearer Token: {RESET}").strip()
            return {'type': 'bearer_token', 'bearer_token': bearer_token}
        elif auth_method == '3':
            username = input(f"{ORANGE}Enter the username: {RESET}").strip()
            password = getpass.getpass(f"{ORANGE}Enter the password: {RESET}")
            return {'type': 'basic_auth', 'username': username, 'password': password}
        else:
            print(f"{RED}Invalid authentication method selected.{RESET}")
            sys.exit(1)
    else:
        return None

# Security check functions
def perform_broken_object_level_authorization_check(url, auth=None):
    log_info("Performing Broken Object Level Authorization check...")
    # Test for IDOR
    response = safe_request(f"{url}/api/user/2", headers={"Authorization": "Bearer user1_token"}, auth=None)
    if response and response.status_code == 200:
        return "Check failed", create_bola_remediation("idor"), analyze_response(response)

    # Test for forced browsing
    response = safe_request(f"{url}/admin", headers={"Authorization": "Bearer user_token"}, auth=None)
    if response and response.status_code == 200:
        return "Check failed", create_bola_remediation("forced_browsing"), analyze_response(response)

    # Test for privilege escalation
    response = safe_request(f"{url}/api/admin/users", headers={"Authorization": "Bearer user_token"}, auth=None)
    if response and response.status_code == 200:
        return "Check failed", create_bola_remediation("privilege_escalation"), analyze_response(response)

    return "Check passed", None, "N/A"


def create_bola_remediation(issue_type):
    base_remediation = """To mitigate Broken Object Level Authorization:<br/><br/>

1. Implement proper access controls for all object references.<br/>
2. Use indirect object references instead of direct object references.<br/>
3. Validate user permissions before allowing access to objects.<br/><br/>
"""
    if issue_type == "idor":
        code_snippet = """
```python<br/>
@app.route('/api/user/<int:user_id>')<br/>
@login_required<br/>
def get_user_data(user_id):<br/>
    if current_user.id != user_id and not current_user.is_admin:<br/>
        return jsonify({"error": "Unauthorized access"}), 403<br/>
    user_data = get_user_by_id(user_id)<br/>
    return jsonify(user_data), 200<br/>
```
"""
    elif issue_type == "forced_browsing":
        code_snippet = """
```python<br/>
@app.route('/admin')<br/>
@login_required<br/>
@admin_required<br/>
def admin_panel():<br/>
    # Admin panel logic<br/>
    pass<br/>
```
"""
    else:  # privilege_escalation
        code_snippet = """
```python<br/>
def check_admin_access(user):<br/>
    return user.role == 'admin'<br/><br/>

@app.route('/api/admin/users')<br/>
@login_required<br/>
def get_all_users():<br/>
    if not check_admin_access(current_user):<br/>
        return jsonify({"error": "Admin access required"}), 403<br/>
    users = get_all_users_from_db()<br/>
    return jsonify(users), 200<br/>
```
"""
    return base_remediation + code_snippet

def perform_broken_authentication_check(url, auth=None):
    log_info("Performing Broken Authentication check...")
    # Test weak passwords
    weak_passwords = ["password", "123456", "admin"]
    for password in weak_passwords:
        response = safe_request(f"{url}/login", method="POST", data={"username": "admin", "password": password}, auth=None)
        if response and "login successful" in response.text.lower():
            return "Check failed", create_broken_auth_remediation(), analyze_response(response)

    # Test for lack of brute force protection
    for _ in range(10):
        response = safe_request(f"{url}/login", method="POST", data={"username": "admin", "password": "wrongpassword"}, auth=None)
        if response and response.status_code != 429:  # 429 is "Too Many Requests"
            return "Check failed", create_broken_auth_remediation(), analyze_response(response)

    # Test for insecure session management
    response = safe_request(f"{url}/login", method="POST", data={"username": "testuser", "password": "testpassword"}, auth=None)
    if response and 'session' in response.cookies:
        session_cookie = response.cookies['session']
        if not session_cookie.startswith('__Host-'):  # Check for secure prefix
            return "Check failed", create_broken_auth_remediation(), analyze_response(response)

    return "Check passed", None, "N/A"

def create_broken_auth_remediation():
    return """To mitigate Broken Authentication:<br/><br/>

1. Implement strong password policies.<br/>
2. Use multi-factor authentication.<br/>
3. Implement account lockout mechanisms.<br/>
4. Use secure session management.<br/>
5. Implement proper brute force protection.<br/><br/>

Sample code for implementing account lockout and secure session:<br/>
```python<br/>
from flask import Flask, request, session<br/>
from werkzeug.security import generate_password_hash, check_password_hash<br/><br/>

app = Flask(__name__)<br/>
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY')<br/>
app.config['SESSION_COOKIE_SECURE'] = True<br/>
app.config['SESSION_COOKIE_HTTPONLY'] = True<br/>
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'<br/><br/>

def login(username, password):<br/>
    user = get_user(username)<br/>
    if user.failed_attempts >= 5:<br/>
        return jsonify({"error": "Account locked. Please reset your password."}), 403<br/>
    if not check_password_hash(user.password, password):<br/>
        user.failed_attempts += 1<br/>
        return jsonify({"error": "Invalid credentials"}), 401<br/>
    user.failed_attempts = 0<br/>
    session['user_id'] = user.id<br/>
    return jsonify({"message": "Login successful"}), 200<br/><br/>

@app.route('/login', methods=['POST'])<br/>
def login_route():<br/>
    username = request.json.get('username')<br/>
    password = request.json.get('password')<br/><br/>

    if not username or not password:<br/>
        return jsonify({"error": "Username and password are required"}), 400<br/><br/>

    return login(username, password)<br/><br/>

@app.route('/logout', methods=['POST'])<br/>
def logout():<br/>
    session.clear()<br/>
    return jsonify({"message": "Logout successful"}), 200<br/><br/>

@app.before_request<br/>
def before_request():<br/>
    session.permanent = True<br/>
    app.permanent_session_lifetime = timedelta(minutes=30)<br/><br/>

def reset_password(username):<br/>
    user = get_user(username)<br/>
    if user:<br/>
        # Generate a secure reset token<br/>
        reset_token = secrets.token_urlsafe(32)<br/>
        user.reset_token = reset_token<br/>
        user.reset_token_expiry = datetime.utcnow() + timedelta(hours=1)<br/>
        # Send reset email to user (implementation not shown)<br/>
        send_reset_email(user.email, reset_token)<br/>
        return jsonify({"message": "Password reset instructions sent to your email"}), 200<br/>
    return jsonify({"error": "User not found"}), 404<br/><br/>

@app.route('/reset-password', methods=['POST'])<br/>
def reset_password_route():<br/>
    username = request.json.get('username')<br/>
    return reset_password(username)<br/><br/>

# Add CSRF protection<br/>
from flask_wtf.csrf import CSRFProtect<br/>
csrf = CSRFProtect(app)<br/><br/>

# Add rate limiting<br/>
from flask_limiter import Limiter<br/>
from flask_limiter.util import get_remote_address<br/><br/>

limiter = Limiter(<br/>
    app,<br/>
    key_func=get_remote_address,<br/>
    default_limits=["200 per day", "50 per hour"]<br/>
)<br/><br/>

@limiter.limit("5 per minute")<br/>
@app.route('/login', methods=['POST'])<br/>
def rate_limited_login():<br/>
    return login_route()<br/>
```<br/>
"""

def perform_broken_object_property_level_authorization_check(url, auth=None):
    log_info("Performing Broken Object Property Level Authorization check...")

    # Helper function to handle responses
    def handle_response(response, check_type):
        if response is None:
            log_error(f"Failed to reach {check_type} endpoint.")
            return "Check inconclusive", None, "N/A"
        if response.status_code == 200:
            return "Check failed", create_bopla_remediation(check_type), analyze_response(response)
        elif response.status_code == 503:
            log_error(f"Service Unavailable (503) for {check_type} endpoint: {url}")
            return "Check inconclusive", None, "N/A"
        return None

    # Test vertical privilege escalation
    response = safe_request(f"{url}/api/admin/users", headers={"Authorization": "Bearer user_token"}, auth=None)
    result = handle_response(response, "vertical")
    if result:
        return result

    # Test horizontal privilege escalation
    response = safe_request(f"{url}/api/user/2/profile", headers={"Authorization": "Bearer user1_token"}, auth=None)
    result = handle_response(response, "horizontal")
    if result:
        return result

    # Test for unauthorized property modification
    response = safe_request(f"{url}/api/user/1/update", method="POST",
                            json={"role": "admin"}, headers={"Authorization": "Bearer user_token"}, auth=None)
    result = handle_response(response, "property")
    if result:
        return result

    return "Check passed", None, "N/A"

def create_bopla_remediation(escalation_type):
    base_remediation = """To mitigate Broken Object Property Level Authorization:<br/>
1. Implement proper access controls for each object property.<br/>
2. Use role-based access control (RBAC) for fine-grained permissions.<br/>
3. Validate user permissions before allowing access to or modification of object properties.<br/>
"""
    if escalation_type == "vertical":
        code_snippet = """
```python<br/>
from flask_rbac import RBAC<br/><br/>

rbac = RBAC()<br/><br/>

@app.route('/api/admin/users')<br/>
@rbac.allow(['admin'], methods=['GET'])<br/>
def get_all_users():<br/>
    # Admin-only functionality<br/>
    pass<br/>
```<br/>
"""
    elif escalation_type == "horizontal":
        code_snippet = """
```python<br/>
@app.route('/api/user/<int:user_id>/profile')<br/>
@login_required<br/>
def get_user_profile(user_id):<br/>
    if current_user.id != user_id:<br/>
        return jsonify({"error": "Not authorized"}), 403<br/>
    # Return user profile<br/>
    pass<br/>
```<br/>
"""
    else:  # property
        code_snippet = """
```python<br/>
@app.route('/api/user/<int:user_id>/update', methods=['POST'])<br/>
@login_required<br/>
def update_user(user_id):<br/>
    if current_user.id != user_id and not current_user.is_admin:<br/>
        return jsonify({"error": "Not authorized"}), 403<br/>
    user = User.query.get(user_id)<br/>
    for key, value in request.json.items():<br/>
        if key in ['username', 'email']:  # Whitelist of allowed properties<br/>
            setattr(user, key, value)<br/>
    db.session.commit()<br/>
    return jsonify({"message": "User updated successfully"})<br/>
```<br/>
"""
    return base_remediation + code_snippet

def perform_unrestricted_resource_consumption_check(url, auth=None):
    log_info("Performing Unrestricted Resource Consumption check...")

    # Test for resource exhaustion
    large_payload = "A" * 1000000  # 1MB of data
    response = safe_request(f"{url}/api/process", method="POST", data=large_payload, auth=auth)
    if response and response.status_code == 200:
        return "Check failed", create_resource_consumption_remediation("exhaustion"), analyze_response(response)

    # Test for lack of rate limiting
    start_time = time.time()
    for _ in range(100):  # Send 100 requests rapidly
        safe_request(url, auth=auth)
    end_time = time.time()
    if end_time - start_time < 5:  # If 100 requests processed in less than 5 seconds
        return "Check failed", create_resource_consumption_remediation("rate_limiting"), "N/A"

    # Test for CPU-intensive operations
    response = safe_request(
        f"{url}/api/hash",
        method="POST",
        json={"data": "a" * 1000000, "iterations": 1000000},
        auth=auth
    )
    if response and response.elapsed.total_seconds() > 10:
        return "Check failed", create_resource_consumption_remediation("cpu_intensive"), analyze_response(response)

    return "Check passed", None, "N/A"

def create_resource_consumption_remediation(issue_type):
    base_remediation = """To mitigate Unrestricted Resource Consumption:<br/>
1. Implement rate limiting and throttling.<br/>
2. Set appropriate resource quotas.<br/>
3. Use efficient algorithms and data structures.<br/>
4. Implement timeouts for long-running operations.<br/>
"""
    if issue_type == "exhaustion":
        code_snippet = """
```python<br/>
@app.route('/api/process', methods=['POST'])<br/>
def process_data():<br/>
    data = request.get_data()<br/>
    if len(data) > 1000000:  # 1MB limit<br/>
        return jsonify({"error": "Payload too large"}), 413<br/>
    # Process data<br/>
    pass<br/>
```<br/>
"""
    elif issue_type == "rate_limiting":
        code_snippet = """
```python<br/>
from flask_limiter import Limiter<br/>
from flask_limiter.util import get_remote_address<br/><br/>

limiter = Limiter(<br/>
    app,<br/>
    key_func=get_remote_address,<br/>
    default_limits=["200 per day", "50 per hour"]<br/>
)<br/><br/>

@app.route("/api/resource")<br/>
@limiter.limit("1 per second")<br/>
def rate_limited_resource():<br/>
    return "This is a rate limited resource"<br/>
```<br/>
"""
    else:  # cpu_intensive
        code_snippet = """
```python<br/>
import threading<br/>
from functools import wraps<br/><br/>

def timeout(seconds):<br/>
    def decorator(func):<br/>
        @wraps(func)<br/>
        def wrapper(*args, **kwargs):<br/>
            result = [TimeoutError('Function call timed out')]<br/>
            def worker():<br/>
                try:<br/>
                    result[0] = func(*args, **kwargs)<br/>
                except Exception as e:<br/>
                    result[0] = e<br/>
            thread = threading.Thread(target=worker)<br/>
            thread.start()<br/>
            thread.join(seconds)<br/>
            if isinstance(result[0], BaseException):<br/>
                raise result[0]<br/>
            return result[0]<br/>
        return wrapper<br/>
    return decorator<br/><br/>

@app.route('/api/hash', methods=['POST'])<br/>
@timeout(10)<br/>
def compute_hash():<br/>
    data = request.json['data']<br/>
    iterations = min(request.json['iterations'], 100000)  # Cap iterations<br/>
    # Perform hash computation<br/>
    pass<br/>
```<br/>
"""
    return base_remediation + code_snippet

def perform_broken_function_level_authorization_check(url, auth=None):
    log_info("Performing Broken Function Level Authorization check...")

    # Test for horizontal authorization bypass
    response = safe_request(f"{url}/api/user/2/data", auth=auth)
    if response and response.status_code == 200:
        return "Check failed", create_bfla_remediation("horizontal"), analyze_response(response)

    # Test for vertical authorization bypass
    response = safe_request(f"{url}/api/admin/panel", auth=auth)
    if response and response.status_code == 200:
        return "Check failed", create_bfla_remediation("vertical"), analyze_response(response)

    # Test for missing function level checks
    response = safe_request(f"{url}/api/delete_user/1", method="POST", auth=auth)
    if response and response.status_code == 200:
        return "Check failed", create_bfla_remediation("missing_checks"), analyze_response(response)

    return "Check passed", None, "N/A"

def create_bfla_remediation(bypass_type):
    base_remediation = """To mitigate Broken Function Level Authorization:<br/>
1. Implement proper role-based access control (RBAC).<br/>
2. Use declarative access control mechanisms.<br/>
3. Centralize authorization logic.<br/>
4. Implement function-level checks for all sensitive operations.<br/><br/>

CWE-285: Improper Authorization<br/>
"""
    if bypass_type == "horizontal":
        code_snippet = """
```python<br/>
@app.route('/api/user/<int:user_id>/data')<br/>
@login_required<br/>
def get_user_data(user_id):<br/>
    if current_user.id != user_id:<br/>
        return jsonify({"error": "Not authorized"}), 403<br/>
    # Return user data<br/>
    pass<br/>
```<br/>
"""
    elif bypass_type == "vertical":
        code_snippet = """
```python<br/>
from flask_rbac import RBAC<br/><br/>

rbac = RBAC()<br/><br/>

@app.route('/api/admin/panel')<br/>
@rbac.allow(['admin'], methods=['GET'])<br/>
def admin_panel():<br/>
    # Admin panel logic<br/>
    pass<br/>
```<br/>
"""
    else:  # missing_checks
        code_snippet = """
```python<br/>
from functools import wraps<br/><br/>

def admin_required(f):<br/>
    @wraps(f)<br/>
    def decorated_function(*args, **kwargs):<br/>
        if not current_user.is_admin:<br/>
            return jsonify({"error": "Admin access required"}), 403<br/>
        return f(*args, **kwargs)<br/>
    return decorated_function<br/><br/>

@app.route('/api/delete_user/<int:user_id>', methods=['POST'])<br/>
@login_required<br/>
@admin_required<br/>
def delete_user(user_id):<br/>
    # Delete user logic<br/>
    pass<br/>
```
"""
    return base_remediation + code_snippet

def perform_unrestricted_access_to_sensitive_business_flows_check(url, auth=None):
    log_info("Performing Unrestricted Access to Sensitive Business Flows check...")
    sensitive_endpoints = ['/api/transfer', '/api/delete_account', '/api/change_role']
    for endpoint in sensitive_endpoints:
        response = safe_request(f"{url}{endpoint}", method="POST", json={"amount": 1000, "to": "attacker"}, auth=auth)
        if response and response.status_code == 200:
            return "Check failed", create_sensitive_flow_remediation(), analyze_response(response)
    return "Check passed", None, "N/A"

def create_sensitive_flow_remediation():
    return """To mitigate Unrestricted Access to Sensitive Business Flows:<br/>
1. Implement proper authentication and authorization for all sensitive endpoints.<br/>
2. Use multi-factor authentication for critical operations.<br/>
3. Implement transaction signing for high-value operations.<br/>
4. Log and monitor all access to sensitive business flows.<br/><br/>

CWE-306: Missing Authentication for Critical Function<br/><br/>

Sample code for implementing transaction signing:<br/>
```python<br/>
import hmac<br/>
import hashlib<br/><br/>

def sign_transaction(transaction_data, user_secret):<br/>
    return hmac.new(user_secret.encode(), transaction_data.encode(), hashlib.sha256).hexdigest()<br/><br/>

@app.route('/api/transfer', methods=['POST'])<br/>
@login_required<br/>
def transfer_funds():<br/>
    amount = request.json.get('amount')<br/>
    to = request.json.get('to')<br/>
    signature = request.headers.get('X-Transaction-Signature')<br/><br/>

    expected_signature = sign_transaction(f"{amount}{to}", current_user.secret)<br/>
    if not hmac.compare_digest(signature, expected_signature):<br/>
        return jsonify({"error": "Invalid transaction signature"}), 403<br/><br/>

    # Proceed with the transfer<br/>
    pass<br/>
```
"""

def perform_server_side_request_forgery_check(url, auth=None):
    log_info("Performing Server Side Request Forgery check...")

    # Test for SSRF vulnerability
    ssrf_payload = "http://localhost:22"  # Attempt to access SSH port
    response = safe_request(f"{url}/api/fetch?url={ssrf_payload}", auth=auth)
    if response and "SSH" in response.text:
        return "Check failed", create_ssrf_remediation(), analyze_response(response)

    # Test for DNS rebinding attack
    dns_rebinding_payload = "http://attacker-controlled-domain.com"
    response = safe_request(f"{url}/api/fetch?url={dns_rebinding_payload}", auth=auth)
    if response and response.status_code == 200:
        return "Check failed", create_ssrf_remediation(), analyze_response(response)

    # Test for bypassing localhost restriction
    bypass_payload = "http://127.1:22"
    response = safe_request(f"{url}/api/fetch?url={bypass_payload}", auth=auth)
    if response and "SSH" in response.text:
        return "Check failed", create_ssrf_remediation(), analyze_response(response)

    return "Check passed", None, "N/A"

def create_ssrf_remediation():
    return """To mitigate Server Side Request Forgery (SSRF) vulnerabilities:<br/>
1. Implement a whitelist of allowed domains and protocols.<br/>
2. Use a separate, restricted DNS server for internal name resolution.<br/>
3. Implement network segmentation to isolate sensitive services.<br/>
4. Use URL parsing libraries to validate and sanitize user input.<br/>
5. Implement proper output encoding to prevent response splitting.<br/><br/>

CWE-918: Server-Side Request Forgery (SSRF)<br/><br/>

Sample code for URL validation:<br/>
```python<br/>
from urllib.parse import urlparse<br/>
from flask import abort<br/><br/>

ALLOWED_HOSTS = ['api.example.com', 'cdn.example.com']<br/>
ALLOWED_SCHEMES = ['http', 'https']<br/><br/>

def is_safe_url(url):<br/>
    try:<br/>
        result = urlparse(url)<br/>
        return result.scheme in ALLOWED_SCHEMES and result.netloc in ALLOWED_HOSTS<br/>
    except ValueError:<br/>
        return False<br/><br/>

@app.route('/api/fetch')<br/>
def fetch_url():<br/>
    url = request.args.get('url')<br/>
    if not is_safe_url(url):<br/>
        abort(400, description="Invalid URL")<br/>
    # Proceed with fetching the URL<br/>
    pass<br/>
```
"""

def perform_security_misconfiguration_check(url, auth=None):
    log_info("Performing Security Misconfiguration check...")
    response = safe_request(url, auth=auth)
    if response:
        server_header = response.headers.get('Server')
        if server_header and server_header != 'Secured Server':
            return "Check failed", create_security_misconfiguration_remediation(), analyze_response(response)
    return "Check passed", None, "N/A"

def create_security_misconfiguration_remediation():
    return """To mitigate Security Misconfiguration:<br/>
1. Implement secure default configurations.<br/>
2. Use the principle of least privilege for all accounts and services.<br/>
3. Remove unnecessary features, components, and documentation.<br/>
4. Update and patch systems regularly.<br/>
5. Implement a strong Content Security Policy (CSP).<br/><br/>

CWE-16: Configuration<br/><br/>

Sample code for implementing a Content Security Policy:<br/>
```python<br/>
from flask import Flask, make_response<br/><br/>

app = Flask(__name__)<br/><br/>

@app.after_request<br/>
def add_security_headers(response):<br/>
    response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'"<br/>
    response.headers['X-Content-Type-Options'] = 'nosniff'<br/>
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'<br/>
    response.headers['X-XSS-Protection'] = '1; mode=block'<br/>
    return response<br/>
```
"""

def perform_improper_assets_management_check(url, auth=None):
    log_info("Performing Improper Assets Management check...")
    old_endpoints = ['/api/v1/users', '/api/beta/admin', '/api/test/debug']
    for endpoint in old_endpoints:
        response = safe_request(f"{url}{endpoint}", auth=auth)
        if response and response.status_code != 404:
            return "Check failed", create_improper_assets_management_remediation(), analyze_response(response)
    return "Check passed", None, "N/A"

def create_improper_assets_management_remediation():
    return """To mitigate Improper Assets Management:<br/>
1. Maintain an up-to-date inventory of all API versions and endpoints.<br/>
2. Implement proper versioning for your APIs.<br/>
3. Regularly review and remove deprecated API versions and endpoints.<br/>
4. Implement strong access controls for all API endpoints.<br/><br/>

CWE-1059: Incomplete Documentation<br/><br/>

Sample code for API versioning:<br/>
```python<br/>
from flask import Flask, Blueprint<br/><br/>

app = Flask(__name__)<br/><br/>

api_v1 = Blueprint('api_v1', __name__, url_prefix='/api/v1')<br/>
api_v2 = Blueprint('api_v2', __name__, url_prefix='/api/v2')<br/><br/>

@api_v1.route('/users')<br/>
def get_users_v1():<br/>
    # V1 implementation<br/>
    pass<br/><br/>

@api_v2.route('/users')<br/>
def get_users_v2():<br/>
    # V2 implementation<br/>
    pass<br/><br/>

app.register_blueprint(api_v1)<br/>
app.register_blueprint(api_v2)<br/>
```
"""

def perform_injection_check(url, auth=None):
    log_info("Performing Injection check...")
    payloads = [
        "' OR '1'='1",
        "'; DROP TABLE users; --",
        "<script>alert('XSS')</script>"
    ]
    for payload in payloads:
        response = safe_request(f"{url}/api/search?q={payload}", auth=auth)
        if response and (response.status_code == 500 or payload in response.text):
            return "Check failed", create_injection_remediation(), analyze_response(response)
    return "Check passed", None, "N/A"

def create_injection_remediation():
    return """To mitigate Injection vulnerabilities:<br/>
1. Use parameterized queries or prepared statements for all database operations.<br/>
2. Implement proper input validation and sanitization for all user inputs.<br/>
3. Use Object-Relational Mapping (ORM) tools to abstract database operations.<br/>
4. Implement the principle of least privilege for database accounts.<br/><br/>

CWE-89: SQL Injection<br/>
CWE-79: Cross-site Scripting<br/><br/>

Sample code for using parameterized queries:<br/>
```python<br/>
import sqlite3<br/><br/>

def safe_query(user_id):<br/>
    conn = sqlite3.connect('example.db')<br/>
    cursor = conn.cursor()<br/>
    cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))<br/>
    result = cursor.fetchone()<br/>
    conn.close()<br/>
    return result<br/><br/>

# Usage<br/>
user_data = safe_query(user_id)<br/>
```
"""

def perform_unauthorized_password_change_check(url, auth=None):
    log_info("Performing Unauthorized Password Change check...")
    response = safe_request(
        f"{url}/api/change_password",
        method="POST",
        json={"user_id": "another_user", "new_password": "hacked"},
        auth=auth
    )
    if response and response.status_code == 200:
        return "Check failed", create_unauthorized_password_change_remediation(), analyze_response(response)
    return "Check passed", None, "N/A"

def create_unauthorized_password_change_remediation():
    return """To mitigate Unauthorized Password Change vulnerabilities:<br/>
1. Always require current password verification for password changes.<br/>
2. Implement proper authentication checks before allowing password changes.<br/>
3. Use secure session management to ensure the user is logged in.<br/>
4. Implement rate limiting on password change attempts.<br/><br/>

CWE-620: Unverified Password Change<br/><br/>

Sample code for secure password change:<br/>
```python<br/>
@app.route('/api/change_password', methods=['POST'])<br/>
@login_required<br/>
def change_password():<br/>
    current_password = request.json.get('current_password')<br/>
    new_password = request.json.get('new_password')<br/><br/>

    if not current_password or not new_password:<br/>
        return jsonify({"error": "Missing required fields"}), 400<br/><br/>

    if not check_password_hash(current_user.password, current_password):<br/>
        return jsonify({"error": "Current password is incorrect"}), 401<br/><br/>

    current_user.password = generate_password_hash(new_password)<br/>
    db.session.commit()<br/><br/>

    return jsonify({"message": "Password changed successfully"}), 200<br/>
```
"""

def perform_mass_assignment_check(url, auth=None):
    log_info("Performing Mass Assignment check...")

    # Mass assignment payload
    payload = {
        "username": "newuser",
        "email": "newuser@example.com",
        "is_admin": True  # This should not be allowed by secure APIs
    }

    # Send the POST request
    response = safe_request(f"{url}/api/create_user", method="POST", json=payload, auth=auth)

    # Check if the mass assignment worked, it should return success if vulnerable
    if response and response.status_code == 200:
        return "Check failed", create_mass_assignment_remediation(), analyze_response(response)

    # If no mass assignment occurred or the server blocked the request
    return "Check passed", None, "N/A"

def create_mass_assignment_remediation():
    return """To mitigate Mass Assignment vulnerabilities:<br/>
1. Use a whitelist approach to explicitly allow only certain fields to be mass-assigned.<br/>
2. Implement strong server-side validation for all input fields.<br/>
3. Use data transfer objects (DTOs) to control which properties can be set.<br/><br/>

CWE-915: Improperly Controlled Modification of Dynamically-Determined Object Attributes<br/><br/>

Sample code for preventing mass assignment:<br/>
```python<br/>
from flask import request, jsonify<br/>
from marshmallow import Schema, fields<br/><br/>

class UserCreateSchema(Schema):<br/>
    username = fields.Str(required=True)<br/>
    email = fields.Email(required=True)<br/>
    # Note: is_admin is not included in this schema<br/><br/>

@app.route('/api/create_user', methods=['POST'])<br/>
def create_user():<br/>
    schema = UserCreateSchema()<br/>
    try:<br/>
        data = schema.load(request.json)<br/>
    except ValidationError as err:<br/>
        return jsonify(err.messages), 400<br/><br/>

    # Create user with validated data<br/>
    user = User(**data)<br/>
    db.session.add(user)<br/>
    db.session.commit()<br/>
    return jsonify({"message": "User created successfully"}), 201<br/>
```
"""

def perform_jwt_authentication_bypass_check(url, auth=None):
    log_info("Performing JWT Authentication Bypass check...")
    # Create a forged token
    forged_token = jwt.encode({"user_id": "admin"}, "guess_the_secret", algorithm="HS256")
    headers = {"Authorization": f"Bearer {forged_token}"}

    # Merge with existing headers if auth is provided
    if auth and 'bearer_token' in auth:
        headers["Authorization"] = f"Bearer {forged_token}"

    response = safe_request(f"{url}/api/admin", headers=headers, auth=auth)
    if response and response.status_code == 200:
        return "Check failed", create_jwt_authentication_bypass_remediation(), analyze_response(response)
    return "Check passed", None, "N/A"

def create_jwt_authentication_bypass_remediation():
    return """To mitigate JWT Authentication Bypass vulnerabilities:<br/>
1. Use strong, randomly generated secrets for JWT signing.<br/>
2. Implement proper JWT validation on the server side.<br/>
3. Use short expiration times for tokens and implement token refresh mechanisms.<br/>
4. Consider using asymmetric key pairs (RS256) instead of symmetric keys (HS256).<br/>
5. Implement additional security measures like JWT blacklisting for logged-out tokens.<br/><br/>

CWE-347: Improper Verification of Cryptographic Signature<br/><br/>

Sample code for proper JWT validation:<br/>
```python<br/>
from flask import request, jsonify<br/>
from flask_jwt_extended import jwt_required, create_access_token, get_jwt_identity<br/><br/>

app.config['JWT_SECRET_KEY'] = os.environ.get('JWT_SECRET_KEY')  # Set this to a secure random value<br/>
jwt = JWTManager(app)<br/><br/>

@app.route('/api/login', methods=['POST'])<br/>
def login():<br/>
    username = request.json.get('username', None)<br/>
    password = request.json.get('password', None)<br/>
    if not username or not password:<br/>
        return jsonify({"error": "Missing username or password"}), 400<br/><br/>

    if check_user_credentials(username, password):<br/>
        access_token = create_access_token(identity=username)<br/>
        return jsonify(access_token=access_token), 200<br/>
    else:<br/>
        return jsonify({"error": "Invalid username or password"}), 401<br/><br/>

@app.route('/api/protected', methods=['GET'])<br/>
@jwt_required<br/>
def protected():<br/>
    current_user = get_jwt_identity()<br/>
    return jsonify(logged_in_as=current_user), 200<br/>
```
"""

def perform_regexdos_check(url, auth=None):
    log_info("Performing RegexDOS check...")
    payload = "a" * 1000000 + "!"
    response = safe_request(f"{url}/api/validate", method="POST", json={"input": payload}, auth=auth)
    if response and response.elapsed.total_seconds() > 5:
        return "Check failed", create_regexdos_remediation(), analyze_response(response)
    return "Check passed", None, "N/A"

def create_regexdos_remediation():
    return """To mitigate RegexDOS (Denial of Service):<br/>
1. Use non-backtracking regex engines when possible.<br/>
2. Limit input length before applying regex.<br/>
3. Use timeouts for regex operations.<br/>
4. Avoid using regex for complex parsing tasks.<br/><br/>

CWE-400: Uncontrolled Resource Consumption<br/><br/>

Sample code for implementing regex with safeguards:<br/>
```python<br/>
import re<br/>
import signal<br/><br/>

def timeout_handler(signum, frame):<br/>
    raise TimeoutError("Regex operation timed out")<br/><br/>

def safe_regex_match(pattern, text, timeout=1):<br/>
    signal.signal(signal.SIGALRM, timeout_handler)<br/>
    signal.alarm(timeout)<br/>
    try:<br/>
        return re.match(pattern, text[:1000])  # Limit input length<br/>
    finally:<br/>
        signal.alarm(0)<br/><br/>

@app.route('/api/validate', methods=['POST'])<br/>
def validate_input():<br/>
    user_input = request.json.get('input', '')<br/>
    try:<br/>
        result = safe_regex_match(r'^[a-zA-Z0-9]{1,100}$', user_input)<br/>
        return jsonify({"valid": bool(result)}), 200<br/>
    except TimeoutError:<br/>
        return jsonify({"error": "Validation timed out"}), 400<br/>
```
"""

def perform_user_enumeration_check(url, auth=None):
    log_info("Performing User Enumeration check...")
    usernames = ["admin", "user", "test", "nonexistent"]
    response_times = {}
    for username in usernames:
        start_time = time.time()
        response = safe_request(
            f"{url}/login",
            method="POST",
            json={"username": username, "password": "wrongpassword"},
            auth=auth
        )
        end_time = time.time()
        response_times[username] = end_time - start_time
        if response and "user not found" in response.text.lower():
            return "Check failed", create_user_enumeration_remediation(), analyze_response(response)

    # Check for timing attacks
    if max(response_times.values()) - min(response_times.values()) > 0.5:  # If timing difference is significant
        return "Check failed", create_user_enumeration_remediation(), "Potential timing attack vulnerability"

    return "Check passed", None, "N/A"

def create_user_enumeration_remediation():
    return """To mitigate User Enumeration vulnerabilities:<br/>
1. Use consistent error messages for failed login attempts.<br/>
2. Implement rate limiting for login attempts.<br/>
3. Use constant-time comparison for passwords to prevent timing attacks.<br/>
4. Consider using CAPTCHAs or other challenge-response systems for login attempts.<br/><br/>

CWE-203: Observable Discrepancy<br/><br/>

Sample code for preventing user enumeration:<br/>
```python<br/>
from werkzeug.security import check_password_hash<br/>
from flask_limiter import Limiter<br/>
from flask_limiter.util import get_remote_address<br/><br/>

limiter = Limiter(app, key_func=get_remote_address)<br/><br/>

@app.route('/login', methods=['POST'])<br/>
@limiter.limit("5 per minute")<br/>
def login():<br/>
    username = request.json.get('username')<br/>
    password = request.json.get('password')<br/><br/>

    user = get_user_by_username(username)<br/>
    if user is None or not check_password_hash(user.password, password):<br/>
        time.sleep(random.uniform(0.1, 0.3))  # Add random delay to prevent timing attacks<br/>
        return jsonify({"error": "Invalid username or password"}), 401<br/><br/>

    # Login successful<br/>
    return jsonify({"message": "Login successful"}), 200<br/>
```
"""

def perform_excessive_data_exposure_check(url, auth=None):
    log_info("Performing Excessive Data Exposure check...")

    try:
        response = safe_request(f"{url}/api/user/1", auth=auth)

        # Ensure response is valid and status is 200 OK
        if response and response.status_code == 200:
            try:
                data = response.json()
            except ValueError:
                print(f"{RED}Error: Invalid JSON response from {url}{RESET}")
                return "Check inconclusive", "Invalid JSON response", "N/A"

            # List of sensitive fields to check for
            sensitive_fields = ['password', 'ssn', 'credit_card']

            # If any sensitive field is present in the data, fail the check
            if any(field in data for field in sensitive_fields):
                return "Check failed", create_excessive_data_exposure_remediation(), analyze_response(response)

        else:
            print(f"{RED}Error: Received invalid response status code {response.status_code} from {url}{RESET}")
            return "Check inconclusive", f"Invalid response status {response.status_code}", "N/A"

    except requests.exceptions.RequestException as e:
        print(f"{RED}Error: Could not reach {url} - {e}{RESET}")
        return "Check inconclusive", "Error reaching URL", "N/A"

    return "Check passed", None, "N/A"

def create_excessive_data_exposure_remediation():
    return """To mitigate Excessive Data Exposure:<br/>
1. Implement proper data filtering on the server-side.<br/>
2. Use response schemas to control what data is sent to the client.<br/>
3. Avoid sending sensitive information in API responses.<br/>
4. Implement proper access controls to ensure users can only access their own data.<br/><br/>

CWE-359: Exposure of Private Personal Information to an Unauthorized Actor<br/><br/>

Sample code for implementing data filtering:<br/>
```python<br/>
from flask import jsonify<br/>
from marshmallow import Schema, fields<br/><br/>

class UserPublicSchema(Schema):<br/>
    id = fields.Int()<br/>
    username = fields.Str()<br/>
    email = fields.Email()<br/><br/>

@app.route('/api/user/<int:user_id>')<br/>
@login_required<br/>
def get_user(user_id):<br/>
    user = User.query.get(user_id)<br/>
    if not user:<br/>
        return jsonify({"error": "User not found"}), 404<br/>
    if current_user.id != user_id and not current_user.is_admin:<br/>
        return jsonify({"error": "Unauthorized"}), 403<br/><br/>

    schema = UserPublicSchema()<br/>
    return jsonify(schema.dump(user)), 200<br/>
```
"""

def perform_unsafe_consumption_of_apis_check(url, auth=None):
    log_info("Performing Unsafe Consumption of APIs check...")
    try:
        response = safe_request(f"{url}/api/external_data", auth=auth)
        if response and response.status_code == 200:
            try:
                data = response.json()
                if 'external_api_data' in data and not isinstance(data['external_api_data'], dict):
                    return "Check failed", create_unsafe_consumption_of_apis_remediation(), analyze_response(response)
            except ValueError:
                return "Check inconclusive", "Invalid JSON response", "N/A"
    except requests.exceptions.RequestException as e:
        print(f"{RED}Error: Could not reach {url} - {e}{RESET}")
        return "Check inconclusive", "Error reaching URL", "N/A"
    return "Check passed", None, "N/A"

def create_unsafe_consumption_of_apis_remediation():
    return """To mitigate Unsafe Consumption of APIs:<br/>
1. Implement proper input validation for data received from external APIs.<br/>
2. Use schema validation for incoming data.<br/>
3. Implement proper error handling for external API calls.<br/>
4. Use timeouts and circuit breakers for external API calls.<br/><br/>

CWE-20: Improper Input Validation<br/><br/>

Sample code for safe consumption of external APIs:<br/>
```python<br/>
import requests<br/>
from marshmallow import Schema, fields, ValidationError<br/><br/>

class ExternalDataSchema(Schema):<br/>
    id = fields.Int(required=True)<br/>
    name = fields.Str(required=True)<br/>
    value = fields.Float(required=True)<br/><br/>

@app.route('/api/external_data')<br/>
def get_external_data():<br/>
    try:<br/>
        response = requests.get('https://external-api.com/data', timeout=5)<br/>
        response.raise_for_status()<br/>
        data = response.json()<br/><br/>

        schema = ExternalDataSchema()<br/>
        validated_data = schema.load(data)<br/><br/>

        return jsonify(validated_data), 200<br/>
    except requests.RequestException as e:<br/>
        return jsonify({"error": "Failed to fetch external data"}), 500<br/>
    except ValidationError as e:<br/>
        return jsonify({"error": "Invalid data received from external API"}), 500<br/>
```
"""

# Main security check function
def perform_security_checks(url, auth=None):
    checks = [
        ("Broken Object Level Authorization", perform_broken_object_level_authorization_check),
        ("Broken Authentication", perform_broken_authentication_check),
        ("Broken Object Property Level Authorization", perform_broken_object_property_level_authorization_check),
        ("Unrestricted Resource Consumption", perform_unrestricted_resource_consumption_check),
        ("Broken Function Level Authorization", perform_broken_function_level_authorization_check),
        ("Mass Assignment", perform_mass_assignment_check),
        ("Security Misconfiguration", perform_security_misconfiguration_check),
        ("Injection", perform_injection_check),
        ("Improper Assets Management", perform_improper_assets_management_check),
        ("Unauthorized Password Change", perform_unauthorized_password_change_check),
        ("JWT Authentication Bypass", perform_jwt_authentication_bypass_check),
        ("Server Side Request Forgery", perform_server_side_request_forgery_check),
        ("RegexDOS", perform_regexdos_check),
        ("User Enumeration", perform_user_enumeration_check),
        ("Unrestricted Access to Sensitive Business Flows", perform_unrestricted_access_to_sensitive_business_flows_check),
        ("Excessive Data Exposure", perform_excessive_data_exposure_check),
        ("Unsafe Consumption of APIs", perform_unsafe_consumption_of_apis_check),
    ]
    results = []
    for check_name, check_function in checks:
        try:
            result, remediation, response_type = check_function(url, auth)
            results.append((check_name, (result, remediation, response_type)))
        except Exception as e:
            log_error(f"Error performing {check_name} check: {str(e)}")
            results.append((check_name, ("Check failed", str(e), "N/A")))
    return results

# Postman collection export function
def export_to_postman(captured_requests, filename):
    postman_collection = {
        "info": {
            "name": "Captured API Requests",
            "schema": "https://schema.getpostman.com/json/collection/v2.1.0/collection.json"
        },
        "item": []
    }

    for req in captured_requests:
        postman_collection["item"].append({
            "name": req["url"],
            "request": {
                "method": req["method"],
                "header": [],
                "url": {
                    "raw": req["url"]
                }
            }
        })

    with open(filename, 'w') as f:
        json.dump(postman_collection, f, indent=2)

    log_info(f"Postman collection exported to {filename}")

def perform_sqlmap_check(target_url, auth=None):
    log_info("Performing SQLMap check...")
    if not shutil.which("sqlmap"):
        log_error("SQLMap is not installed on this system.")
        return "Check inconclusive", "SQLMap is not installed."
    sqlmap_command = [
        "sqlmap", "-u", target_url, "--batch",
        "--output-dir=.", "--forms", "--crawl=3"
    ]

    # Add authentication details
    if auth:
        if auth['type'] == 'api_key':
            headers = f"Authorization: ApiKey {auth['api_key']}"
            sqlmap_command.extend(["--headers", headers])
        elif auth['type'] == 'bearer_token':
            headers = f"Authorization: Bearer {auth['bearer_token']}"
            sqlmap_command.extend(["--headers", headers])
        elif auth['type'] == 'basic_auth':
            auth_str = f"{auth['username']}:{auth['password']}"
            sqlmap_command.extend(["--auth-type", "basic", "--auth-cred", auth_str])

    try:
        result = subprocess.run(sqlmap_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=300)
        with open("sqlmap_report.txt", "w") as file:
            file.write(result.stdout.decode())

        with open("sqlmap_report.txt", "r") as file:
            sqlmap_content = file.read()

        if "vulnerable" in sqlmap_content.lower():
            return "Check failed", sqlmap_content
        else:
            return "Check passed", sqlmap_content
    except subprocess.TimeoutExpired:
        return "Check inconclusive", "SQLMap check timed out after 5 minutes"
    except Exception as e:
        return "Check failed", f"Error running SQLMap: {str(e)}"

class PageBreakIfNotEnoughSpace(Flowable):
    def __init__(self, space_needed):
        Flowable.__init__(self)
        self.space_needed = space_needed

    def wrap(self, availWidth, availHeight):
        if availHeight < self.space_needed:
            return (0, availHeight)
        return (0, 0)

    def draw(self):
        pass

def add_page_background(canvas, doc):
    canvas.saveState()
    canvas.setFillColor(HexColor('#141D2B'))
    canvas.rect(0, 0, letter[0], letter[1], fill=1)
    canvas.restoreState()

def create_first_page(canvas, doc):
    add_page_background(canvas, doc)
    
    canvas.saveState()
    
    # Add YOUR logo (larger size)
    logo_path = os.path.join(os.path.dirname(__file__), "YOUR_LOGO.png")
    if not os.path.isfile(logo_path):
        print(f"{RED}Logo image not found at {logo_path}{RESET}")
    else:
        canvas.drawImage(logo_path, 1.5*inch, 7*inch, width=5*inch, height=2.5*inch, preserveAspectRatio=True, mask='auto')
    
    # Add titles
    canvas.setFillColor(HexColor('#FFFFFF'))
    canvas.setFont("Helvetica-Bold", 22)
    canvas.drawCentredString(4.25*inch, 5.5*inch, "API Health Check Security Test")
    canvas.drawCentredString(4.25*inch, 5.1*inch, "Findings Report")

    # Add team name (right-aligned)
    canvas.setFillColor(HexColor('#9fef00'))
    canvas.setFont("Helvetica-Bold", 14)
    team_name = "Threat and Vulnerability Management"
    canvas.drawRightString(7.5*inch, 1.5*inch, team_name)
    canvas.drawRightString(7.5*inch, 1.2*inch, "Team")
    
    canvas.restoreState()

def create_pdf_report(full_target_url, security_assessor, application_name, all_results, sqlmap_result_tuple):
    sqlmap_result, sqlmap_output = sqlmap_result_tuple
    
    safe_filename = re.sub(r'[^\w\-_. ]', '_', application_name)
    pdf_filename = f"{safe_filename}_Security_Report.pdf"
    doc = SimpleDocTemplate(pdf_filename, pagesize=letter,
                            leftMargin=0.5 * inch, rightMargin=0.5 * inch,
                            topMargin=0.5 * inch, bottomMargin=0.5 * inch)
    styles = getSampleStyleSheet()
    flowables = []

    # Custom styles
    styles.add(ParagraphStyle(name='HTBHeading1',
                              parent=styles['Heading1'],
                              fontSize=18,
                              textColor=HexColor('#9fef00'),
                              alignment=TA_CENTER))
    styles.add(ParagraphStyle(name='HTBHeading2',
                              parent=styles['Heading2'],
                              fontSize=16,
                              textColor=HexColor('#9fef00')))
    styles.add(ParagraphStyle(name='HTBNormal',
                              parent=styles['Normal'],
                              fontSize=10,
                              textColor=HexColor('#FFFFFF')))

    # Add a blank first page (will be replaced by our custom first page)
    flowables.append(PageBreak())

    # Basic Info
    flowables.append(Paragraph(f"Target: {application_name}", styles['HTBNormal']))
    flowables.append(Paragraph(f"URL: {full_target_url}", styles['HTBNormal']))
    flowables.append(Paragraph(f"Date: {datetime.now().strftime('%Y-%m-%d')}", styles['HTBNormal']))
    flowables.append(Paragraph(f"Assessor: {security_assessor}", styles['HTBNormal']))
    flowables.append(Spacer(1, 0.2 * inch))

    # Executive Summary
    flowables.append(Paragraph("Executive Summary", styles['HTBHeading2']))
    flowables.append(Paragraph(
        f"This report presents the findings of a comprehensive security assessment conducted on the {application_name} API. "
        "The assessment aimed to identify potential vulnerabilities and security risks in the API implementation, covering various aspects "
        "of API security including authentication, authorization, data exposure, and common web application vulnerabilities. "
        "Our findings indicate areas of concern that require immediate attention to enhance the overall security posture of the application.",
        styles['HTBNormal']))
    flowables.append(Spacer(1, 0.2 * inch))

    # Methodology
    flowables.append(Paragraph("Methodology", styles['HTBHeading2']))
    flowables.append(Paragraph(
        "The security assessment was conducted using a combination of automated scanning tools and manual testing techniques. Our approach included:",
        styles['HTBNormal']))
    methodology_points = [
        "1. Reconnaissance and information gathering",
        "2. Vulnerability scanning",
        "3. Manual penetration testing",
        "4. Analysis of API responses and error messages",
        "5. Review of authentication and authorization mechanisms",
        "6. Assessment of data handling and exposure"
    ]
    for point in methodology_points:
        flowables.append(Paragraph(point, styles['HTBNormal']))
    flowables.append(Spacer(1, 0.2 * inch))

    # Risk Assessment
    flowables.append(Paragraph("Risk Assessment", styles['HTBHeading2']))
    flowables.append(Paragraph(
        "Based on our findings, we have categorized the identified vulnerabilities into risk levels:",
        styles['HTBNormal']))
    risk_levels = [
        "- Critical: Vulnerabilities that pose an immediate threat and require urgent attention.",
        "- High: Significant vulnerabilities that should be addressed in the short term.",
        "- Medium: Moderate risks that should be mitigated in due course.",
        "- Low: Minor issues that should be addressed as part of routine maintenance."
    ]
    for level in risk_levels:
        flowables.append(Paragraph(level, styles['HTBNormal']))
    flowables.append(Spacer(1, 0.2 * inch))

    # Test Assessment Summary
    flowables.append(Paragraph("Test Assessment Summary", styles['HTBHeading2']))
    total_checks = sum(len(results) for _, results in all_results)
    total_pass = sum(sum(1 for _, result in results if result[0] == "Check passed") for _, results in all_results)
    total_fail = total_checks - total_pass

    summary_data = [
        ['Total Checks', 'Passed', 'Failed'],
        [str(total_checks), str(total_pass), str(total_fail)]
    ]
    summary_table = Table(summary_data, colWidths=[2 * inch, 2 * inch, 2 * inch])
    summary_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), HexColor('#1a2332')),
        ('TEXTCOLOR', (0, 0), (-1, 0), HexColor('#9fef00')),
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, 0), 12),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
        ('BACKGROUND', (0, 1), (-1, -1), HexColor('#1e2b3d')),
        ('TEXTCOLOR', (0, 1), (-1, -1), HexColor('#FFFFFF')),
        ('TEXTCOLOR', (1, 1), (1, 1), HexColor('#9fef00')),  # Green color for "Passed"
        ('TEXTCOLOR', (2, 1), (2, 1), HexColor('#FF0000')),  # Red color for "Failed"
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
        ('FONTSIZE', (0, 1), (-1, -1), 10),
        ('TOPPADDING', (0, 1), (-1, -1), 6),
        ('BOTTOMPADDING', (0, -1), (-1, -1), 6),
        ('GRID', (0, 0), (-1, -1), 1, HexColor('#a4b1cd'))
    ]))
    flowables.append(summary_table)
    flowables.append(Spacer(1, 0.2 * inch))

    # Summary of Findings
    flowables.append(Paragraph("Summary of Findings", styles['HTBHeading2']))
    flowables.append(Paragraph(
        f"The security assessment of the {application_name} API revealed {total_fail} failed checks out of {total_checks} total checks performed. "
        "These failed checks indicate potential vulnerabilities that could be exploited by malicious actors. "
        "The severity of these issues ranges from low to critical, with some requiring immediate attention to mitigate potential security risks.",
        styles['HTBNormal']))
    flowables.append(Spacer(1, 0.2 * inch))

    # Remediation Summary
    flowables.append(Paragraph("Remediation Summary", styles['HTBHeading2']))
    flowables.append(Paragraph(
        "Based on our findings, we recommend the following high-level remediation steps:<br/>"
        "1. Implement robust input validation and sanitization across all API endpoints.<br/>"
        "2. Strengthen authentication mechanisms and enforce the principle of least privilege.<br/>"
        "3. Review and enhance access control measures to prevent unauthorized data access.<br/>"
        "4. Implement proper error handling to prevent information leakage.<br/>"
        "5. Conduct regular security assessments and penetration testing.<br/>"
        "6. Provide security awareness training for development and operations teams.<br/>"
        "7. Implement a secure software development lifecycle (SSDLC) to prevent future vulnerabilities.",
        styles['HTBNormal']))
    flowables.append(Spacer(1, 0.2 * inch))

    # Conclusion
    flowables.append(Paragraph("Conclusion", styles['HTBHeading2']))
    flowables.append(Paragraph(
        f"The security assessment of the {application_name} API has revealed several areas that require attention to enhance the overall security posture. "
        "By addressing the identified vulnerabilities and implementing the recommended security measures, the organization can significantly improve the resilience of the API against potential attacks.<br/><br/>"
        "It is crucial to view security as an ongoing process rather than a one-time effort. Regular assessments, continuous monitoring, and prompt addressing of security issues are essential to maintaining a robust security posture in an ever-evolving threat landscape.<br/><br/>"
        "We recommend scheduling a follow-up assessment after implementing the suggested remediation measures to verify their effectiveness and identify any remaining or new security concerns.",
        styles['HTBNormal']))
    flowables.append(PageBreak())

    # Technical Findings Details
    flowables.append(Paragraph("Technical Findings Details", styles['HTBHeading1']))
    for url, results in all_results:
        flowables.append(Paragraph(f"Results for {url}", styles['HTBHeading2']))
        for check_name, (check_result, check_remediation, response_type) in results:
            result_color = HexColor('#9fef00') if check_result == "Check passed" else HexColor('#ff3e3e')
            flowables.append(Paragraph(check_name, styles['HTBHeading2']))
            flowables.append(
                Paragraph(f"Result: <font color={result_color}>{check_result}</font>", styles['HTBNormal']))
            if check_result == "Check failed" and check_remediation:
                flowables.append(Paragraph("Remediation:", styles['HTBHeading2']))
                flowables.append(Paragraph(check_remediation, styles['HTBNormal']))
            flowables.append(Spacer(1, 0.1 * inch))
        flowables.append(PageBreak())

    # SQLMap Results Section
    flowables.append(Paragraph("SQLMap Results", styles['HTBHeading1']))
    flowables.append(Paragraph("The following results were obtained from running SQLMap:", styles['HTBNormal']))
    flowables.append(Spacer(1, 0.1 * inch))

    if isinstance(sqlmap_output, tuple) and len(sqlmap_output) == 2:
        sqlmap_result, sqlmap_details = sqlmap_output
        flowables.append(Paragraph(f"SQLMap Check Result: {sqlmap_result}", styles['HTBNormal']))
        flowables.append(Spacer(1, 0.1 * inch))
        flowables.append(Preformatted(sqlmap_details, ParagraphStyle(
            'HTBPreformatted', parent=styles['HTBNormal'], fontName='Courier', fontSize=8)))
    elif isinstance(sqlmap_output, str):
        flowables.append(Preformatted(sqlmap_output, ParagraphStyle(
            'HTBPreformatted', parent=styles['HTBNormal'], fontName='Courier', fontSize=8)))
    else:
        flowables.append(Paragraph(f"SQLMap output is in an unexpected format: {str(sqlmap_output)}", styles['HTBNormal']))

    # Build the PDF document
    doc.build(flowables, onFirstPage=create_first_page, onLaterPages=add_page_background)
    print(f"{GREEN}Report generated: {pdf_filename}{RESET}")
    
# Main function
def main():
    full_target_url, security_assessor, application_name, endpoints = read_user_input_from_file()
    if not all([full_target_url, security_assessor, application_name]):
        # Data not available, prompt the user for input
        full_target_url, security_assessor, application_name, endpoints = get_user_input()

    # Get authentication details
    auth = get_authentication_details()

    all_urls = [full_target_url] + (endpoints or [])
    all_results = []
    all_captured_requests = []

    # Start packet capture before performing the checks
    traffic_capture = TrafficCapture()
    try:
        traffic_capture.start()
    except Exception as e:
        print(f"{RED}Failed to start packet capture: {e}{RESET}")
        print(f"{GREEN}Continuing without packet capture.{RESET}")
        traffic_capture = None

    try:
        for url in all_urls:
            try:
                validate_url(url)
                print(f"{GREEN}\nScanning URL: {url}{RESET}")
                results = perform_security_checks(url, auth)
                all_results.append((url, results))
            except ValueError as e:
                log_error(f"Invalid URL {url}: {e}")
    finally:
        # Stop packet capture after the checks are done
        if traffic_capture:
            traffic_capture.stop()

    # Save the captured packets and requests
    try:
        if traffic_capture:
            traffic_capture.save_pcap("captured_traffic.pcap")
            for url in all_urls:
                captured_requests = traffic_capture.save_requests(url)
                all_captured_requests.extend(captured_requests)
            export_to_postman(all_captured_requests, "captured_requests.postman_collection.json")
    except Exception as e:
        print(f"{RED}Unable to perform packet capture: {e}{RESET}")
        print(f"{GREEN}Continuing without packet capture.{RESET}")

    try:
        sqlmap_result, sqlmap_output = perform_sqlmap_check(full_target_url, auth)
    except Exception as e:
        log_error(f"Error performing SQLMap check: {str(e)}")
        sqlmap_result, sqlmap_output = "Check failed", f"Error running SQLMap: {str(e)}"

    try:
        create_pdf_report(
            full_target_url,
            security_assessor,
            application_name,
            all_results,
            (sqlmap_result, sqlmap_output)
        )
        print(f"{GREEN}Scan completed. Report generated.{RESET}")
    except Exception as e:
        log_error(f"Error generating PDF report: {str(e)}")

    print("Retained files:")
    print("1. Final report (PDF)")
    print("2. captured_traffic.pcap")
    print("3. captured_requests.postman_collection.json")
    print("4. GET and POST request files for each URL")
    print("5. SQL check")

    # File Cleanup
    os.system("rm -f user_input.txt")
    os.system("rm -f cred.txt")
    os.system("rm -f sqlmap_report.txt")
    os.system("rm -f *.csv")
    os.system("rm -f security_assessment.log")

# Run the main function
if __name__ == "__main__":
    check_and_elevate_privileges()
    try:
        main()
    except KeyboardInterrupt:
        print("\nScript execution interrupted by user.")
    except Exception as e:
        log_error(f"An unexpected error occurred: {str(e)}")
    finally:
        print(f"{GREEN}Script execution completed.{RESET}")
        sys.exit(0)
       
