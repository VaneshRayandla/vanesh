import requests
import dns.resolver
import whois
import socket
from datetime import datetime

# Function to get the WHOIS information of a domain
def get_whois_info(domain):
    try:
        domain_info = whois.whois(domain)
        print("\nWHOIS Information:")
        print(domain_info)
    except Exception as e:
        print(f"Error getting WHOIS info for {domain}: {e}")

# Function to get DNS records (A, MX, NS)
def get_dns_records(domain):
    print("\nDNS Records:")

    try:
        # A Record
        print(f"A Record:")
        answers = dns.resolver.resolve(domain, 'A')
        for rdata in answers:
            print(f"  {rdata.to_text()}")

        # MX Record
        print(f"MX Record:")
        answers = dns.resolver.resolve(domain, 'MX')
        for rdata in answers:
            print(f"  {rdata.exchange} - Priority: {rdata.preference}")

        # NS Record
        print(f"NS Record:")
        answers = dns.resolver.resolve(domain, 'NS')
        for rdata in answers:
            print(f"  {rdata.to_text()}")
    except dns.resolver.NoAnswer as e:
        print(f"Error getting DNS records for {domain}: {e}")

# Function to perform an HTTP request and get the response
def get_http_info(url):
    try:
        response = requests.get(url)
        print("\nHTTP Request Information:")
        print(f"URL: {url}")
        print(f"Status Code: {response.status_code}")
        print(f"Content Type: {response.headers['Content-Type']}")
        print(f"Response Time: {response.elapsed.total_seconds()} seconds")
    except requests.exceptions.RequestException as e:
        print(f"Error performing HTTP request: {e}")

# Function to get IP from domain name
def get_ip_from_domain(domain):
    try:
        ip = socket.gethostbyname(domain)
        print(f"\nIP Address for {domain}: {ip}")
    except socket.gaierror as e:
        print(f"Error resolving IP for {domain}: {e}")

# Main function
def automate_recon(target_domain):
    print(f"Starting reconnaissance for {target_domain}\n")

    # Perform WHOIS Lookup
    get_whois_info(target_domain)

    # Get DNS Records
    get_dns_records(target_domain)

    # Get HTTP info
    target_url = f"http://{target_domain}"
    get_http_info(target_url)

    # Get IP address
    get_ip_from_domain(target_domain)

    print("\nReconnaissance completed.")

if __name__ == "__main__":
    target_domain = input("Enter the target domain (e.g., example.com): ").strip()
    automate_recon(target_domain)
import requests
import dns.resolver
import whois
import socket
from datetime import datetime

# Function to get the WHOIS information of a domain
def get_whois_info(domain):
    try:
        domain_info = whois.whois(domain)
        print("\nWHOIS Information:")
        print(domain_info)
    except Exception as e:
        print(f"Error getting WHOIS info for {domain}: {e}")

# Function to get DNS records (A, MX, NS)
def get_dns_records(domain):
    print("\nDNS Records:")

    try:
        # A Record
        print(f"A Record:")
        answers = dns.resolver.resolve(domain, 'A')
        for rdata in answers:
            print(f"  {rdata.to_text()}")

        # MX Record
        print(f"MX Record:")
        answers = dns.resolver.resolve(domain, 'MX')
        for rdata in answers:
            print(f"  {rdata.exchange} - Priority: {rdata.preference}")

        # NS Record
        print(f"NS Record:")
        answers = dns.resolver.resolve(domain, 'NS')
        for rdata in answers:
            print(f"  {rdata.to_text()}")
    except dns.resolver.NoAnswer as e:
        print(f"Error getting DNS records for {domain}: {e}")

# Function to perform an HTTP request and get the response
def get_http_info(url):
    try:
        response = requests.get(url)
        print("\nHTTP Request Information:")
        print(f"URL: {url}")
        print(f"Status Code: {response.status_code}")
        print(f"Content Type: {response.headers['Content-Type']}")
        print(f"Response Time: {response.elapsed.total_seconds()} seconds")
    except requests.exceptions.RequestException as e:
        print(f"Error performing HTTP request: {e}")

# Function to get IP from domain name
def get_ip_from_domain(domain):
    try:
        ip = socket.gethostbyname(domain)
        print(f"\nIP Address for {domain}: {ip}")
    except socket.gaierror as e:
        print(f"Error resolving IP for {domain}: {e}")

# Main function
def automate_recon(target_domain):
    print(f"Starting reconnaissance for {target_domain}\n")

    # Perform WHOIS Lookup
    get_whois_info(target_domain)

    # Get DNS Records
    get_dns_records(target_domain)

    # Get HTTP info
    target_url = f"http://{target_domain}"
    get_http_info(target_url)

    # Get IP address
    get_ip_from_domain(target_domain)

    print("\nReconnaissance completed.")

if __name__ == "__main__":
    target_domain = input("Enter the target domain (e.g., example.com): ").strip()
    automate_recon(target_domain)
