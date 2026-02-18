# Server-Side Request Forgery (SSRF)

CWE-918 (SSRF), OWASP A10:2021

## Detection Patterns

```bash
# HTTP requests with user input
grep -rn "requests\.get\|requests\.post\|urllib\|fetch\|axios\|http\.get\|HttpClient" --include="*.py" --include="*.js" --include="*.java" --include="*.go"

# URL from user input
grep -rn "req\.body\.url\|request\.json\['url'\]\|params\[:url\]\|getParameter.*url" --include="*.py" --include="*.js" --include="*.java" --include="*.rb"

# Webhook/callback URLs
grep -rn "webhook\|callback\|redirect_uri\|return_url\|notify_url" --include="*.py" --include="*.js" --include="*.java"

# Image/file fetching from URL
grep -rn "download\|fetch.*url\|get.*url\|import.*url" --include="*.py" --include="*.js"
```

## Vulnerable Patterns

```python
# VULNERABLE: Direct user URL access
@app.route('/fetch')
def fetch_url():
    url = request.args.get('url')
    return requests.get(url).content

# VULNERABLE: SSRF via image processing
@app.route('/resize')
def resize_image():
    url = request.args.get('image_url')
    img = Image.open(requests.get(url, stream=True).raw)
```

## Attack Vectors

### Internal Network Access
```
# Target internal services
?url=http://localhost/admin
?url=http://127.0.0.1:8080/
?url=http://192.168.1.1/
?url=http://10.0.0.1/
?url=http://internal-service/
```

### Cloud Metadata (Critical)
```
# AWS metadata
?url=http://169.254.169.254/latest/meta-data/
?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/

# GCP metadata
?url=http://metadata.google.internal/computeMetadata/v1/

# Azure metadata
?url=http://169.254.169.254/metadata/instance

# Common bypasses
?url=http://[::1]/  # IPv6 localhost
?url=http://0.0.0.0/
?url=http://0177.0.0.1/  # Octal
?url=http://2130706433/  # Decimal
```

### Protocol Attacks
```
?url=file:///etc/passwd
?url=gopher://localhost:25/
?url=dict://localhost:6379/
```

## Secure Implementation

```python
import ipaddress
from urllib.parse import urlparse

ALLOWED_SCHEMES = {'http', 'https'}
BLOCKED_NETWORKS = [
    ipaddress.ip_network('127.0.0.0/8'),      # Loopback
    ipaddress.ip_network('10.0.0.0/8'),       # Private
    ipaddress.ip_network('172.16.0.0/12'),    # Private
    ipaddress.ip_network('192.168.0.0/16'),   # Private
    ipaddress.ip_network('169.254.0.0/16'),   # Link-local (metadata)
    ipaddress.ip_network('::1/128'),          # IPv6 loopback
]

def is_safe_url(url):
    parsed = urlparse(url)
    
    # Check scheme
    if parsed.scheme not in ALLOWED_SCHEMES:
        return False
    
    # Resolve hostname
    try:
        ip = ipaddress.ip_address(socket.gethostbyname(parsed.hostname))
    except:
        return False
    
    # Check against blocked networks
    for network in BLOCKED_NETWORKS:
        if ip in network:
            return False
    
    return True

@app.route('/fetch')
def fetch_url():
    url = request.args.get('url')
    if not is_safe_url(url):
        abort(400, "Invalid URL")
    return requests.get(url, timeout=5).content
```

## SSRF Checklist

- [ ] URL scheme whitelisting (http/https only)
- [ ] Block private/internal IP ranges
- [ ] Block cloud metadata IPs (169.254.169.254)
- [ ] DNS rebinding protection (re-resolve after check)
- [ ] Timeout on requests
- [ ] Response size limits
- [ ] No following redirects to internal URLs
- [ ] Log all outbound requests
