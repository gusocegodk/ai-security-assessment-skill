# Denial of Service (DoS) Vulnerabilities

CWE-400 (Resource Consumption), CWE-1333 (ReDoS)

## Table of Contents
- [Rate Limiting](#rate-limiting)
- [ReDoS](#redos)
- [Resource Exhaustion](#resource-exhaustion)

## Rate Limiting

### Detection Patterns

```bash
# Rate limiting middleware
grep -rn "rate.*limit\|throttle\|ratelimit" --include="*.py" --include="*.js" --include="*.java" --include="*.rb"

# Login/auth endpoints without rate limiting
grep -rn "login\|authenticate\|signin\|password" --include="*.py" --include="*.js" -l | xargs grep -L "rate\|throttle\|limit"

# API endpoints
grep -rn "@app\.route\|app\.get\|app\.post" --include="*.py" --include="*.js"
```

### Critical Endpoints to Protect

| Endpoint | Attack Vector | Recommendation |
|----------|---------------|----------------|
| /login | Credential stuffing | 5/min per IP, 3/min per user |
| /register | Account enumeration | 10/hour per IP |
| /password-reset | Email bombing | 3/hour per email |
| /api/* | API abuse | 100/min per token |
| /search | Resource exhaustion | 30/min per IP |
| /upload | Storage exhaustion | 10/hour per user |

### Implementation Check

```python
# Good: Rate limiting on sensitive endpoints
from flask_limiter import Limiter

limiter = Limiter(app, key_func=get_remote_address)

@app.route('/login', methods=['POST'])
@limiter.limit("5 per minute")
def login():
    pass
```

## ReDoS

### Detection Patterns

```bash
# Regex patterns (inspect manually for ReDoS)
grep -rn "re\.\|RegExp\|regex\|pattern\s*=" --include="*.py" --include="*.js" --include="*.java"

# User input in regex
grep -rn "re\.match.*request\|re\.search.*request\|new RegExp.*req\." --include="*.py" --include="*.js"
```

### Vulnerable Regex Patterns

Patterns vulnerable to catastrophic backtracking:
- `(a+)+` - Nested quantifiers
- `(a|a)+` - Overlapping alternation
- `(.*a){x}` - Quantified groups with wildcards
- `([a-zA-Z]+)*` - Repeated character classes

```javascript
// VULNERABLE: ReDoS pattern
const emailRegex = /^([a-zA-Z0-9]+)+@([a-zA-Z0-9]+)+\.[a-zA-Z]{2,}$/;
// Attack: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa!"

// SECURE: Non-backtracking or atomic groups
const emailRegex = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;
```

### Testing for ReDoS

```python
# Test regex with long input
import re
import time

pattern = r"(a+)+"  # Vulnerable
test_input = "a" * 30 + "!"

start = time.time()
re.match(pattern, test_input)
duration = time.time() - start
print(f"Time: {duration}s")  # Should be instant, not seconds
```

## Resource Exhaustion

### Detection Patterns

```bash
# File upload without size limits
grep -rn "upload\|multipart\|file\s*=" --include="*.py" --include="*.js" | grep -v "max_size\|limit\|MAX"

# Memory-intensive operations
grep -rn "\.readAll\|\.read\(\)\|\.load\(\)\|slurp" --include="*.py" --include="*.js" --include="*.java"

# Unbounded loops/recursion
grep -rn "while True\|while\s*1\|for.*in.*request" --include="*.py" --include="*.js"

# Large data structures from user input
grep -rn "range.*request\|list.*request\|dict.*request" --include="*.py" --include="*.js"
```

### Vulnerable Patterns

```python
# VULNERABLE: No upload size limit
@app.route('/upload', methods=['POST'])
def upload():
    file = request.files['file']
    file.save(f'/uploads/{file.filename}')

# SECURE: With limits
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB
```

```python
# VULNERABLE: Reading entire file into memory
data = request.get_data()  # Could be GB

# SECURE: Streaming/chunked processing
for chunk in request.stream:
    process_chunk(chunk)
```

```python
# VULNERABLE: User-controlled iteration
def process(n):
    return [compute() for _ in range(n)]
# Attack: n=999999999

# SECURE: Cap the limit
MAX_ITEMS = 1000
def process(n):
    n = min(n, MAX_ITEMS)
    return [compute() for _ in range(n)]
```

### XML/JSON Bombs

```bash
# Check for XML parsing (vulnerable to billion laughs)
grep -rn "xml\.parse\|lxml\|ElementTree" --include="*.py" --include="*.java"

# Check for JSON depth limits
grep -rn "json\.loads\|JSON\.parse\|ObjectMapper" --include="*.py" --include="*.js" --include="*.java"
```

```python
# VULNERABLE: No depth/size limit
data = json.loads(request.data)

# SECURE: With limits
import json
from json.decoder import JSONDecoder

def limited_json_loads(data, max_depth=20, max_size=1024*1024):
    if len(data) > max_size:
        raise ValueError("JSON too large")
    # Use custom decoder with depth tracking
```

## DoS Checklist

- [ ] Rate limiting on all public endpoints
- [ ] Stricter limits on auth endpoints
- [ ] Upload file size limits
- [ ] Request body size limits
- [ ] Timeout on all operations
- [ ] Pagination on list endpoints
- [ ] ReDoS-safe regex patterns
- [ ] No user input in regex patterns
- [ ] XML parser limits (depth, entities)
- [ ] JSON parser limits (depth, size)
- [ ] Database query timeouts
- [ ] Connection pool limits
