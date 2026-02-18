# Security Misconfiguration

CWE-16 (Configuration), OWASP A05:2021

## Table of Contents
- [Debug Mode](#debug-mode)
- [CORS Misconfiguration](#cors-misconfiguration)
- [Security Headers](#security-headers)
- [Default Credentials](#default-credentials)
- [Verbose Errors](#verbose-errors)
- [Directory Listing](#directory-listing)

## Debug Mode

### Detection Patterns

```bash
# Debug mode enabled
grep -rn "DEBUG\s*=\s*True\|debug:\s*true\|NODE_ENV.*development" --include="*.py" --include="*.js" --include="*.json" --include="*.yml" --include="*.yaml" --include="*.env"

# Flask/Django debug
grep -rn "app\.debug\|DEBUG\s*=" --include="*.py" --include="settings.py"

# Development servers in production
grep -rn "app\.run\|flask run\|runserver" --include="*.py" --include="Procfile" --include="Dockerfile"
```

### Vulnerable Patterns

```python
# VULNERABLE: Debug enabled in production
app.run(debug=True)  # Exposes debugger
DEBUG = True  # Django shows stack traces

# SECURE: Environment-based
DEBUG = os.environ.get('DEBUG', 'False').lower() == 'true'
```

## CORS Misconfiguration

### Detection Patterns

```bash
# CORS configuration
grep -rn "Access-Control-Allow-Origin\|cors\|CORS" --include="*.py" --include="*.js" --include="*.java" --include="*.config"

# Wildcard or reflected origin
grep -rn "'\*'\|\"\\*\"\|origin\s*:" --include="*.py" --include="*.js" | grep -i "cors\|allow-origin"
```

### Vulnerable Patterns

```javascript
// VULNERABLE: Wildcard with credentials
app.use(cors({
    origin: '*',
    credentials: true  // DANGEROUS COMBINATION
}));

// VULNERABLE: Reflecting any origin
app.use(cors({
    origin: req.headers.origin,  // Reflects attacker domain
    credentials: true
}));

// SECURE: Whitelist specific origins
const allowedOrigins = ['https://app.example.com', 'https://admin.example.com'];
app.use(cors({
    origin: (origin, callback) => {
        if (!origin || allowedOrigins.includes(origin)) {
            callback(null, true);
        } else {
            callback(new Error('Not allowed'));
        }
    },
    credentials: true
}));
```

## Security Headers

### Detection Patterns

```bash
# Security header configuration
grep -rn "X-Frame-Options\|Content-Security-Policy\|X-Content-Type-Options\|Strict-Transport-Security\|X-XSS-Protection\|helmet\|SecurityHeaders" --include="*.py" --include="*.js" --include="*.java" --include="*.config"
```

### Required Headers Checklist

| Header | Value | Purpose |
|--------|-------|---------|
| X-Frame-Options | DENY or SAMEORIGIN | Clickjacking protection |
| X-Content-Type-Options | nosniff | MIME sniffing prevention |
| Strict-Transport-Security | max-age=31536000; includeSubDomains | Force HTTPS |
| Content-Security-Policy | default-src 'self' | XSS mitigation |
| X-XSS-Protection | 0 | Disable buggy browser filter |
| Referrer-Policy | strict-origin-when-cross-origin | Control referrer leakage |
| Permissions-Policy | geolocation=(), camera=() | Restrict browser features |

### Implementation Example

```javascript
// Express with helmet
const helmet = require('helmet');
app.use(helmet());

// Or manually:
app.use((req, res, next) => {
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('Content-Security-Policy', "default-src 'self'");
    res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
    next();
});
```

## Default Credentials

### Detection Patterns

```bash
# Common default credentials
grep -rn "admin:admin\|root:root\|password123\|default.*password\|changeme" --include="*.py" --include="*.js" --include="*.yml" --include="*.json" --include="*.env"

# Database default configs
grep -rn "localhost:5432\|localhost:3306\|localhost:27017" --include="*.py" --include="*.js" --include="*.yml"
```

## Verbose Errors

### Detection Patterns

```bash
# Stack trace exposure
grep -rn "traceback\|stack.*trace\|print_exc\|e\.message\|err\.stack" --include="*.py" --include="*.js" --include="*.java"

# Detailed error responses
grep -rn "500.*error\|InternalServerError\|Exception" --include="*.py" --include="*.js"
```

### Vulnerable Patterns

```python
# VULNERABLE: Exposes internals
@app.errorhandler(500)
def error_handler(e):
    return str(e), 500  # Shows stack trace

# SECURE: Generic error
@app.errorhandler(500)
def error_handler(e):
    app.logger.error(f"Internal error: {e}")  # Log internally
    return {"error": "Internal server error"}, 500  # Generic response
```

## Directory Listing

### Detection Patterns

```bash
# Static file serving without index
grep -rn "static\|serve_static\|express\.static\|sendFile" --include="*.py" --include="*.js"

# Apache/Nginx config
grep -rn "Options.*Indexes\|autoindex\s*on" --include="*.conf" --include=".htaccess"
```

## Configuration Checklist

- [ ] Debug mode disabled in production
- [ ] CORS properly restricted
- [ ] Security headers configured
- [ ] Default credentials changed
- [ ] Error messages are generic
- [ ] Directory listing disabled
- [ ] Admin interfaces restricted
- [ ] Unnecessary features disabled
- [ ] TLS 1.2+ enforced
- [ ] HTTP methods restricted (no TRACE)
