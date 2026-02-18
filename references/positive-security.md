# Positive Security Checks

Verify the presence of security controls and best practices. These checks detect "sins of omission" — missing protections rather than vulnerable code.

## Table of Contents
- [Security Headers](#security-headers)
- [Rate Limiting](#rate-limiting)
- [Input Validation](#input-validation)
- [Logging & Monitoring](#logging--monitoring)
- [Dependency Security](#dependency-security)
- [Authentication Hardening](#authentication-hardening)
- [Error Handling](#error-handling)
- [Transport Security](#transport-security)

## Security Headers

### Detection: Are headers configured?

```bash
# Check for helmet (Express) or equivalent
grep -rn "helmet\|SecurityHeaders\|SecurityMiddleware\|secure_headers" --include="*.py" --include="*.js" --include="*.ts" --include="*.rb" --include="*.java" --include="*.go"

# Check for CSP
grep -rn "Content-Security-Policy\|contentSecurityPolicy\|CSP" --include="*.py" --include="*.js" --include="*.ts" --include="*.rb" --include="*.config" --include="*.conf"

# Check for HSTS
grep -rn "Strict-Transport-Security\|HSTS\|SECURE_HSTS" --include="*.py" --include="*.js" --include="*.conf" --include="*.env"
```

### What to Flag as Missing

| Missing Control | Severity | Note |
|----------------|----------|------|
| No CSP header | Medium | XSS mitigation missing |
| No HSTS | Medium | HTTPS downgrade possible |
| No X-Frame-Options / frame-ancestors | Low | Clickjacking risk |
| No X-Content-Type-Options | Low | MIME sniffing risk |
| No Referrer-Policy | Low | URL leakage |

## Rate Limiting

### Detection: Is rate limiting present?

```bash
# Rate limiting middleware/libraries
grep -rn "rate.limit\|rateLimit\|RateLimit\|throttle\|Throttle\|slowDown\|express-rate-limit\|flask-limiter\|django-ratelimit\|rack-attack\|bucket4j" --include="*.py" --include="*.js" --include="*.ts" --include="*.rb" --include="*.java" --include="*.go"

# Redis-based rate limiting
grep -rn "redis.*rate\|rate.*redis\|INCR.*expire\|sliding.window" --include="*.py" --include="*.js" --include="*.ts"
```

### What to Flag as Missing

| Missing Control | Severity | Endpoints |
|----------------|----------|-----------|
| No rate limiting on login | High | /login, /auth, /signin |
| No rate limiting on registration | Medium | /register, /signup |
| No rate limiting on password reset | High | /forgot-password, /reset |
| No rate limiting on API globally | Medium | All API routes |
| No rate limiting on OTP/MFA verification | High | /verify, /2fa |

### Detection: Critical endpoints without rate limiting

```bash
# Find auth endpoints
grep -rn "login\|signin\|sign_in\|authenticate\|forgot.password\|reset.password\|register\|signup\|sign_up\|verify.*code\|verify.*otp" --include="*.py" --include="*.js" --include="*.ts" --include="*.rb" --include="*.java" --include="*.go" | grep -i "route\|app\.\|router\.\|path\|mapping\|endpoint"
```

Then verify each has rate limiting applied.

## Input Validation

### Detection: Is a validation library present?

```bash
# Validation libraries
grep -rn "joi\|yup\|zod\|class-validator\|express-validator\|marshmallow\|pydantic\|WTForms\|cerberus\|voluptuous\|dry-validation\|bean.validation\|javax\.validation" --include="*.py" --include="*.js" --include="*.ts" --include="*.rb" --include="*.java" --include="*.go"

# Schema validation for API input
grep -rn "schema\|validate\|sanitize\|validator" --include="*.py" --include="*.js" --include="*.ts" | grep -i "request\|body\|input\|param"
```

### What to Flag as Missing

- No input validation library detected in project dependencies
- API endpoints accepting request body without schema validation
- File uploads without type/size validation
- Database queries receiving unvalidated input

## Logging & Monitoring

### Detection: Is security logging present?

```bash
# Logging frameworks
grep -rn "winston\|morgan\|bunyan\|pino\|logging\|log4j\|logback\|slf4j\|serilog\|NLog\|logrus\|zap\|zerolog" --include="*.py" --include="*.js" --include="*.ts" --include="*.rb" --include="*.java" --include="*.go" --include="*.cs"

# Security event logging
grep -rn "login.*log\|auth.*log\|failed.*login\|suspicious\|audit\|security.*event\|access.*denied\|unauthorized" --include="*.py" --include="*.js" --include="*.ts" --include="*.rb" --include="*.java"

# Error monitoring (Sentry, Datadog, etc.)
grep -rn "sentry\|Sentry\|datadog\|newrelic\|bugsnag\|rollbar\|airbrake" --include="*.py" --include="*.js" --include="*.ts" --include="*.rb" --include="*.java" --include="*.go"
```

### What to Flag as Missing

| Missing Control | Severity | Note |
|----------------|----------|------|
| No logging framework | Medium | Cannot detect attacks |
| No auth failure logging | Medium | Brute force invisible |
| No error monitoring service | Low | Production errors untracked |
| No audit trail for admin actions | Medium | Compliance gap |

## Dependency Security

### Detection: Is dependency scanning in CI?

```bash
# CI configuration files
grep -rn "npm audit\|safety check\|snyk\|dependabot\|renovate\|govulncheck\|bundler-audit\|composer audit\|cargo audit\|trivy\|grype" --include="*.yml" --include="*.yaml" --include="*.json" --include="Makefile" --include="Dockerfile"

# Dependabot/Renovate config
find . -name "dependabot.yml" -o -name "dependabot.yaml" -o -name "renovate.json" -o -name ".renovaterc"

# Lock file present (ensures reproducible builds)
find . -maxdepth 2 -name "package-lock.json" -o -name "yarn.lock" -o -name "pnpm-lock.yaml" -o -name "Pipfile.lock" -o -name "poetry.lock" -o -name "Cargo.lock" -o -name "go.sum" -o -name "Gemfile.lock" -o -name "composer.lock"
```

### What to Flag as Missing

| Missing Control | Severity |
|----------------|----------|
| No dependency scanning in CI | Medium |
| No lock file | Medium |
| No automated dependency updates (Dependabot/Renovate) | Low |

## Authentication Hardening

### Detection: Are auth best practices present?

```bash
# Account lockout mechanism
grep -rn "lockout\|lock_out\|max_attempts\|failed_attempts\|login_attempts\|account.*locked\|brute" --include="*.py" --include="*.js" --include="*.ts" --include="*.rb" --include="*.java"

# Password complexity enforcement
grep -rn "password.*length\|password.*min\|password.*policy\|password.*strength\|zxcvbn\|password.*validator" --include="*.py" --include="*.js" --include="*.ts" --include="*.rb" --include="*.java"

# Breach password checking
grep -rn "haveibeenpwned\|hibp\|breached\|pwned\|compromised.*password" --include="*.py" --include="*.js" --include="*.ts"
```

## Error Handling

### Detection: Is there a global error handler?

```bash
# Global error handlers
grep -rn "errorHandler\|error_handler\|exception_handler\|@app\.errorhandler\|@ExceptionHandler\|rescue_from\|set_error_handler\|Recovery\|PanicHandler" --include="*.py" --include="*.js" --include="*.ts" --include="*.rb" --include="*.java" --include="*.go" --include="*.php"

# Custom error pages
grep -rn "404\|500\|error.*page\|error.*template" --include="*.py" --include="*.js" --include="*.ts" --include="*.rb" --include="*.html"
```

### What to Flag as Missing

- No global error handler (stack traces may leak)
- No custom error pages for 4xx/5xx
- Exception handling that catches and ignores silently

## Transport Security

### Detection: Is HTTPS enforced?

```bash
# HTTPS enforcement/redirect
grep -rn "SECURE_SSL_REDIRECT\|force_ssl\|requireHTTPS\|redirect.*https\|http.*redirect\|HTTPS_ONLY" --include="*.py" --include="*.js" --include="*.ts" --include="*.rb" --include="*.java" --include="*.conf" --include="*.env"

# Certificate pinning (mobile/API)
grep -rn "pinning\|certificate.*pin\|ssl.*pin\|TrustManager\|CertificatePinner" --include="*.java" --include="*.kt" --include="*.swift" --include="*.m"
```

## Summary: Minimum Security Baseline

Flag a project as missing baseline security if ANY of these are absent:

| Control | Detection Method |
|---------|-----------------|
| Input validation library | Package dependencies |
| Rate limiting on auth endpoints | Route + middleware analysis |
| Security headers (CSP, HSTS minimum) | Middleware/config scan |
| Logging framework | Package dependencies |
| Global error handler | Route/middleware scan |
| Dependency lock file | File system check |
| HTTPS enforcement | Config scan |
