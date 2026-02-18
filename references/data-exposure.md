# Sensitive Data Exposure

CWE-200 (Information Exposure), CWE-532 (Log Injection), OWASP A02:2021

## Table of Contents
- [Hardcoded Secrets](#hardcoded-secrets)
- [Sensitive Data Logging](#sensitive-data-logging)
- [PII Exposure](#pii-exposure)
- [API Key Exposure](#api-key-exposure)
- [Source Code Exposure](#source-code-exposure)

## Hardcoded Secrets

### Detection Patterns

```bash
# API keys and tokens
grep -rn "api_key\|apikey\|api-key\|secret_key\|secretkey\|access_token\|auth_token" --include="*.py" --include="*.js" --include="*.java" --include="*.go" --include="*.rb"

# AWS credentials
grep -rn "AKIA\|aws_access_key\|aws_secret" --include="*"

# Private keys
grep -rn "BEGIN.*PRIVATE KEY\|BEGIN RSA\|BEGIN EC\|BEGIN DSA" --include="*"

# Connection strings with passwords
grep -rn "mysql://\|postgres://\|mongodb://\|redis://\|amqp://" --include="*.py" --include="*.js" --include="*.env" --include="*.yml"

# Common secret patterns
grep -rn "password\s*=\|passwd\s*=\|secret\s*=\|token\s*=" --include="*.py" --include="*.js" --include="*.java" --include="*.env" | grep -v "\.example\|test\|spec\|mock"

# Base64-encoded secrets (JWT, API keys)
grep -rn "eyJ\|sk-\|pk_live\|sk_live\|ghp_\|gho_\|glpat-" --include="*.py" --include="*.js" --include="*.ts"
```

### High-Entropy String Detection

Look for long random strings that could be secrets:
- 32+ character alphanumeric strings
- Base64 strings in configuration
- Hex strings (64+ chars could be SHA256)

### Vulnerable Patterns

```python
# VULNERABLE: Hardcoded secrets
API_KEY = "sk-1234567890abcdef"
DATABASE_URL = "postgres://user:password123@db.example.com/prod"

# SECURE: Environment variables
API_KEY = os.environ.get('API_KEY')
DATABASE_URL = os.environ.get('DATABASE_URL')
```

## Sensitive Data Logging

### Detection Patterns

```bash
# Logging sensitive fields
grep -rn "log.*password\|log.*token\|log.*secret\|log.*api_key\|log.*credit\|log.*ssn\|log.*card" --include="*.py" --include="*.js" --include="*.java"

# Request/response body logging
grep -rn "log.*req\.body\|log.*request\.json\|log.*response" --include="*.py" --include="*.js"

# Debug logging of user data
grep -rn "console\.log.*user\|print.*user\|logger.*user" --include="*.py" --include="*.js"
```

### Vulnerable Patterns

```python
# VULNERABLE: Logging sensitive data
logger.info(f"User login: {username}, password: {password}")
logger.debug(f"Request body: {request.json}")  # May contain secrets

# SECURE: Sanitize before logging
logger.info(f"User login: {username}")
logger.debug(f"Request to: {request.path}")
```

## PII Exposure

### Detection Patterns

```bash
# Social Security Numbers
grep -rn "ssn\|social_security\|tax_id" --include="*.py" --include="*.js" --include="*.java"

# Credit card numbers
grep -rn "card_number\|credit_card\|ccn\|pan" --include="*.py" --include="*.js"

# Health information
grep -rn "diagnosis\|medical\|health_record\|hipaa" --include="*.py" --include="*.js"

# PII in URLs/query strings
grep -rn "email=\|phone=\|ssn=\|name=" --include="*.py" --include="*.js" | grep -i "get\|query\|url"
```

### Data Classification

| Category | Examples | Handling |
|----------|----------|----------|
| Critical | SSN, Credit Card, Health | Encrypt at rest, mask in logs |
| Sensitive | Email, Phone, DOB | Access control, audit logging |
| Internal | User ID, Preferences | Standard protection |

## API Key Exposure

### Detection Patterns

```bash
# Keys in frontend code
grep -rn "api_key\|apiKey\|API_KEY" --include="*.jsx" --include="*.tsx" --include="*.vue" --include="*.html"

# Keys in public repositories (check .gitignore)
cat .gitignore | grep -i "env\|secret\|key\|credential"

# Keys in config files that shouldn't be committed
grep -rn "sk-\|pk_\|api_key" --include="*.json" --include="*.yml" --include="*.yaml"
```

### Common Exposed Keys

| Service | Pattern | Risk |
|---------|---------|------|
| AWS | AKIA... | Account compromise |
| GitHub | ghp_, gho_ | Repo access |
| Stripe | sk_live_, pk_live_ | Financial |
| OpenAI | sk-... | API abuse |
| Slack | xox... | Workspace access |

## Source Code Exposure

### Detection Patterns

```bash
# Source maps in production
find . -name "*.map" -o -name "*.js.map"

# Backup files
find . -name "*.bak" -o -name "*.old" -o -name "*.orig" -o -name "*~"

# IDE/editor files
find . -name ".idea" -o -name ".vscode" -o -name "*.swp"

# Git directory exposed
ls -la .git
```

## .env File Exposure

### Detection Patterns

```bash
# .env files committed to repo
find . -name ".env" -o -name ".env.local" -o -name ".env.production" -o -name ".env.staging" | grep -v node_modules | grep -v .git

# Check if .env is in .gitignore
grep -n "\.env" .gitignore

# .env referenced but potentially missing from .gitignore
grep -rn "dotenv\|load_dotenv\|config()\|from_envvar" --include="*.py" --include="*.js" --include="*.ts" --include="*.rb"
```

### What to Flag

- `.env` files present in repo without `.gitignore` entry
- `.env.example` containing real values instead of placeholders
- Multiple `.env.*` variants that may contain production secrets

## Secrets in Comments and Documentation

### Detection Patterns

```bash
# Secrets in code comments
grep -rn "TODO.*password\|FIXME.*secret\|HACK.*key\|#.*api_key.*=\|//.*password.*=" --include="*.py" --include="*.js" --include="*.ts" --include="*.java" --include="*.rb" --include="*.go"

# Secrets in markdown/docs
grep -rn "password\|secret\|api.key\|token" --include="*.md" | grep -v "CHANGEME\|<.*>\|example\|placeholder\|your_"
```

## Git History Secret Scanning

### Detection Guidance

When assessing a repo, note if secrets scanning has been done on git history:

```bash
# Check for git-secrets, trufflehog, or gitleaks in CI
grep -rn "git-secrets\|trufflehog\|gitleaks\|detect-secrets\|whispers" --include="*.yml" --include="*.yaml" --include="*.json" --include="Makefile" --include="Dockerfile"

# Check pre-commit hooks for secret scanning
cat .pre-commit-config.yaml 2>/dev/null | grep -i "secret\|trufflehog\|gitleaks"
```

Flag as **Medium** finding if:
- No secret scanning tool configured in CI/CD pipeline
- No pre-commit hook for secret detection
- Hardcoded secrets found in current code (likely also in history)

## High-Entropy String Hints

When reviewing code manually, look for these high-entropy patterns that automated grep may miss:

| Pattern | Likely Secret |
|---------|--------------|
| 40-char hex string | SHA1 hash, API token |
| 64-char hex string | SHA256 hash, secret key |
| 32+ char alphanumeric | API key, random token |
| Base64 string > 40 chars in config | Encrypted key, certificate |
| String starting with `ey` in config | JWT token (base64 encoded JSON) |

## Data Protection Checklist

- [ ] No hardcoded secrets in code
- [ ] No secrets in comments or documentation
- [ ] .gitignore includes .env and sensitive files
- [ ] Environment variables for secrets
- [ ] Secrets management system (Vault, AWS Secrets Manager)
- [ ] Git history scanned for leaked secrets
- [ ] Secret scanning in CI/CD pipeline
- [ ] Pre-commit hooks for secret detection
- [ ] PII encrypted at rest
- [ ] PII masked in logs
- [ ] No PII in URLs
- [ ] API keys not in frontend
- [ ] Source maps disabled in production
- [ ] Backup files not accessible
