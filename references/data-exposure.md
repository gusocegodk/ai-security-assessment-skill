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

## Data Protection Checklist

- [ ] No hardcoded secrets in code
- [ ] .gitignore includes sensitive files
- [ ] Environment variables for secrets
- [ ] Secrets management system (Vault, AWS Secrets Manager)
- [ ] PII encrypted at rest
- [ ] PII masked in logs
- [ ] No PII in URLs
- [ ] API keys not in frontend
- [ ] Source maps disabled in production
- [ ] Backup files not accessible
