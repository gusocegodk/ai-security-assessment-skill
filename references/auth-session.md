# Authentication & Session Management

CWE-287 (Improper Auth), CWE-384 (Session Fixation), OWASP A07:2021

## Table of Contents
- [Password Handling](#password-handling)
- [Authentication Logic](#authentication-logic)
- [Session Management](#session-management)
- [Multi-Factor Authentication](#multi-factor-authentication)
- [JWT Security](#jwt-security)

## Password Handling

### Detection Patterns

```bash
# Weak hashing algorithms
grep -rn "md5\|sha1\|sha256" --include="*.py" --include="*.js" --include="*.java" --include="*.php" | grep -i "password\|passwd\|pwd"

# Password in logs or error messages
grep -rn "log.*password\|print.*password\|console\.log.*password" --include="*.py" --include="*.js" --include="*.java"

# Plaintext password storage
grep -rn "password\s*=\|passwd\s*=" --include="*.sql" --include="*.py" --include="*.js"

# Proper bcrypt/argon2 usage (positive check)
grep -rn "bcrypt\|argon2\|scrypt\|pbkdf2" --include="*.py" --include="*.js" --include="*.java"
```

### Vulnerable Patterns

```python
# VULNERABLE: Weak hashing
password_hash = hashlib.md5(password.encode()).hexdigest()
password_hash = hashlib.sha256(password.encode()).hexdigest()

# SECURE: Use bcrypt or argon2
password_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=12))
# or
password_hash = argon2.hash(password)
```

### Password Policy Checks

Look for enforcement of:
- Minimum length (≥12 characters recommended)
- Complexity requirements
- Breach database checking (HaveIBeenPwned API)
- Rate limiting on login attempts

## Authentication Logic

### Detection Patterns

```bash
# Authentication bypass patterns
grep -rn "isAdmin\|is_admin\|role\s*==\|role\s*===\|authenticated\s*=" --include="*.py" --include="*.js" --include="*.java"

# Timing attacks in comparison
grep -rn "==.*password\|===.*password\|\.equals.*password" --include="*.py" --include="*.js" --include="*.java"

# Account enumeration via different responses
grep -rn "user not found\|invalid user\|no such user\|email not registered" --include="*.py" --include="*.js" --include="*.java"
```

### Vulnerable Patterns

```python
# VULNERABLE: Timing attack possible
if user.password == submitted_password:
    return True

# SECURE: Constant-time comparison
if hmac.compare_digest(user.password_hash, computed_hash):
    return True
```

```python
# VULNERABLE: Account enumeration
if not user_exists(email):
    return "User not found"
elif not check_password(email, password):
    return "Wrong password"

# SECURE: Generic error message
if not authenticate(email, password):
    return "Invalid credentials"
```

## Session Management

### Detection Patterns

```bash
# Session configuration
grep -rn "session\|cookie\|SESSION" --include="*.py" --include="*.js" --include="*.php" --include="*.rb" --include="*.config" --include="*.json"

# Session ID in URL
grep -rn "sessionid=\|PHPSESSID=\|JSESSIONID=" --include="*.py" --include="*.js" --include="*.php"

# Missing session regeneration
grep -rn "login\|authenticate\|sign_in" --include="*.py" --include="*.js" --include="*.php" --include="*.rb"
```

### Checklist

- [ ] HttpOnly flag on session cookies
- [ ] Secure flag on session cookies (HTTPS only)
- [ ] SameSite attribute set (Lax or Strict)
- [ ] Session regeneration after login
- [ ] Session invalidation on logout
- [ ] Reasonable session timeout
- [ ] Session ID entropy (≥128 bits)

### Vulnerable Patterns

```python
# VULNERABLE: Missing session regeneration
def login(user):
    session['user_id'] = user.id  # Same session ID

# SECURE: Regenerate session
def login(user):
    session.regenerate()  # New session ID
    session['user_id'] = user.id
```

## Multi-Factor Authentication

### Detection Patterns

```bash
# MFA/2FA implementation
grep -rn "totp\|otp\|2fa\|mfa\|authenticator\|verification_code" --include="*.py" --include="*.js" --include="*.java"

# Backup codes
grep -rn "backup_code\|recovery_code" --include="*.py" --include="*.js"
```

### Checklist

- [ ] MFA bypass not possible via API
- [ ] Rate limiting on code verification
- [ ] Codes are time-limited
- [ ] Backup codes are hashed
- [ ] MFA required for sensitive operations

## JWT Security

### Detection Patterns

```bash
# JWT usage
grep -rn "jwt\|jsonwebtoken\|jose\|JWT" --include="*.py" --include="*.js" --include="*.java" --include="*.go"

# Algorithm configuration
grep -rn "algorithm\|alg\|HS256\|RS256\|none" --include="*.py" --include="*.js"

# Secret handling
grep -rn "secret\|SECRET_KEY\|JWT_SECRET" --include="*.py" --include="*.js" --include="*.env"
```

### Vulnerable Patterns

```javascript
// VULNERABLE: Algorithm confusion possible
jwt.verify(token, secret);  // No algorithm specified

// SECURE: Explicit algorithm
jwt.verify(token, secret, { algorithms: ['HS256'] });
```

```javascript
// VULNERABLE: Weak or hardcoded secret
const secret = "mysecret123";

// SECURE: Strong, environment-sourced secret
const secret = process.env.JWT_SECRET; // Should be 256+ bits of entropy
```

### JWT Checklist

- [ ] Algorithm explicitly specified (no "none" allowed)
- [ ] Strong secret (≥256 bits for HMAC)
- [ ] Reasonable expiration (exp claim)
- [ ] Token validated server-side
- [ ] Sensitive data not in payload (or encrypted)
