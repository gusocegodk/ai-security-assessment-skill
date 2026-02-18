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

## OAuth / OIDC Security

### Detection Patterns

```bash
# OAuth libraries and configuration
grep -rn "oauth\|OAuth\|passport\|OAuthLib\|authlib\|omniauth\|spring-security-oauth\|oidc\|openid" --include="*.py" --include="*.js" --include="*.ts" --include="*.rb" --include="*.java" --include="*.go"

# Redirect URI configuration
grep -rn "redirect_uri\|callback_url\|callbackURL\|redirect_url\|OAUTH.*REDIRECT\|authorization_url" --include="*.py" --include="*.js" --include="*.ts" --include="*.rb" --include="*.java" --include="*.env"

# State parameter handling
grep -rn "state\s*=\|state=\|csrf.*state\|anti_forgery\|state_token" --include="*.py" --include="*.js" --include="*.ts" --include="*.rb" --include="*.java" | grep -i "oauth\|auth\|callback"

# Token storage
grep -rn "access_token\|refresh_token\|id_token" --include="*.py" --include="*.js" --include="*.ts" | grep -i "localStorage\|sessionStorage\|cookie\|store\|save\|set"
```

### Vulnerable Patterns

```python
# VULNERABLE: No state parameter (CSRF on OAuth flow)
@app.route('/login/github')
def github_login():
    return redirect(f"https://github.com/login/oauth/authorize?"
                    f"client_id={CLIENT_ID}&redirect_uri={REDIRECT_URI}")
    # Missing state parameter!

# SECURE: State parameter with verification
@app.route('/login/github')
def github_login():
    state = secrets.token_urlsafe(32)
    session['oauth_state'] = state
    return redirect(f"https://github.com/login/oauth/authorize?"
                    f"client_id={CLIENT_ID}&redirect_uri={REDIRECT_URI}&state={state}")

@app.route('/callback')
def callback():
    if request.args.get('state') != session.pop('oauth_state', None):
        abort(403)  # CSRF protection
    # ... exchange code for token
```

```javascript
// VULNERABLE: Token stored in localStorage (XSS accessible)
localStorage.setItem('access_token', response.data.token);

// VULNERABLE: Client secret exposed in frontend
const clientSecret = 'abc123';  // Never do this

// SECURE: Token in httpOnly cookie, secret on server only
res.cookie('token', accessToken, {
    httpOnly: true,
    secure: true,
    sameSite: 'Lax'
});
```

```javascript
// VULNERABLE: Open redirect_uri allows token theft
app.get('/callback', (req, res) => {
    // Accepts any redirect_uri from the request
    const redirectUri = req.query.redirect_uri;
});

// SECURE: Validate redirect_uri against registered values
const REGISTERED_URIS = ['https://app.example.com/callback'];
if (!REGISTERED_URIS.includes(redirectUri)) {
    return res.status(400).json({ error: 'Invalid redirect_uri' });
}
```

### OAuth/OIDC Checklist

- [ ] State parameter used and validated (CSRF protection)
- [ ] Redirect URIs strictly validated against registered list
- [ ] Client secret stored server-side only (never in frontend)
- [ ] PKCE used for public clients (SPAs, mobile apps)
- [ ] Access tokens not stored in localStorage (use httpOnly cookies)
- [ ] Token exchange happens server-side (authorization code flow)
- [ ] Refresh tokens rotated on use
- [ ] Scopes follow principle of least privilege
- [ ] ID token signature verified
- [ ] Token expiration enforced
