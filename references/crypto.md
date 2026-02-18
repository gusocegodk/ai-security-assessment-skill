# Cryptographic Failures

CWE-327 (Broken Crypto), CWE-328 (Weak Hash), OWASP A02:2021

## Table of Contents
- [Weak Algorithms](#weak-algorithms)
- [Key Management](#key-management)
- [Randomness](#randomness)
- [TLS Configuration](#tls-configuration)

## Weak Algorithms

### Detection Patterns

```bash
# Weak hash algorithms
grep -rn "md5\|sha1\|MD5\|SHA1" --include="*.py" --include="*.js" --include="*.java" --include="*.go" --include="*.rb" --include="*.php"

# Weak encryption
grep -rn "DES\|3DES\|RC4\|RC2\|Blowfish\|ECB" --include="*.py" --include="*.js" --include="*.java" --include="*.go"

# Weak key derivation
grep -rn "PBKDF2.*iterations.*1000\|bcrypt.*cost.*[0-9]\|rounds\s*=\s*[0-9]" --include="*.py" --include="*.js"

# Check for proper algorithms (positive)
grep -rn "AES-256-GCM\|ChaCha20\|Argon2\|bcrypt\|scrypt" --include="*.py" --include="*.js" --include="*.java"
```

### Algorithm Classification

| Deprecated (Do Not Use) | Acceptable | Recommended |
|-------------------------|------------|-------------|
| MD5, SHA1 (for security) | SHA-256 | SHA-256, SHA-3, BLAKE2 |
| DES, 3DES, RC4 | AES-128 | AES-256-GCM, ChaCha20-Poly1305 |
| RSA-1024 | RSA-2048 | RSA-4096, Ed25519 |
| PBKDF2 (<10k iterations) | bcrypt (cost 10) | Argon2id |

### Vulnerable Patterns

```python
# VULNERABLE: MD5 for password hashing
password_hash = hashlib.md5(password.encode()).hexdigest()

# VULNERABLE: DES encryption
cipher = DES.new(key, DES.MODE_ECB)

# SECURE: AES-256-GCM
cipher = AES.new(key, AES.MODE_GCM)

# SECURE: Argon2 for passwords
password_hash = argon2.hash(password)
```

```javascript
// VULNERABLE: Weak algorithm
crypto.createHash('md5').update(data).digest('hex');
crypto.createCipher('des', key);  // Deprecated API too

// SECURE
crypto.createHash('sha256').update(data).digest('hex');
crypto.createCipheriv('aes-256-gcm', key, iv);
```

## Key Management

### Detection Patterns

```bash
# Hardcoded keys
grep -rn "key\s*=\s*['\"]" --include="*.py" --include="*.js" --include="*.java" | grep -v "api_key\|public_key"

# Key in source code
grep -rn "AES\|RSA\|HMAC" --include="*.py" --include="*.js" | grep -E "key\s*=\s*['\"][a-zA-Z0-9]+"

# Static IVs/nonces
grep -rn "iv\s*=\s*\|nonce\s*=\s*\|IV\s*=\s*" --include="*.py" --include="*.js" --include="*.java"
```

### Vulnerable Patterns

```python
# VULNERABLE: Hardcoded key
key = b"0123456789abcdef"

# VULNERABLE: Static IV (reuse)
iv = b"\x00" * 16

# SECURE: Key from secure storage
key = get_key_from_vault('encryption_key')

# SECURE: Random IV
iv = os.urandom(16)
```

### Key Management Checklist

- [ ] Keys stored in secrets manager (Vault, AWS KMS, etc.)
- [ ] Keys rotated periodically
- [ ] Different keys for different environments
- [ ] IVs/nonces generated randomly per operation
- [ ] Key derivation uses salt
- [ ] Old keys securely destroyed

## Randomness

### Detection Patterns

```bash
# Insecure random
grep -rn "Math\.random\|random\.random\|random\.randint\|rand\(\)" --include="*.py" --include="*.js" --include="*.java" --include="*.rb" --include="*.php"

# Should use secure random
grep -rn "token\|secret\|key\|session\|nonce\|salt" --include="*.py" --include="*.js" | grep -i "random"
```

### Vulnerable Patterns

```python
# VULNERABLE: Predictable random
import random
token = ''.join(random.choice('abcdef0123456789') for _ in range(32))

# SECURE: Cryptographically secure
import secrets
token = secrets.token_hex(32)
```

```javascript
// VULNERABLE: Math.random() is predictable
const token = Math.random().toString(36).substring(2);

// SECURE: crypto module
const crypto = require('crypto');
const token = crypto.randomBytes(32).toString('hex');
```

### When Secure Random is Required

- Session tokens
- CSRF tokens
- Password reset tokens
- API keys/secrets
- Encryption keys
- IVs/nonces
- Salts
- OTP/MFA codes

## TLS Configuration

### Detection Patterns

```bash
# SSL/TLS version configuration
grep -rn "SSLv2\|SSLv3\|TLSv1\.0\|TLSv1\.1\|ssl_version\|tls_version" --include="*.py" --include="*.js" --include="*.conf" --include="*.yml"

# Certificate verification disabled
grep -rn "verify\s*=\s*False\|rejectUnauthorized\s*:\s*false\|CERT_NONE\|InsecureRequestWarning" --include="*.py" --include="*.js"

# Self-signed certificates
grep -rn "self-signed\|selfsigned\|INSECURE" --include="*.py" --include="*.js" --include="*.yml"
```

### Vulnerable Patterns

```python
# VULNERABLE: Disabled certificate verification
requests.get(url, verify=False)

# VULNERABLE: Old TLS versions
ssl_context.options |= ssl.OP_NO_SSLv3  # Implies SSLv3 was considered

# SECURE
requests.get(url, verify=True)
ssl_context.minimum_version = ssl.TLSVersion.TLSv1_2
```

```javascript
// VULNERABLE: Disabled TLS verification
process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';

// SECURE: Keep defaults
// Don't set NODE_TLS_REJECT_UNAUTHORIZED
```

## Cryptography Checklist

- [ ] No MD5/SHA1 for security purposes
- [ ] AES-256-GCM or ChaCha20-Poly1305 for encryption
- [ ] Argon2id or bcrypt (cost ≥10) for passwords
- [ ] RSA ≥2048 bits or Ed25519 for signatures
- [ ] Keys from secure storage, not hardcoded
- [ ] Random IVs/nonces for each operation
- [ ] Cryptographically secure random for tokens
- [ ] TLS 1.2+ enforced
- [ ] Certificate verification enabled
