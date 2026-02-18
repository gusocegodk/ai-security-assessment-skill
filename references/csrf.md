# CSRF Protection

CWE-352 (CSRF), OWASP A01:2021

## Detection Patterns

```bash
# Forms without CSRF tokens
grep -rn "<form" --include="*.html" --include="*.jsx" --include="*.vue" --include="*.erb" --include="*.blade.php" | grep -v "csrf\|_token"

# State-changing endpoints without CSRF protection
grep -rn "app\.post\|app\.put\|app\.delete\|@app\.route.*methods.*POST" --include="*.py" --include="*.js"

# CSRF middleware/configuration
grep -rn "csrf\|CSRF\|csurf\|CsrfViewMiddleware" --include="*.py" --include="*.js" --include="*.config" --include="*.json"

# Cookie configuration
grep -rn "SameSite\|samesite\|cookie" --include="*.py" --include="*.js" --include="*.config"
```

## Vulnerable Patterns

```python
# VULNERABLE: No CSRF token validation
@app.route('/transfer', methods=['POST'])
def transfer():
    amount = request.form['amount']
    to_account = request.form['to_account']
    perform_transfer(current_user, to_account, amount)
```

```html
<!-- VULNERABLE: Form without CSRF token -->
<form action="/transfer" method="POST">
    <input name="amount" type="number">
    <input name="to_account" type="text">
    <button type="submit">Transfer</button>
</form>

<!-- SECURE: With CSRF token -->
<form action="/transfer" method="POST">
    <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
    <input name="amount" type="number">
    <input name="to_account" type="text">
    <button type="submit">Transfer</button>
</form>
```

## Cookie Security Settings

```javascript
// SECURE: Cookie configuration
app.use(session({
    cookie: {
        httpOnly: true,
        secure: true,  // HTTPS only
        sameSite: 'strict',  // or 'lax'
        maxAge: 3600000
    }
}));
```

```python
# SECURE: Flask cookie settings
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
```

## Framework-Specific CSRF

| Framework | Default Protection | Check For |
|-----------|-------------------|-----------|
| Django | ✅ CsrfViewMiddleware | @csrf_exempt decorators |
| Rails | ✅ protect_from_forgery | skip_before_action :verify_authenticity_token |
| Laravel | ✅ VerifyCsrfToken | $except array, @csrf blade |
| Express | ❌ Manual | csurf middleware |
| Spring | ❌ Manual | csrf().disable() |
| Flask | ❌ Manual | Flask-WTF CSRFProtect |

## CSRF Checklist

- [ ] CSRF tokens on all state-changing forms
- [ ] Token validation on server side
- [ ] SameSite cookie attribute set
- [ ] Tokens are unpredictable (random, per-session)
- [ ] Double-submit cookie if using SPA
- [ ] No CSRF exemptions on sensitive endpoints
