# Open Redirect

CWE-601 (URL Redirection to Untrusted Site), OWASP A01:2021

## Table of Contents
- [Detection Patterns](#detection-patterns)
- [Common Vulnerable Patterns](#common-vulnerable-patterns)
- [Framework-Specific Patterns](#framework-specific-patterns)
- [Bypass Techniques to Check](#bypass-techniques-to-check)

## Detection Patterns

```bash
# Redirect functions with user input
grep -rn "redirect\|sendRedirect\|header.*Location\|res\.redirect\|redirect_to\|HttpResponseRedirect" --include="*.py" --include="*.js" --include="*.java" --include="*.rb" --include="*.php" --include="*.go" --include="*.ts"

# URL parameters commonly used for redirects
grep -rn "return_url\|redirect_url\|next\|redir\|url\|goto\|dest\|destination\|continue\|return_to\|forward\|target\|callback_url\|success_url" --include="*.py" --include="*.js" --include="*.java" --include="*.rb" --include="*.php" | grep -i "request\|param\|query\|args\|get\|post"

# Login/OAuth redirect patterns
grep -rn "login.*redirect\|auth.*callback\|oauth.*redirect\|next=\|returnTo\|post_login\|after_login" --include="*.py" --include="*.js" --include="*.java" --include="*.rb" --include="*.php"

# JavaScript client-side redirects
grep -rn "window\.location\|location\.href\|location\.assign\|location\.replace" --include="*.js" --include="*.ts" --include="*.jsx" --include="*.tsx" --include="*.html"
```

## Common Vulnerable Patterns

### Server-Side Redirects

```python
# VULNERABLE: Direct redirect from user input
@app.route('/login')
def login():
    next_url = request.args.get('next')
    if authenticate(user):
        return redirect(next_url)  # Open redirect

# VULNERABLE: Django
def login_view(request):
    return HttpResponseRedirect(request.GET.get('next', '/'))

# SECURE: Validate against allowlist
@app.route('/login')
def login():
    next_url = request.args.get('next', '/')
    if not is_safe_url(next_url):
        next_url = '/'
    return redirect(next_url)

def is_safe_url(url):
    """Only allow relative paths to the same host."""
    from urllib.parse import urlparse
    parsed = urlparse(url)
    return not parsed.netloc and not parsed.scheme
```

```javascript
// VULNERABLE: Express redirect from query param
app.get('/callback', (req, res) => {
    res.redirect(req.query.redirect_url);  // Open redirect
});

// SECURE: Validate the URL
app.get('/callback', (req, res) => {
    const url = req.query.redirect_url || '/';
    if (!url.startsWith('/') || url.startsWith('//')) {
        return res.redirect('/');
    }
    res.redirect(url);
});
```

```java
// VULNERABLE: Java servlet
String url = request.getParameter("url");
response.sendRedirect(url);  // Open redirect

// SECURE: Allowlist validation
String url = request.getParameter("url");
if (ALLOWED_REDIRECTS.contains(url)) {
    response.sendRedirect(url);
} else {
    response.sendRedirect("/");
}
```

### Client-Side Redirects

```javascript
// VULNERABLE: URL from hash/query used for redirect
const params = new URLSearchParams(window.location.search);
window.location.href = params.get('url');  // Open redirect

// VULNERABLE: Document referrer used without validation
window.location = document.referrer;

// SECURE: Validate against allowed origins
const url = params.get('url');
try {
    const parsed = new URL(url, window.location.origin);
    if (parsed.origin === window.location.origin) {
        window.location.href = parsed.href;
    }
} catch {
    window.location.href = '/';
}
```

## Framework-Specific Patterns

```bash
# Django: next parameter in login
grep -rn "LOGIN_REDIRECT_URL\|next\|redirect_field_name" --include="*.py"

# Rails: redirect_to with params
grep -rn "redirect_to.*params\|redirect_back" --include="*.rb"

# Spring: redirect: prefix
grep -rn "redirect:" --include="*.java" | grep -i "request\|param"

# Express: res.redirect with req
grep -rn "res\.redirect.*req\.\|res\.redirect.*params" --include="*.js" --include="*.ts"

# Go: http.Redirect with user input
grep -rn "http\.Redirect\|Redirect(" --include="*.go"

# PHP: header Location with user input
grep -rn "header.*Location.*\$_GET\|header.*Location.*\$_POST\|header.*Location.*\$_REQUEST" --include="*.php"
```

## Bypass Techniques to Check

When validating redirect protections, verify these bypasses are blocked:

| Bypass | Example | What It Exploits |
|--------|---------|-----------------|
| Protocol-relative | `//evil.com` | Starts with `/` check passes |
| Backslash | `\evil.com` | Some parsers treat `\` as `/` |
| @ symbol | `https://legit.com@evil.com` | URL userinfo field |
| Subdomain | `https://evil.com.legit.com` | Weak domain check |
| URL encoding | `%2F%2Fevil.com` | Decoded after validation |
| Null byte | `https://legit.com%00.evil.com` | Truncation |
| Tab/newline | `http://evil.com%09` | Whitespace injection |
| Data URI | `data:text/html,<script>...` | Alternative protocol |
| JavaScript URI | `javascript:alert(1)` | JS execution instead of redirect |

### Testing Patterns

```bash
# Check if validation only checks prefix
grep -rn "startswith\|starts_with\|indexOf.*==.*0\|\.startsWith" --include="*.py" --include="*.js" --include="*.rb" | grep -i "redirect\|url\|next"

# Check if protocol-relative URLs are blocked
grep -rn "startswith.*/" --include="*.py" | grep -v "//"
```

## Open Redirect Checklist

- [ ] All redirect targets validated against allowlist or restricted to relative paths
- [ ] Protocol-relative URLs (`//evil.com`) blocked
- [ ] Backslash URLs (`\evil.com`) blocked
- [ ] URL parsing used (not string matching) for validation
- [ ] Login/OAuth flows validate `next`/`redirect_uri` parameters
- [ ] Client-side redirects validate origin before `window.location` assignment
- [ ] `javascript:` and `data:` URI schemes rejected in redirect targets
