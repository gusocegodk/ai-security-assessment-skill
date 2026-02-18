# Cross-Site Scripting (XSS)

CWE-79 (XSS), OWASP A03:2021

## Table of Contents
- [DOM-based XSS](#dom-based-xss)
- [Reflected XSS](#reflected-xss)
- [Stored XSS](#stored-xss)

## DOM-based XSS

### Detection Patterns

```bash
# Dangerous sinks
grep -rn "innerHTML\|outerHTML\|document\.write\|eval\|setTimeout\|setInterval" --include="*.js" --include="*.ts" --include="*.jsx" --include="*.tsx"

# jQuery dangerous methods
grep -rn "\.html\(\|\.append\(\|\.prepend\(\|\.after\(\|\.before\(" --include="*.js"

# React dangerouslySetInnerHTML
grep -rn "dangerouslySetInnerHTML" --include="*.jsx" --include="*.tsx"

# Angular bypass security
grep -rn "bypassSecurityTrust\|DomSanitizer" --include="*.ts"

# Vue v-html directive
grep -rn "v-html" --include="*.vue"
```

### Vulnerable Patterns

```javascript
// VULNERABLE: Direct innerHTML assignment
element.innerHTML = userInput;
document.getElementById("output").innerHTML = location.hash.slice(1);

// SECURE: Use textContent or sanitize
element.textContent = userInput;
element.innerHTML = DOMPurify.sanitize(userInput);
```

```jsx
// VULNERABLE: React dangerouslySetInnerHTML without sanitization
<div dangerouslySetInnerHTML={{__html: userContent}} />

// SECURE: Sanitize first
<div dangerouslySetInnerHTML={{__html: DOMPurify.sanitize(userContent)}} />
```

## Reflected XSS

### Detection Patterns

```bash
# URL parameters rendered in templates
grep -rn "request\.GET\|request\.query\|req\.query\|params\[" --include="*.py" --include="*.js" --include="*.php" --include="*.rb"

# Template rendering without escaping
grep -rn "render_template_string\|Markup\|safe\||safe\|{!!.*!!}\|<%=.*%>" --include="*.py" --include="*.php" --include="*.erb" --include="*.blade.php"
```

### Vulnerable Patterns

```python
# VULNERABLE: Jinja2 with Markup or |safe
return Markup(f"<p>Hello {user_input}</p>")
return render_template("page.html", content=user_input|safe)

# SECURE: Let template engine escape
return render_template("page.html", content=user_input)
```

```php
// VULNERABLE: Direct echo
echo $_GET['name'];

// SECURE: Escape output
echo htmlspecialchars($_GET['name'], ENT_QUOTES, 'UTF-8');
```

## Stored XSS

### Detection Patterns

```bash
# Database content rendered in views
grep -rn "\.save\(\|\.create\(\|\.insert" --include="*.py" --include="*.js" --include="*.rb"

# Then check corresponding view rendering
grep -rn "innerHTML\||safe\|Markup\|raw\|html_safe" --include="*.py" --include="*.js" --include="*.rb" --include="*.html"
```

### Key Areas to Check

1. User profile fields (bio, name, avatar URL)
2. Comments and posts
3. File names displayed in UI
4. Error messages containing user input
5. Search terms displayed on results page
6. Chat/messaging features
7. Admin panels displaying user data

### Framework-Specific Notes

| Framework | Auto-escape | Bypass Syntax |
|-----------|-------------|---------------|
| React | Yes (JSX) | dangerouslySetInnerHTML |
| Angular | Yes | bypassSecurityTrust* |
| Vue | Yes | v-html directive |
| Django | Yes | \|safe, mark_safe() |
| Rails | Yes | raw(), html_safe |
| Laravel | Yes | {!! !!} |
