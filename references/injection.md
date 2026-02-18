# Injection Vulnerabilities

CWE-89 (SQL), CWE-78 (OS Command), CWE-22 (Path Traversal), CWE-943 (NoSQL)

## Table of Contents
- [SQL Injection](#sql-injection)
- [Command Injection](#command-injection)
- [Path Traversal](#path-traversal)
- [NoSQL Injection](#nosql-injection)
- [LDAP/XPath Injection](#ldapxpath-injection)

## SQL Injection

### Detection Patterns

```bash
# String concatenation in queries
grep -rn "SELECT.*\+.*\|INSERT.*\+.*\|UPDATE.*\+.*\|DELETE.*\+.*" --include="*.py" --include="*.js" --include="*.java" --include="*.php"

# Format strings in queries
grep -rn "execute.*%s\|execute.*\.format\|cursor.*%s" --include="*.py"

# Raw queries with variables
grep -rn "raw\|rawQuery\|executeQuery" --include="*.java" --include="*.kt"

# Template literals in SQL (JS/TS)
grep -rn "query\s*\`\|sql\s*\`" --include="*.js" --include="*.ts"
```

### Vulnerable Patterns

```python
# VULNERABLE: String concatenation
query = "SELECT * FROM users WHERE id = " + user_id
cursor.execute(f"SELECT * FROM users WHERE name = '{name}'")

# SECURE: Parameterized queries
cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
```

```javascript
// VULNERABLE
db.query(`SELECT * FROM users WHERE id = ${userId}`);

// SECURE
db.query("SELECT * FROM users WHERE id = ?", [userId]);
```

## Command Injection

### Detection Patterns

```bash
# Shell execution functions
grep -rn "exec\|system\|popen\|subprocess\|spawn\|shell_exec" --include="*.py" --include="*.js" --include="*.php" --include="*.rb"

# Backticks or $() with variables
grep -rn '\`.*\$\|\$(\|child_process' --include="*.js" --include="*.sh"
```

### Vulnerable Patterns

```python
# VULNERABLE
os.system(f"ping {user_input}")
subprocess.call(user_input, shell=True)

# SECURE
subprocess.run(["ping", "-c", "1", validated_host], shell=False)
```

## Path Traversal

### Detection Patterns

```bash
# File operations with user input
grep -rn "open\|readFile\|writeFile\|readFileSync\|file_get_contents" --include="*.py" --include="*.js" --include="*.php"

# Path joining without validation
grep -rn "path\.join\|os\.path\.join\|File\.join" --include="*.py" --include="*.js" --include="*.rb"
```

### Vulnerable Patterns

```python
# VULNERABLE
file_path = os.path.join(base_dir, user_filename)
with open(file_path) as f: ...

# SECURE
real_path = os.path.realpath(os.path.join(base_dir, user_filename))
if not real_path.startswith(os.path.realpath(base_dir)):
    raise SecurityError("Path traversal attempt")
```

## NoSQL Injection

### Detection Patterns

```bash
# MongoDB query operators from user input
grep -rn "\$where\|\$gt\|\$lt\|\$ne\|\$regex\|\.find\|\.findOne" --include="*.js" --include="*.ts"

# Direct object construction from request
grep -rn "req\.body\|req\.query\|req\.params" --include="*.js" --include="*.ts" | grep -i "find\|update\|delete"
```

### Vulnerable Patterns

```javascript
// VULNERABLE: Direct use of user input
db.users.find({ username: req.body.username, password: req.body.password });
// Attack: { "username": "admin", "password": { "$ne": "" } }

// SECURE: Type checking and sanitization
const username = String(req.body.username);
const password = String(req.body.password);
```

## Code Injection (eval / exec)

### Detection Patterns

```bash
# Python: eval/exec with user input
grep -rn "eval\s*(\|exec\s*(\|compile\s*(" --include="*.py"

# JavaScript: eval, Function constructor, setTimeout/setInterval with strings
grep -rn "eval\s*(\|new\s*Function\s*(\|setTimeout\s*(\s*['\"\`]\|setInterval\s*(\s*['\"\`]" --include="*.js" --include="*.ts"

# Ruby: eval, send, public_send with user input
grep -rn "eval\s*(\|instance_eval\|class_eval\|send\s*(\|public_send\s*(" --include="*.rb"

# PHP: eval, assert, preg_replace with /e
grep -rn "eval\s*(\|assert\s*(\|preg_replace.*\/e\|create_function" --include="*.php"
```

### Vulnerable Patterns

```python
# VULNERABLE: eval with user input
result = eval(request.args.get('expr'))  # RCE

# VULNERABLE: exec with user input
exec(request.form.get('code'))

# SECURE: Use ast.literal_eval for safe data parsing
import ast
result = ast.literal_eval(user_input)  # Only parses literals
```

```javascript
// VULNERABLE: eval with user input
const result = eval(req.query.expression);

// VULNERABLE: Function constructor
const fn = new Function('return ' + userInput)();

// SECURE: Use a safe expression parser
const mathjs = require('mathjs');
const result = mathjs.evaluate(userInput);
```

## LDAP/XPath Injection

### Detection Patterns

```bash
# LDAP queries
grep -rn "ldap_search\|LdapConnection\|DirectorySearcher" --include="*.py" --include="*.java" --include="*.cs"

# XPath queries
grep -rn "xpath\|selectNodes\|evaluate" --include="*.py" --include="*.java" --include="*.js"
```

## Template Injection

See `references/ssti.md` for comprehensive Server-Side Template Injection patterns (Jinja2, ERB, Velocity, FreeMarker, Twig, Pug, EJS).

## Injection Checklist

- [ ] No string concatenation/interpolation in SQL queries
- [ ] No shell=True with user input in subprocess calls
- [ ] File paths validated against base directory (realpath check)
- [ ] No eval/exec/Function with user-controlled input
- [ ] NoSQL queries type-check input (no operator injection)
- [ ] Template rendering uses files with variables, not user-constructed strings
