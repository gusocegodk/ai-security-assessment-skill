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

## LDAP/XPath Injection

### Detection Patterns

```bash
# LDAP queries
grep -rn "ldap_search\|LdapConnection\|DirectorySearcher" --include="*.py" --include="*.java" --include="*.cs"

# XPath queries
grep -rn "xpath\|selectNodes\|evaluate" --include="*.py" --include="*.java" --include="*.js"
```
