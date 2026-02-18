# Dependency Vulnerabilities

CWE-1104 (Unmaintained Components), OWASP A06:2021

## Detection Patterns

### Package Files to Locate

```bash
# Find dependency manifests
find . -name "package.json" -o -name "package-lock.json" -o -name "yarn.lock"
find . -name "requirements.txt" -o -name "Pipfile" -o -name "Pipfile.lock" -o -name "poetry.lock"
find . -name "pom.xml" -o -name "build.gradle" -o -name "build.gradle.kts"
find . -name "go.mod" -o -name "go.sum"
find . -name "Gemfile" -o -name "Gemfile.lock"
find . -name "composer.json" -o -name "composer.lock"
find . -name "Cargo.toml" -o -name "Cargo.lock"
```

## Vulnerability Scanning Commands

### Node.js/npm

```bash
# Built-in npm audit
npm audit
npm audit --json

# Check for outdated packages
npm outdated
```

### Python

```bash
# pip-audit (install: pip install pip-audit)
pip-audit
pip-audit -r requirements.txt

# Safety (install: pip install safety)
safety check -r requirements.txt
```

### Java (Maven)

```bash
# OWASP Dependency-Check plugin
mvn org.owasp:dependency-check-maven:check
```

### Go

```bash
# govulncheck (install: go install golang.org/x/vuln/cmd/govulncheck@latest)
govulncheck ./...
```

### Ruby

```bash
# bundler-audit (install: gem install bundler-audit)
bundle-audit check --update
```

### PHP

```bash
# Composer security check
composer audit
```

## Manual Version Analysis

When tools aren't available, manually check critical packages:

### High-Risk Dependencies

| Category | Packages to Check |
|----------|-------------------|
| Web frameworks | express, django, flask, rails, spring |
| Auth libraries | passport, django-auth, spring-security |
| Crypto | openssl, cryptography, bcrypt |
| Database drivers | pg, mysql2, pymysql, jdbc |
| XML/JSON parsers | lxml, xml2js, jackson |
| Template engines | jinja2, ejs, handlebars, pug |

### Check for Known Vulnerable Versions

```bash
# Extract versions from package.json
cat package.json | grep -E '"(name|version)"'

# Extract from requirements.txt
cat requirements.txt | grep -E "^[a-zA-Z]"

# Extract from pom.xml
grep -E "<version>|<artifactId>" pom.xml
```

## Remediation Guidance

### Automated Fixes

```bash
# npm
npm audit fix
npm audit fix --force  # Breaking changes

# pip (manual upgrade)
pip install --upgrade package_name

# bundler
bundle update --conservative vulnerable_gem
```

### Pinning Strategies

```javascript
// package.json - Exact versions for production
{
  "dependencies": {
    "express": "4.18.2",  // Exact, not "^4.18.2"
  }
}
```

```python
# requirements.txt - Pin all versions
django==4.2.7
requests==2.31.0
```

## Dependency Checklist

- [ ] Automated scanning in CI/CD pipeline
- [ ] No high/critical vulnerabilities in production
- [ ] Dependencies updated within last 6 months
- [ ] Lock files committed to version control
- [ ] No deprecated packages
- [ ] No packages with no maintainer
- [ ] License compliance checked
- [ ] Transitive dependencies analyzed
