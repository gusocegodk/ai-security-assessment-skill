# Security Misconfiguration

CWE-16 (Configuration), OWASP A05:2021

## Table of Contents
- [Debug Mode](#debug-mode)
- [CORS Misconfiguration](#cors-misconfiguration)
- [Security Headers](#security-headers)
- [Default Credentials](#default-credentials)
- [Verbose Errors](#verbose-errors)
- [Directory Listing](#directory-listing)

## Debug Mode

### Detection Patterns

```bash
# Debug mode enabled
grep -rn "DEBUG\s*=\s*True\|debug:\s*true\|NODE_ENV.*development" --include="*.py" --include="*.js" --include="*.json" --include="*.yml" --include="*.yaml" --include="*.env"

# Flask/Django debug
grep -rn "app\.debug\|DEBUG\s*=" --include="*.py" --include="settings.py"

# Development servers in production
grep -rn "app\.run\|flask run\|runserver" --include="*.py" --include="Procfile" --include="Dockerfile"
```

### Vulnerable Patterns

```python
# VULNERABLE: Debug enabled in production
app.run(debug=True)  # Exposes debugger
DEBUG = True  # Django shows stack traces

# SECURE: Environment-based
DEBUG = os.environ.get('DEBUG', 'False').lower() == 'true'
```

## CORS Misconfiguration

### Detection Patterns

```bash
# CORS configuration
grep -rn "Access-Control-Allow-Origin\|cors\|CORS" --include="*.py" --include="*.js" --include="*.java" --include="*.config"

# Wildcard or reflected origin
grep -rn "'\*'\|\"\\*\"\|origin\s*:" --include="*.py" --include="*.js" | grep -i "cors\|allow-origin"
```

### Vulnerable Patterns

```javascript
// VULNERABLE: Wildcard with credentials
app.use(cors({
    origin: '*',
    credentials: true  // DANGEROUS COMBINATION
}));

// VULNERABLE: Reflecting any origin
app.use(cors({
    origin: req.headers.origin,  // Reflects attacker domain
    credentials: true
}));

// SECURE: Whitelist specific origins
const allowedOrigins = ['https://app.example.com', 'https://admin.example.com'];
app.use(cors({
    origin: (origin, callback) => {
        if (!origin || allowedOrigins.includes(origin)) {
            callback(null, true);
        } else {
            callback(new Error('Not allowed'));
        }
    },
    credentials: true
}));
```

## Security Headers

### Detection Patterns

```bash
# Security header configuration
grep -rn "X-Frame-Options\|Content-Security-Policy\|X-Content-Type-Options\|Strict-Transport-Security\|X-XSS-Protection\|helmet\|SecurityHeaders" --include="*.py" --include="*.js" --include="*.java" --include="*.config"
```

### Required Headers Checklist

| Header | Value | Purpose |
|--------|-------|---------|
| X-Frame-Options | DENY or SAMEORIGIN | Clickjacking protection |
| X-Content-Type-Options | nosniff | MIME sniffing prevention |
| Strict-Transport-Security | max-age=31536000; includeSubDomains | Force HTTPS |
| Content-Security-Policy | default-src 'self' | XSS mitigation |
| X-XSS-Protection | 0 | Disable buggy browser filter |
| Referrer-Policy | strict-origin-when-cross-origin | Control referrer leakage |
| Permissions-Policy | geolocation=(), camera=() | Restrict browser features |

### Implementation Example

```javascript
// Express with helmet
const helmet = require('helmet');
app.use(helmet());

// Or manually:
app.use((req, res, next) => {
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('Content-Security-Policy', "default-src 'self'");
    res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
    next();
});
```

## Default Credentials

### Detection Patterns

```bash
# Common default credentials
grep -rn "admin:admin\|root:root\|password123\|default.*password\|changeme" --include="*.py" --include="*.js" --include="*.yml" --include="*.json" --include="*.env"

# Database default configs
grep -rn "localhost:5432\|localhost:3306\|localhost:27017" --include="*.py" --include="*.js" --include="*.yml"
```

## Verbose Errors

### Detection Patterns

```bash
# Stack trace exposure
grep -rn "traceback\|stack.*trace\|print_exc\|e\.message\|err\.stack" --include="*.py" --include="*.js" --include="*.java"

# Detailed error responses
grep -rn "500.*error\|InternalServerError\|Exception" --include="*.py" --include="*.js"
```

### Vulnerable Patterns

```python
# VULNERABLE: Exposes internals
@app.errorhandler(500)
def error_handler(e):
    return str(e), 500  # Shows stack trace

# SECURE: Generic error
@app.errorhandler(500)
def error_handler(e):
    app.logger.error(f"Internal error: {e}")  # Log internally
    return {"error": "Internal server error"}, 500  # Generic response
```

## Directory Listing

### Detection Patterns

```bash
# Static file serving without index
grep -rn "static\|serve_static\|express\.static\|sendFile" --include="*.py" --include="*.js"

# Apache/Nginx config
grep -rn "Options.*Indexes\|autoindex\s*on" --include="*.conf" --include=".htaccess"
```

## Container Security (Docker)

### Detection Patterns

```bash
# Dockerfile security issues
grep -rn "FROM.*latest\|FROM.*:latest" --include="Dockerfile*"

# Running as root
grep -rn "USER\s" --include="Dockerfile*"

# Secrets in build args or env
grep -rn "ARG.*password\|ARG.*secret\|ARG.*key\|ARG.*token\|ENV.*password\|ENV.*secret\|ENV.*key\|ENV.*token" --include="Dockerfile*" --include="docker-compose*.yml" --include="docker-compose*.yaml"

# Privileged mode in docker-compose
grep -rn "privileged:\s*true\|cap_add\|security_opt.*no-new-privileges" --include="docker-compose*.yml" --include="docker-compose*.yaml"

# Exposed ports
grep -rn "EXPOSE\|ports:" --include="Dockerfile*" --include="docker-compose*.yml"
```

### Vulnerable Patterns

```dockerfile
# VULNERABLE: Running as root (default)
FROM node:latest
COPY . /app
RUN npm install
CMD ["node", "app.js"]

# SECURE: Non-root user, pinned version, multi-stage
FROM node:20-alpine AS builder
WORKDIR /app
COPY package*.json ./
RUN npm ci --only=production

FROM node:20-alpine
RUN addgroup -S appgroup && adduser -S appuser -G appgroup
USER appuser
WORKDIR /app
COPY --from=builder /app/node_modules ./node_modules
COPY . .
CMD ["node", "app.js"]
```

### Docker Security Checklist

- [ ] Base image uses specific version tag (not `latest`)
- [ ] Non-root USER specified
- [ ] No secrets in ENV or ARG instructions
- [ ] Multi-stage build used (minimal final image)
- [ ] No privileged mode in docker-compose
- [ ] Health check defined
- [ ] Read-only filesystem where possible

## Kubernetes Security

### Detection Patterns

```bash
# K8s manifests
grep -rn "securityContext\|runAsNonRoot\|readOnlyRootFilesystem\|allowPrivilegeEscalation\|capabilities" --include="*.yml" --include="*.yaml" | grep -v node_modules

# Privileged containers
grep -rn "privileged:\s*true" --include="*.yml" --include="*.yaml"

# Missing resource limits
grep -rn "resources:\|limits:\|requests:" --include="*.yml" --include="*.yaml" | grep -v node_modules

# Secrets in plain text manifests
grep -rn "kind:\s*Secret" --include="*.yml" --include="*.yaml" -A 10 | grep "stringData\|data:"

# Host network/PID/IPC
grep -rn "hostNetwork:\s*true\|hostPID:\s*true\|hostIPC:\s*true" --include="*.yml" --include="*.yaml"
```

### Vulnerable Patterns

```yaml
# VULNERABLE: Overly permissive pod spec
apiVersion: v1
kind: Pod
spec:
  containers:
  - name: app
    image: app:latest
    securityContext:
      privileged: true          # Full host access
      runAsUser: 0              # Running as root
    # No resource limits = DoS risk

# SECURE: Hardened pod spec
apiVersion: v1
kind: Pod
spec:
  securityContext:
    runAsNonRoot: true
    runAsUser: 1000
  containers:
  - name: app
    image: app:1.2.3
    securityContext:
      allowPrivilegeEscalation: false
      readOnlyRootFilesystem: true
      capabilities:
        drop: ["ALL"]
    resources:
      limits:
        memory: "128Mi"
        cpu: "500m"
```

## Infrastructure as Code (Terraform)

### Detection Patterns

```bash
# Public access misconfigurations
grep -rn "publicly_accessible\s*=\s*true\|acl\s*=\s*\"public" --include="*.tf"

# Security groups with open ingress
grep -rn 'cidr_blocks.*"0\.0\.0\.0/0"\|cidr_blocks.*"::/0"' --include="*.tf"

# Unencrypted storage
grep -rn "encrypted\s*=\s*false\|storage_encrypted\s*=\s*false" --include="*.tf"

# Missing logging
grep -rn "logging\|access_logs\|enable_logging" --include="*.tf"

# Hardcoded credentials in Terraform
grep -rn "password\s*=\s*\"\|secret_key\s*=\s*\"\|access_key\s*=\s*\"" --include="*.tf" --include="*.tfvars"
```

### Vulnerable Patterns

```hcl
# VULNERABLE: Public S3 bucket
resource "aws_s3_bucket" "data" {
  bucket = "my-data-bucket"
  acl    = "public-read"  # Publicly accessible
}

# VULNERABLE: Open security group
resource "aws_security_group_rule" "ssh" {
  type        = "ingress"
  from_port   = 22
  to_port     = 22
  cidr_blocks = ["0.0.0.0/0"]  # SSH open to world
}

# SECURE: Restricted access
resource "aws_security_group_rule" "ssh" {
  type        = "ingress"
  from_port   = 22
  to_port     = 22
  cidr_blocks = ["10.0.0.0/8"]  # Internal only
}
```

## Configuration Checklist

- [ ] Debug mode disabled in production
- [ ] CORS properly restricted
- [ ] Security headers configured
- [ ] Default credentials changed
- [ ] Error messages are generic
- [ ] Directory listing disabled
- [ ] Admin interfaces restricted
- [ ] Unnecessary features disabled
- [ ] TLS 1.2+ enforced
- [ ] HTTP methods restricted (no TRACE)
- [ ] Docker containers run as non-root
- [ ] Docker images use pinned versions
- [ ] No secrets in Dockerfiles or docker-compose
- [ ] Kubernetes pods have security contexts
- [ ] Terraform resources not publicly accessible
- [ ] Security groups restrict ingress appropriately
