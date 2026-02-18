---
name: security-assessment
description: >
  Comprehensive AI-powered security audit for analyzing codebases and identifying vulnerabilities.
  Follows OWASP Top 10 (2021), CWE Top 25, and SANS Top 25 standards.

  Use this skill when: (1) user requests security audit/assessment/review of code,
  (2) user asks to find vulnerabilities in a codebase, (3) user mentions "/security-assessment",
  (4) user wants penetration testing analysis of source code, (5) user asks about security
  issues in their project, (6) user requests compliance checking (GDPR, PCI-DSS, SOC 2).

  Supports all major languages: JavaScript/TypeScript/Node.js, Python, Java, Go, Ruby, PHP, C#, etc.
metadata:
  version: "2.0.0"
---

# Security Assessment Skill

Conduct thorough security assessments of codebases, generating detailed vulnerability reports with remediation guidance.

## Workflow Overview

1. **Scope determination** - Identify target path and languages
2. **Discovery** - Enumerate files and detect technology stack
3. **Analysis** - Scan all 18 security domains (see references/)
4. **Reporting** - Generate `ai-security-assessment-report.md`

## Quick Start

```bash
# Analyze entire project
/security-assessment

# Analyze specific directory
/security-assessment src/

# Focus on authentication module
/security-assessment src/auth
```

## Analysis Process

### Step 1: Scope & Discovery

Determine target path (default: entire project). Detect:
- Languages and frameworks present
- Package managers (package.json, requirements.txt, go.mod, etc.)
- Configuration files
- Entry points and sensitive areas (auth, payments, admin)

### Step 2: Systematic Analysis

Analyze each security domain using patterns in `references/`. For each domain:
1. Use grep/find to locate relevant patterns
2. Examine context around matches
3. Assess exploitability and impact
4. Document findings with file:line references

**Security Domains** (load relevant reference as needed):

*Injection & Input Handling:*
- `references/injection.md` - SQL, Command, Path Traversal, NoSQL, LDAP, XPath, Code Injection (eval/exec)
- `references/xss.md` - DOM-based, Reflected, Stored XSS
- `references/ssti.md` - Server-Side Template Injection (Jinja2, ERB, Velocity, FreeMarker, Twig, Pug)
- `references/xxe.md` - XML external entity injection
- `references/deserialization.md` - Insecure deserialization (Pickle, ObjectInputStream, unserialize, Marshal)

*Authentication & Access:*
- `references/auth-session.md` - Authentication, password handling, session management, OAuth/OIDC
- `references/access-control.md` - Authorization, IDOR, privilege escalation
- `references/csrf.md` - CSRF tokens, SameSite cookies
- `references/open-redirect.md` - URL redirection, login flow redirect validation

*Configuration & Infrastructure:*
- `references/config.md` - Security misconfiguration, debug mode, CORS, headers, Docker, Kubernetes, Terraform
- `references/data-exposure.md` - Hardcoded secrets, sensitive data logging, PII, .env exposure, git history
- `references/crypto.md` - Weak algorithms, key management, randomness

*Application Logic:*
- `references/ssrf.md` - Server-side request forgery
- `references/graphql.md` - Introspection, authorization, query complexity, batching abuse
- `references/race-conditions.md` - TOCTOU, async race conditions, database locking, Go concurrency
- `references/dos.md` - Rate limiting, ReDoS, resource exhaustion
- `references/dependencies.md` - Outdated packages, known CVEs

*Security Baseline:*
- `references/positive-security.md` - Missing security controls (headers, rate limiting, validation, logging, error handling)

### Step 3: Generate Report

Create `ai-security-assessment-report.md` using template in `references/report-template.md`.

## Severity Classification

| Level | Definition | Response |
|-------|------------|----------|
| **Critical** | Actively exploitable, immediate compromise possible | Fix immediately |
| **High** | Significant risk, likely exploitable | Fix within days |
| **Medium** | Moderate risk, requires specific conditions | Fix within sprint |
| **Low** | Minor risk, defense-in-depth improvement | Address in backlog |

## Output Location

Save report to: `ai-security-assessment-report.md` in the project root or specified output path.

## Notes

- Large codebases may take several minutes
- Findings should be validated manually before remediation
- The report includes a risk score (0-100) and security baseline status table
- Positive security checks flag missing controls (not just vulnerable code)
