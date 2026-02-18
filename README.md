# AI Security Assessment Skill

Comprehensive AI-powered security audit skill for [Claude Code](https://docs.anthropic.com/en/docs/claude-code) that analyzes codebases and identifies vulnerabilities following industry standards.

## Overview

This skill performs automated security assessments of codebases, scanning 18 security domains and generating detailed reports with remediation guidance. It follows **OWASP Top 10 (2021)**, **CWE Top 25**, and **SANS Top 25** standards.

## Supported Languages

JavaScript/TypeScript, Python, Java, Go, Ruby, PHP, C#, and more.

## Security Domains

| Domain | Examples |
|---|---|
| Injection | SQL, Command, Path Traversal, NoSQL, LDAP, Code Injection (eval/exec) |
| XSS | DOM-based, Reflected, Stored |
| Template Injection (SSTI) | Jinja2, ERB, Velocity, FreeMarker, Twig, Pug, EJS |
| Deserialization | Pickle, ObjectInputStream, unserialize, Marshal, node-serialize |
| Authentication & Session | Password handling, session management, OAuth/OIDC |
| Access Control | Authorization, IDOR, privilege escalation |
| CSRF | Token validation, SameSite cookies |
| Open Redirect | URL redirection, login flow redirects, bypass techniques |
| Configuration | Debug mode, CORS, security headers, Docker, Kubernetes, Terraform |
| Data Exposure | Hardcoded secrets, PII leakage, .env files, git history |
| Cryptography | Weak algorithms, key management, randomness |
| SSRF | Server-side request forgery |
| XXE | XML external entity injection |
| GraphQL | Introspection, authorization, query complexity, batching |
| Race Conditions | TOCTOU, async/await, database locking, Go concurrency |
| DoS | Rate limiting, ReDoS, resource exhaustion |
| Dependencies | Outdated packages, known CVEs |
| Positive Security | Missing controls: CSP, rate limiting, input validation, logging |

## Usage

Invoke within Claude Code:

```
/security-assessment
```

Or ask naturally:

- "Run a security audit on this project"
- "Find vulnerabilities in this codebase"
- "Check this code for security issues"

## Workflow

1. **Scope** - Identifies target path and languages
2. **Discovery** - Enumerates files and detects technology stack
3. **Analysis** - Scans all 18 security domains using reference patterns
4. **Report** - Generates `ai-security-assessment-report.md` with categorized findings

## Severity Levels

- **Critical** - Actively exploitable, immediate compromise possible
- **High** - Significant risk, likely exploitable
- **Medium** - Moderate risk, requires specific conditions
- **Low** - Minor risk, defense-in-depth improvement

## Output

Generates a structured markdown report including:

- Risk score (0-100) with rating
- Security baseline status table (missing controls)
- Executive summary with severity breakdown
- Technology stack detection
- Categorized findings with CWE/OWASP mappings
- Remediation guidance for each finding
- Compliance considerations (GDPR, PCI-DSS, SOC 2)

## Installation

Copy the `security-assessment` directory to your Claude Code skills folder:

```
~/.claude/skills/security-assessment/
```

## License

MIT
