# Security Assessment Report Template

Use this template for generating `ai-security-assessment-report.md`.

## Report Structure

```markdown
# Security Assessment Report

**Project:** [Project Name]  
**Date:** [Assessment Date]  
**Scope:** [Target path/directories]  
**Assessor:** AI Security Assessment Tool

---

## Executive Summary

**Overall Risk Level:** [Critical/High/Medium/Low]

### Risk Score: [X/100]

Calculate based on: `100 - (Critical × 25) - (High × 10) - (Medium × 3) - (Low × 1)`, clamped to 0-100.

| Score Range | Rating | Meaning |
|-------------|--------|---------|
| 90-100 | Excellent | Minimal risk, strong security posture |
| 70-89 | Good | Minor issues, generally well-secured |
| 40-69 | Moderate | Notable vulnerabilities requiring attention |
| 20-39 | Poor | Significant vulnerabilities, high risk |
| 0-19 | Critical | Severe vulnerabilities, immediate action required |

### Findings Summary

| Severity | Count | Status |
|----------|-------|--------|
| Critical | X | ⬜ Requires immediate action |
| High | X | ⬜ Fix within days |
| Medium | X | ⬜ Fix within sprint |
| Low | X | ⬜ Address in backlog |
| **Total** | **X** | |

### Security Baseline Status

| Control | Present | Note |
|---------|---------|------|
| Input validation | Yes/No | [Library or concern] |
| Rate limiting (auth) | Yes/No | [Details] |
| Security headers (CSP, HSTS) | Yes/No | [Details] |
| Dependency scanning | Yes/No | [CI/CD integration] |
| Error handling | Yes/No | [Global handler?] |
| Secret management | Yes/No | [Env vars / Vault?] |
| Logging & monitoring | Yes/No | [Framework?] |

[2-3 sentence summary of key findings and overall security posture]

---

## Technology Stack Detected

- **Languages:** [e.g., Python, JavaScript/TypeScript]
- **Frameworks:** [e.g., Django, Express, React]
- **Package Managers:** [e.g., npm, pip]
- **Databases:** [if detectable]

---

## Critical Findings

### [FINDING-001] [Finding Title]

**Severity:** Critical  
**Category:** [e.g., SQL Injection]  
**CWE:** CWE-XXX  
**OWASP:** [e.g., A03:2021 Injection]

**Location:**
- `path/to/file.py:42`
- `path/to/file.py:67`

**Description:**
[Clear explanation of the vulnerability]

**Vulnerable Code:**
```python
# Example of vulnerable code
cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")
```

**Proof of Concept:**
[Example attack payload or exploitation scenario]

**Impact:**
[What an attacker could achieve - data breach, RCE, etc.]

**Remediation:**
```python
# Secure code example
cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
```

**References:**
- [Relevant documentation/OWASP link]

---

## High Findings

[Same structure as Critical Findings]

---

## Medium Findings

[Same structure as Critical Findings]

---

## Low Findings

[Same structure as Critical Findings]

---

## Compliance Considerations

### GDPR
- [ ] [Relevant finding]

### PCI-DSS
- [ ] [Relevant finding]

### SOC 2
- [ ] [Relevant finding]

---

## Recommended Security Tools

Based on the technology stack, consider integrating:

| Tool | Purpose | Integration Point |
|------|---------|-------------------|
| [Tool name] | [Purpose] | [CI/CD/IDE] |

---

## Remediation Roadmap

### Immediate (0-7 days)
1. [Critical finding remediation]

### Short-term (1-4 weeks)
1. [High finding remediation]

### Medium-term (1-3 months)
1. [Medium findings and hardening]

### Long-term
1. [Security process improvements]

---

## Appendix

### A. Files Analyzed
[List of files/directories scanned]

### B. Out of Scope
[Items not analyzed and why]

### C. Methodology
This assessment followed OWASP Top 10 (2021), CWE Top 25, and SANS Top 25 standards.
```

## Severity Definitions (for reference)

| Severity | CVSS Range | Definition |
|----------|------------|------------|
| Critical | 9.0-10.0 | Actively exploitable, leads to immediate system compromise |
| High | 7.0-8.9 | Significant risk, likely exploitable with moderate effort |
| Medium | 4.0-6.9 | Moderate risk, requires specific conditions to exploit |
| Low | 0.1-3.9 | Minor risk, defense-in-depth improvement |

## Finding ID Convention

- Format: `[SEVERITY_INITIAL]-[SEQ]`
- Examples: `CRIT-001`, `HIGH-002`, `MED-003`, `LOW-004`

## Category Mappings

| Category | CWE | OWASP 2021 |
|----------|-----|------------|
| SQL Injection | CWE-89 | A03:2021 |
| Command Injection | CWE-78 | A03:2021 |
| Code Injection (eval/exec) | CWE-94 | A03:2021 |
| Template Injection (SSTI) | CWE-1336 | A03:2021 |
| XSS | CWE-79 | A03:2021 |
| Path Traversal | CWE-22 | A01:2021 |
| Broken Auth | CWE-287 | A07:2021 |
| OAuth/OIDC Flaws | CWE-287 | A07:2021 |
| IDOR | CWE-639 | A01:2021 |
| CSRF | CWE-352 | A01:2021 |
| Security Misconfig | CWE-16 | A05:2021 |
| Container Misconfig | CWE-16 | A05:2021 |
| Sensitive Data Exposure | CWE-200 | A02:2021 |
| Weak Crypto | CWE-327 | A02:2021 |
| SSRF | CWE-918 | A10:2021 |
| XXE | CWE-611 | A05:2021 |
| Open Redirect | CWE-601 | A01:2021 |
| Insecure Deserialization | CWE-502 | A08:2021 |
| GraphQL Security | CWE-284 | A01:2021 |
| Race Condition | CWE-362 | A04:2021 |
| DoS/ReDoS | CWE-400 | A05:2021 |
| Vulnerable Dependencies | CWE-1104 | A06:2021 |
| Missing Security Controls | CWE-693 | A05:2021 |
