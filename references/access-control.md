# Authorization & Access Control

CWE-862 (Missing Authorization), CWE-639 (IDOR), OWASP A01:2021

## Table of Contents
- [Insecure Direct Object References (IDOR)](#insecure-direct-object-references-idor)
- [Missing Function-Level Access Control](#missing-function-level-access-control)
- [Privilege Escalation](#privilege-escalation)
- [Path-Based Access Control](#path-based-access-control)

## Insecure Direct Object References (IDOR)

### Detection Patterns

```bash
# Direct ID usage in routes/endpoints
grep -rn "/:id\|/<id>\|/\d+\|params\['id'\]\|params\[:id\]\|req\.params\.id" --include="*.py" --include="*.js" --include="*.rb" --include="*.java"

# Database queries using user-supplied IDs
grep -rn "findById\|get_object_or_404\|find_by_id\|WHERE.*id\s*=" --include="*.py" --include="*.js" --include="*.rb" --include="*.java"

# File access with user-supplied names
grep -rn "download\|attachment\|file.*=\|document.*=" --include="*.py" --include="*.js"
```

### Vulnerable Patterns

```python
# VULNERABLE: No ownership check
@app.route('/api/documents/<doc_id>')
def get_document(doc_id):
    return Document.query.get(doc_id).to_json()

# SECURE: Verify ownership
@app.route('/api/documents/<doc_id>')
@login_required
def get_document(doc_id):
    doc = Document.query.get(doc_id)
    if doc.owner_id != current_user.id:
        abort(403)
    return doc.to_json()
```

```javascript
// VULNERABLE: Direct ID access
app.get('/api/users/:id/profile', (req, res) => {
    const user = await User.findById(req.params.id);
    res.json(user);
});

// SECURE: Verify authorization
app.get('/api/users/:id/profile', authenticate, (req, res) => {
    if (req.params.id !== req.user.id && !req.user.isAdmin) {
        return res.status(403).json({ error: 'Forbidden' });
    }
    const user = await User.findById(req.params.id);
    res.json(user);
});
```

### Common IDOR Locations

1. User profile endpoints (`/users/{id}`)
2. Document/file downloads (`/files/{id}`)
3. Order/invoice access (`/orders/{id}`)
4. API endpoints with numeric IDs
5. Export/report generation
6. Admin functions accessible via ID manipulation

## Missing Function-Level Access Control

### Detection Patterns

```bash
# Admin/privileged routes without auth checks
grep -rn "admin\|manage\|delete\|update\|create" --include="*.py" --include="*.js" --include="*.rb" -l | xargs grep -L "@login_required\|@admin_required\|authenticate\|authorize"

# Routes without middleware
grep -rn "app\.get\|app\.post\|app\.put\|app\.delete\|@app\.route" --include="*.py" --include="*.js"

# GraphQL resolvers without auth
grep -rn "resolver\|Query\|Mutation" --include="*.js" --include="*.ts" --include="*.py"
```

### Vulnerable Patterns

```python
# VULNERABLE: No role check
@app.route('/admin/users/delete/<user_id>', methods=['POST'])
def delete_user(user_id):
    User.query.filter_by(id=user_id).delete()
    return {'status': 'deleted'}

# SECURE: Role verification
@app.route('/admin/users/delete/<user_id>', methods=['POST'])
@login_required
@admin_required
def delete_user(user_id):
    User.query.filter_by(id=user_id).delete()
    return {'status': 'deleted'}
```

## Privilege Escalation

### Detection Patterns

```bash
# Role assignment without validation
grep -rn "role\s*=\|isAdmin\s*=\|is_admin\s*=\|privileges\s*=\|permissions\s*=" --include="*.py" --include="*.js" --include="*.java"

# User-controllable privilege fields
grep -rn "req\.body\.role\|request\.json\['role'\]\|params\[:role\]" --include="*.py" --include="*.js" --include="*.rb"

# Mass assignment vulnerabilities
grep -rn "update_attributes\|update\(req\.body\)\|Object\.assign\|\.merge\(" --include="*.rb" --include="*.js" --include="*.py"
```

### Vulnerable Patterns

```javascript
// VULNERABLE: Mass assignment allows role change
app.put('/api/users/:id', (req, res) => {
    await User.findByIdAndUpdate(req.params.id, req.body);
});
// Attack: PUT /api/users/123 { "role": "admin" }

// SECURE: Whitelist allowed fields
app.put('/api/users/:id', (req, res) => {
    const { name, email } = req.body;  // Only allowed fields
    await User.findByIdAndUpdate(req.params.id, { name, email });
});
```

```python
# VULNERABLE: User can set own role
user.role = request.json.get('role', 'user')

# SECURE: Ignore role from user input
allowed_fields = ['name', 'email', 'bio']
for field in allowed_fields:
    if field in request.json:
        setattr(user, field, request.json[field])
```

## Path-Based Access Control

### Detection Patterns

```bash
# URL-based auth (weak)
grep -rn "if.*url.*admin\|if.*path.*admin\|startswith.*admin" --include="*.py" --include="*.js"

# Client-side route guards (insufficient)
grep -rn "PrivateRoute\|AuthGuard\|canActivate" --include="*.jsx" --include="*.tsx" --include="*.ts"
```

### Vulnerable Patterns

```python
# VULNERABLE: Path-based check only
if not request.path.startswith('/admin'):
    return  # Allow access
# Attack: Access /Admin or /admin/../admin or URL encoding

# SECURE: Role-based middleware
@app.before_request
def check_admin():
    if request.path.startswith('/admin'):
        if not current_user.is_authenticated or not current_user.is_admin:
            abort(403)
```

### Authorization Checklist

- [ ] All endpoints have authorization checks
- [ ] Ownership verified for resource access
- [ ] Role checks at server level (not just client)
- [ ] No mass assignment of sensitive fields
- [ ] Admin functions protected
- [ ] API keys/tokens properly scoped
- [ ] GraphQL queries/mutations authorized
