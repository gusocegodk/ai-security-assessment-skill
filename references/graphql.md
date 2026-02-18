# GraphQL Security

CWE-284 (Improper Access Control), CWE-400 (Resource Exhaustion), OWASP A01:2021, A05:2021

## Table of Contents
- [Detection Patterns](#detection-patterns)
- [Introspection Exposure](#introspection-exposure)
- [Authorization Flaws](#authorization-flaws)
- [Query Complexity Attacks](#query-complexity-attacks)
- [Batching Abuse](#batching-abuse)
- [Injection via GraphQL](#injection-via-graphql)
- [Information Disclosure](#information-disclosure)

## Detection Patterns

```bash
# GraphQL endpoints and setup
grep -rn "graphql\|GraphQL\|ApolloServer\|graphene\|ariadne\|strawberry\|gqlgen\|juniper" --include="*.py" --include="*.js" --include="*.ts" --include="*.java" --include="*.go" --include="*.rs"

# Schema definitions
grep -rn "type Query\|type Mutation\|type Subscription\|@resolver\|@query\|@mutation" --include="*.py" --include="*.js" --include="*.ts" --include="*.graphql" --include="*.gql"

# Introspection configuration
grep -rn "introspection\|__schema\|__type" --include="*.py" --include="*.js" --include="*.ts" --include="*.java" --include="*.go" --include="*.graphql"

# Depth/complexity limiting
grep -rn "depthLimit\|depth_limit\|maxDepth\|max_depth\|complexity\|costAnalysis\|queryComplexity\|validationRules" --include="*.py" --include="*.js" --include="*.ts" --include="*.java"

# Batching configuration
grep -rn "allowBatchedHttpRequests\|batch\|DataLoader" --include="*.py" --include="*.js" --include="*.ts" --include="*.java"

# Authorization in resolvers
grep -rn "@auth\|@login_required\|@permission\|isAuthenticated\|hasRole\|authorize\|guard" --include="*.py" --include="*.js" --include="*.ts" --include="*.graphql"
```

## Introspection Exposure

### Vulnerable Patterns

```javascript
// VULNERABLE: Introspection enabled in production
const server = new ApolloServer({
    typeDefs,
    resolvers,
    // No introspection config = enabled by default in Apollo < 4
});

// SECURE: Disable introspection in production
const server = new ApolloServer({
    typeDefs,
    resolvers,
    introspection: process.env.NODE_ENV !== 'production',
});
```

```python
# VULNERABLE: Graphene with introspection enabled
schema = graphene.Schema(query=Query, mutation=Mutation)
# Introspection is enabled by default

# SECURE: Disable introspection in production
from graphql import validate, parse
from graphql.validation import NoSchemaIntrospectionCustomRule

validation_rules = default_rules + [NoSchemaIntrospectionCustomRule]
```

### Impact

Introspection reveals entire API schema: types, fields, mutations, enums, descriptions. Attackers use this to map the full attack surface.

## Authorization Flaws

### Vulnerable Patterns

```javascript
// VULNERABLE: No auth check in resolver
const resolvers = {
    Query: {
        user: (_, { id }) => {
            return db.users.findById(id);  // Any user can query any other user
        },
        adminDashboard: (_, args) => {
            return db.getDashboardData();  // No role check
        }
    },
    Mutation: {
        deleteUser: (_, { id }) => {
            return db.users.delete(id);  // No authorization
        }
    }
};

// SECURE: Auth check in each resolver
const resolvers = {
    Query: {
        user: (_, { id }, context) => {
            if (!context.user) throw new AuthenticationError('Not logged in');
            if (context.user.id !== id && !context.user.isAdmin) {
                throw new ForbiddenError('Not authorized');
            }
            return db.users.findById(id);
        }
    }
};
```

```python
# VULNERABLE: Graphene resolver without auth
class Query(graphene.ObjectType):
    all_users = graphene.List(UserType)

    def resolve_all_users(self, info):
        return User.objects.all()  # No permission check

# SECURE: Permission check
class Query(graphene.ObjectType):
    all_users = graphene.List(UserType)

    @login_required
    @permission_required('view_users')
    def resolve_all_users(self, info):
        return User.objects.all()
```

### Nested Object Authorization

```javascript
// VULNERABLE: Parent authorized, but nested field leaks data
const resolvers = {
    Query: {
        me: (_, __, context) => context.user  // Auth check here
    },
    User: {
        // No auth check on field resolver - any user's orders accessible via nested query
        orders: (parent) => db.orders.findByUserId(parent.id),
        creditCard: (parent) => db.cards.findByUserId(parent.id)  // PII leak
    }
};
```

## Query Complexity Attacks

### Vulnerable Patterns

```javascript
// VULNERABLE: No depth or complexity limiting
const server = new ApolloServer({
    typeDefs,
    resolvers
    // Missing: validationRules, maxDepth, maxComplexity
});
```

### Attack Example

```graphql
# Deeply nested query causing exponential DB load
query {
    users {
        friends {
            friends {
                friends {
                    friends {
                        name
                        email
                    }
                }
            }
        }
    }
}

# Field duplication / aliasing attack
query {
    a: user(id: "1") { name }
    b: user(id: "2") { name }
    c: user(id: "3") { name }
    # ... hundreds of aliases
}
```

### Secure Patterns

```javascript
// SECURE: Apollo with depth limiting and complexity analysis
import depthLimit from 'graphql-depth-limit';
import { createComplexityLimitRule } from 'graphql-validation-complexity';

const server = new ApolloServer({
    typeDefs,
    resolvers,
    validationRules: [
        depthLimit(5),
        createComplexityLimitRule(1000)
    ]
});
```

```python
# SECURE: Graphene with query depth limiting
from graphene_django.views import GraphQLView
from graphql.validation import ASTValidationRule

class DepthAnalysisRule(ASTValidationRule):
    max_depth = 5
    # Custom implementation to enforce depth
```

## Batching Abuse

### Vulnerable Patterns

```javascript
// VULNERABLE: Batching enabled without rate limiting
const server = new ApolloServer({
    typeDefs,
    resolvers,
    allowBatchedHttpRequests: true  // Can send 1000 queries in one request
});
```

### Attack Example

```json
// Brute-force login via batched mutations
[
    {"query": "mutation { login(email: \"admin@test.com\", password: \"pass1\") { token } }"},
    {"query": "mutation { login(email: \"admin@test.com\", password: \"pass2\") { token } }"},
    {"query": "mutation { login(email: \"admin@test.com\", password: \"pass3\") { token } }"}
]
```

### Secure Patterns

```javascript
// SECURE: Disable batching or limit batch size
const server = new ApolloServer({
    allowBatchedHttpRequests: false
});

// Or limit batch size with middleware
app.use('/graphql', (req, res, next) => {
    if (Array.isArray(req.body) && req.body.length > 5) {
        return res.status(400).json({ error: 'Batch limit exceeded' });
    }
    next();
});
```

## Injection via GraphQL

### Vulnerable Patterns

```javascript
// VULNERABLE: GraphQL argument passed directly to SQL
const resolvers = {
    Query: {
        search: (_, { term }) => {
            return db.query(`SELECT * FROM products WHERE name LIKE '%${term}%'`);  // SQLi
        }
    }
};

// VULNERABLE: Argument passed to OS command
const resolvers = {
    Mutation: {
        exportData: (_, { format }) => {
            exec(`convert --format ${format} data.json`);  // Command injection
        }
    }
};

// SECURE: Parameterized query
const resolvers = {
    Query: {
        search: (_, { term }) => {
            return db.query('SELECT * FROM products WHERE name LIKE ?', [`%${term}%`]);
        }
    }
};
```

## Information Disclosure

### Detection Patterns

```bash
# Error verbosity configuration
grep -rn "debug\|formatError\|includeStacktrace\|stacktrace" --include="*.py" --include="*.js" --include="*.ts" | grep -i "graphql\|apollo\|server"

# Suggestion messages (field name guessing)
grep -rn "didYouMean\|suggestions" --include="*.py" --include="*.js" --include="*.ts"
```

### Vulnerable Patterns

```javascript
// VULNERABLE: Stack traces in production errors
const server = new ApolloServer({
    includeStacktraceInErrorResponses: true  // Apollo 4
});

// SECURE: Custom error formatting
const server = new ApolloServer({
    includeStacktraceInErrorResponses: false,
    formatError: (error) => ({
        message: error.message,
        code: error.extensions?.code
    })
});
```

## GraphQL Security Checklist

- [ ] Introspection disabled in production
- [ ] Query depth limiting enforced
- [ ] Query complexity/cost analysis enabled
- [ ] Authorization checked in every resolver (not just top-level)
- [ ] Nested object authorization verified (field-level permissions)
- [ ] Batching disabled or limited with rate limiting
- [ ] Input arguments validated and sanitized (no SQL/command injection)
- [ ] Error messages don't leak schema or stack traces
- [ ] Field suggestions disabled in production
- [ ] Persisted queries used for known operations where possible
- [ ] Rate limiting applied per query/mutation type
