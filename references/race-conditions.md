# Race Conditions

CWE-362 (Race Condition), CWE-367 (TOCTOU)

## Detection Patterns

```bash
# Check-then-act patterns
grep -rn "if.*exists\|if.*os\.path\|if.*File\." --include="*.py" --include="*.java" --include="*.js" | grep -A5 "open\|write\|delete\|create"

# Balance/inventory checks before operations
grep -rn "balance\|inventory\|stock\|quantity\|available" --include="*.py" --include="*.js" --include="*.java" | grep -i "if\|check"

# Non-atomic operations
grep -rn "get.*save\|find.*update\|select.*update" --include="*.py" --include="*.js" --include="*.java"

# Missing locks/transactions
grep -rn "BEGIN\|TRANSACTION\|lock\|mutex\|synchronized" --include="*.py" --include="*.js" --include="*.java" --include="*.sql"
```

## Common Vulnerable Patterns

### Time-of-Check to Time-of-Use (TOCTOU)

```python
# VULNERABLE: File TOCTOU
if os.path.exists(filename):
    # Window for race condition
    with open(filename) as f:
        data = f.read()

# SECURE: Handle exception
try:
    with open(filename) as f:
        data = f.read()
except FileNotFoundError:
    handle_missing_file()
```

### Financial/Inventory Race Conditions

```python
# VULNERABLE: Check-then-update without locking
def transfer(from_account, to_account, amount):
    if from_account.balance >= amount:  # Check
        # Race window: another thread could debit here
        from_account.balance -= amount   # Use
        to_account.balance += amount

# SECURE: Database transaction with row locking
def transfer(from_account_id, to_account_id, amount):
    with db.transaction():
        from_account = Account.query.with_for_update().get(from_account_id)
        if from_account.balance >= amount:
            from_account.balance -= amount
            to_account = Account.query.with_for_update().get(to_account_id)
            to_account.balance += amount
```

### Coupon/Voucher Double-Spend

```python
# VULNERABLE: Double-redemption possible
def redeem_coupon(coupon_code, user):
    coupon = Coupon.query.filter_by(code=coupon_code, used=False).first()
    if coupon:
        # Race window
        apply_discount(user, coupon.discount)
        coupon.used = True
        db.session.commit()

# SECURE: Atomic update
def redeem_coupon(coupon_code, user):
    result = Coupon.query.filter_by(
        code=coupon_code, 
        used=False
    ).update({'used': True, 'used_by': user.id})
    
    if result > 0:  # Row was actually updated
        coupon = Coupon.query.filter_by(code=coupon_code).first()
        apply_discount(user, coupon.discount)
        db.session.commit()
```

### API Rate Limiting Race

```python
# VULNERABLE: Check-then-increment
def check_rate_limit(user_id):
    count = redis.get(f"rate:{user_id}")
    if int(count or 0) < LIMIT:
        redis.incr(f"rate:{user_id}")
        return True
    return False

# SECURE: Atomic increment with check
def check_rate_limit(user_id):
    key = f"rate:{user_id}"
    count = redis.incr(key)
    if count == 1:
        redis.expire(key, WINDOW_SECONDS)
    return count <= LIMIT
```

## High-Risk Areas

1. **Financial transactions** - Balance checks, transfers, withdrawals
2. **Inventory management** - Stock checks, order placement
3. **Coupon/voucher redemption** - Single-use validation
4. **Rate limiting** - Request counting
5. **Session management** - Token refresh/invalidation
6. **File operations** - Check-then-read/write
7. **Voting/polling systems** - Duplicate vote prevention
8. **Auction/bidding** - Bid validation

## Async / Promise Race Conditions (JavaScript)

### Detection Patterns

```bash
# Shared state modified in async functions
grep -rn "async\s*function\|async\s*(" --include="*.js" --include="*.ts" | grep -c ""

# Await gaps with shared state
grep -rn "await.*\n.*await" --include="*.js" --include="*.ts"

# Promise.all with dependent operations
grep -rn "Promise\.all\|Promise\.allSettled" --include="*.js" --include="*.ts"
```

### Vulnerable Patterns

```javascript
// VULNERABLE: Shared state between awaits
let balance = await getBalance(userId);
// Race window: another request can read same balance here
if (balance >= amount) {
    await deductBalance(userId, amount);  // Double-spend possible
}

// VULNERABLE: Non-atomic read-modify-write
app.post('/like', async (req, res) => {
    const post = await Post.findById(req.body.postId);
    post.likes += 1;  // Race: two requests read same value
    await post.save();
});

// SECURE: Atomic database operation
app.post('/like', async (req, res) => {
    await Post.findByIdAndUpdate(req.body.postId, { $inc: { likes: 1 } });
});
```

## Database Locking Patterns

### Detection Patterns

```bash
# SELECT FOR UPDATE (pessimistic locking)
grep -rn "FOR UPDATE\|for_update\|with_for_update\|NOWAIT\|SKIP LOCKED" --include="*.py" --include="*.js" --include="*.ts" --include="*.java" --include="*.rb" --include="*.sql"

# Optimistic locking (version columns)
grep -rn "version\|optimistic_lock\|@Version\|lock_version\|OptimisticLocking\|StaleObjectError\|OptimisticLockException" --include="*.py" --include="*.js" --include="*.ts" --include="*.java" --include="*.rb"
```

### Vulnerable Patterns

```sql
-- VULNERABLE: No locking on balance check
SELECT balance FROM accounts WHERE id = 123;
-- Another transaction can read same balance here
UPDATE accounts SET balance = balance - 100 WHERE id = 123;

-- SECURE: SELECT FOR UPDATE
BEGIN;
SELECT balance FROM accounts WHERE id = 123 FOR UPDATE;
-- Row is locked, other transactions wait
UPDATE accounts SET balance = balance - 100 WHERE id = 123;
COMMIT;
```

```python
# VULNERABLE: Django/SQLAlchemy without locking
account = Account.objects.get(id=account_id)
if account.balance >= amount:
    account.balance -= amount
    account.save()

# SECURE: select_for_update
with transaction.atomic():
    account = Account.objects.select_for_update().get(id=account_id)
    if account.balance >= amount:
        account.balance -= amount
        account.save()
```

## Go Concurrency Race Conditions

### Detection Patterns

```bash
# Goroutines accessing shared state
grep -rn "go func\|go \w" --include="*.go"

# Missing mutex/lock around shared data
grep -rn "sync\.Mutex\|sync\.RWMutex\|sync\.Map\|atomic\." --include="*.go"

# Channel operations (check for proper usage)
grep -rn "make(chan\|<-\s*chan\|chan\s*<-" --include="*.go"
```

### Vulnerable Patterns

```go
// VULNERABLE: Shared map without synchronization
var cache = make(map[string]string)  // Concurrent map read/write = panic

func handler(w http.ResponseWriter, r *http.Request) {
    go func() {
        cache[r.URL.Path] = result  // Race condition
    }()
}

// SECURE: Use sync.Map or mutex
var cache sync.Map

func handler(w http.ResponseWriter, r *http.Request) {
    cache.Store(r.URL.Path, result)
}
```

## Race Condition Checklist

- [ ] Financial operations use database transactions with row locking
- [ ] SELECT FOR UPDATE used for check-then-update patterns
- [ ] Atomic operations for counters (INCR, not GET+SET)
- [ ] Unique constraints prevent duplicate entries
- [ ] No TOCTOU in file operations
- [ ] Idempotency keys for payment operations
- [ ] Optimistic locking with version numbers where appropriate
- [ ] Async/await code doesn't have shared state between await points
- [ ] Go goroutines use sync primitives for shared data
- [ ] Promise.all not used for dependent/sequential operations
