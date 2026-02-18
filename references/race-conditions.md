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

## Race Condition Checklist

- [ ] Financial operations use database transactions
- [ ] Row-level locking for balance/inventory updates
- [ ] Atomic operations for counters (INCR, not GET+SET)
- [ ] Unique constraints prevent duplicate entries
- [ ] No TOCTOU in file operations
- [ ] Idempotency keys for payment operations
- [ ] Optimistic locking with version numbers where appropriate
