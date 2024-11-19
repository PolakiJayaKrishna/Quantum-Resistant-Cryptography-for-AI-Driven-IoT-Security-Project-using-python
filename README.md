import json
import streamlit as st
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import SHA256
from Crypto.Signature import pkcs1_15

# Generate RSA keys (simulating quantum-resistant encryption)
def generate_keys():
    key = RSA.generate(2048)
    private_key = key
    public_key = key.publickey()
    return private_key, public_key

# Save keys to files (optional)
private_key, public_key = generate_keys()

# IoT device data generation (now accepts user input via Streamlit as text)
def generate_text_data():
    text = st.text_area("Enter text to analyze:", "Type some text here.")
    return text

# Encrypt data with public key
def encrypt_data(data, pub_key):
    cipher = PKCS1_OAEP.new(pub_key)
    return cipher.encrypt(data)

# Sign data with private key
def sign_data(data, priv_key):
    hasher = SHA256.new(data)
    signature = pkcs1_15.new(priv_key).sign(hasher)
    return signature

# Simulate IoT device sending data to server
def simulate_iot_device(pub_key, priv_key):
    # Generate and analyze text
    text = generate_text_data()
    
    # Convert data to JSON and encrypt it
    data_json = json.dumps({"text": text}).encode('utf-8')
    encrypted_data = encrypt_data(data_json, pub_key)
    signature = sign_data(data_json, priv_key)

    # Return encrypted and signed data
    return encrypted_data, signature, data_json  # Including plain JSON for demo

# Decrypt data with private key
def decrypt_data(encrypted_data, priv_key):
    cipher = PKCS1_OAEP.new(priv_key)
    return cipher.decrypt(encrypted_data)

# Verify data with public key
def verify_signature(data, signature, pub_key):
    hasher = SHA256.new(data)
    try:
        pkcs1_15.new(pub_key).verify(hasher, signature)
        return True
    except (ValueError, TypeError):
        return False

# Threat analysis function for text data
def analyze_threat(text):
    # Define some threat keywords or patterns
    threat_keywords = ["attack", "malware", "virus", "unauthorized", "breach"]
    
    # Check if any threat keywords appear in the text
    for keyword in threat_keywords:
        if keyword.lower() in text.lower():
            return f"Threat detected: The text contains suspicious keyword '{keyword}'."
    
    # If no threats found, consider it safe
    return "No threats detected in the text."

# Simulate server receiving data from IoT device
def simulate_server(encrypted_data, signature, pub_key, priv_key):
    try:
        # Decrypt data
        decrypted_data = decrypt_data(encrypted_data, priv_key)
        
        # Verify signature
        if verify_signature(decrypted_data, signature, pub_key):
            st.success("Signature Verified. Data is authentic.")
            
            # Load and process data
            data = json.loads(decrypted_data)
            st.write("Decrypted Data:", data)
            
            # Threat Analysis: Check if the data has any security issues
            threat_message = analyze_threat(data["text"])
            st.write(threat_message)
        else:
            st.error("Signature Verification Failed. Data may have been tampered with.")
    except Exception as e:
        st.error(f"Failed to decrypt or verify data: {str(e)}")

# Main execution flow using Streamlit interface
def main():
    st.title("Text Data Threat Analysis with Quantum-Resistant Cryptography")

    # Simulate IoT device sending data
    encrypted_data, signature, plain_json = simulate_iot_device(public_key, private_key)

    st.subheader("Original JSON Data (Before Encryption):")
    st.json(json.loads(plain_json.decode('utf-8')))  # Display the plain JSON

    st.subheader("Encrypted Data Sent (Hexadecimal Encoding):")
    st.text(encrypted_data.hex())  # Display encrypted data in hexadecimal format

    # Simulate server processing received data
    simulate_server(encrypted_data, signature, public_key, private_key)

# Run the Streamlit app
if __name__ == "__main__":
    main()
