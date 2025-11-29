"""
Main Flask application for the Secure File Encryption System
Developed by: Cadet Ekeh Wisdom Uzoma, NPA/03/03/21/0379
Nigeria Police Academy, Wudil
"""

from flask import Flask, render_template, request, session, send_file, flash
import os
from crypto_engine import (
    encrypt_data, 
    decrypt_data, 
    derive_key, 
    compute_hash, 
    verify_integrity,
    generate_random_bytes
)
import secrets

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)  # Secure random key for production

@app.route('/')
def index():
    """Render the main page with file upload form"""
    return render_template('index.html')

@app.route('/process', methods=['POST'])
def process_file():
    """Handle file encryption/decryption requests"""
    try:
        operation = request.form.get('operation')
        password = request.form['password'].encode('utf-8')
        uploaded_file = request.files['file']
        
        if uploaded_file.filename == '':
            flash('No file selected. Please choose a file.', 'error')
            return render_template('index.html')
        
        file_data = uploaded_file.read()
        
        if operation == 'encrypt':
            return handle_encryption(file_data, password, uploaded_file.filename)
        elif operation == 'decrypt':
            return handle_decryption(file_data, password, uploaded_file.filename)
        else:
            flash('Invalid operation selected.', 'error')
            return render_template('index.html')
            
    except Exception as e:
        flash(f'Operation failed: {str(e)}', 'error')
        return render_template('index.html')

def handle_encryption(file_data, password, original_filename):
    """Handle file encryption process"""
    # Derive key with new salt
    key, salt = derive_key(password)
    
    # Compute hash of original file
    original_hash = compute_hash(file_data)
    session['original_hash'] = original_hash.hex()
    
    # Encrypt the data
    ciphertext, iv = encrypt_data(file_data, key)
    
    # Create output file: salt (16) + iv (16) + ciphertext
    output_data = salt + iv + ciphertext
    
    # Save encrypted file
    output_filename = f"encrypted_{original_filename}.enc"
    with open(output_filename, 'wb') as f:
        f.write(output_data)
    
    flash('File encrypted successfully!', 'success')
    return send_file(output_filename, as_attachment=True, 
                   download_name=output_filename)

def handle_decryption(file_data, password, encrypted_filename):
    """Handle file decryption process"""
    try:
        # Extract salt (first 16 bytes), iv (next 16 bytes), and ciphertext
        if len(file_data) < 32:
            flash('Invalid encrypted file: too short.', 'error')
            return render_template('index.html')
            
        salt = file_data[:16]
        iv = file_data[16:32]
        ciphertext = file_data[32:]
        
        # Re-derive key
        key, _ = derive_key(password, salt)
        
        # Decrypt data
        decrypted_data = decrypt_data(ciphertext, key, iv)
        
        # Verify integrity
        original_hash_hex = session.get('original_hash', '')
        if original_hash_hex:
            original_hash = bytes.fromhex(original_hash_hex)
            if not verify_integrity(original_hash, decrypted_data):
                flash('Integrity check failed! File may be corrupted or password incorrect.', 'error')
                return render_template('index.html')
        
        # Save decrypted file
        output_filename = f"decrypted_{encrypted_filename.replace('.enc', '')}"
        with open(output_filename, 'wb') as f:
            f.write(decrypted_data)
        
        flash('File decrypted successfully! Integrity verified.', 'success')
        return send_file(output_filename, as_attachment=True)
        
    except ValueError as e:
        flash('Decryption failed. Possible incorrect password or corrupted file.', 'error')
        return render_template('index.html')

if __name__ == '__main__':
    app.run(debug=True, host='127.0.0.1', port=5000)