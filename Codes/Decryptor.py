import os
import tkinter as tk
from tkinter import filedialog, messagebox
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding

def decrypt_file():
    # Get the encryption key
    key = key_entry.get().encode('ascii')
    if len(key) != 16:
        messagebox.showerror("Error", "The AES key must be exactly 16 characters long.")
        return
    
    # Select the encrypted file
    file_path = filedialog.askopenfilename(title="Select Encrypted File", filetypes=[("Encrypted Files", "*.enc"), ("All Files", "*.*")])
    if not file_path:
        return

    # Read the encrypted data
    try:
        with open(file_path, 'rb') as encrypted_file:
            encrypted_data = encrypted_file.read()
        
        # Extract IV and encrypted content
        iv = encrypted_data[-16:]
        encrypted_data = encrypted_data[:-16]
        
        # Set up the AES decryption
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        padded_pt = decryptor.update(encrypted_data) + decryptor.finalize()
        
        # Remove padding
        unpadder = padding.PKCS7(128).unpadder()
        pt = unpadder.update(padded_pt) + unpadder.finalize()

        # Save decrypted content as a zip file
        save_path = filedialog.asksaveasfilename(defaultextension=".zip", filetypes=[("Zip Files", "*.zip")], title="Save Decrypted File As")
        if not save_path:
            return
        
        with open(save_path, 'wb') as decrypted_file:
            decrypted_file.write(pt)
        
        messagebox.showinfo("Success", "Decryption completed successfully!")
    except Exception as e:
        messagebox.showerror("Error", f"An error occurred during decryption: {e}")

# GUI setup
app = tk.Tk()
app.title("Decryption Tool")
app.geometry("600x300")
app.configure(bg="#f0f4fa")

# Title Label
title_label = tk.Label(app, text="File Decryption System", font=("Helvetica", 18, "bold"), bg="#4a90e2", fg="white")
title_label.pack(fill="x", pady=10)

# Key Entry
key_label = tk.Label(app, text="Enter AES Key (16 characters):", font=("Arial", 12), bg="#f0f4fa", fg="#333")
key_label.pack(pady=10)
key_entry = tk.Entry(app, font=("Arial", 12), width=30, show="*")
key_entry.pack()

# Decrypt Button
decrypt_button = tk.Button(
    app,
    text="Decrypt File",
    font=("Arial", 14),
    bg="#4a90e2",
    fg="white",
    width=20,
    command=decrypt_file
)
decrypt_button.pack(pady=20)

# Footer Label
footer_label = tk.Label(app, text="All rights reserved © 2023", font=("Arial", 10), bg="#f0f4fa", fg="#777")
footer_label.pack(side="bottom", pady=10)

app.mainloop()
