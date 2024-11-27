import os
import time
import shutil
import tkinter as tk
from tkinter import filedialog, messagebox
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from pydrive.drive import GoogleDrive
from pydrive.auth import GoogleAuth
from cryptography.hazmat.primitives import padding
import shutil



def create_backup():
    # Folder selection
    src_dir = filedialog.askdirectory(title="Select Directory to Backup")
    dest_dir = filedialog.askdirectory(title="Select Backup Destination")
    
    if not src_dir or not dest_dir:
        messagebox.showwarning("Warning", "Both directories must be selected.")
        return
    
    # Using command prompt(cmd) to execute a powershell command, this powershell command will search the cwd for files/
    # folders which have been created since previous run
    # files = (os.popen(rf'powershell "Get-ChildItem \"{x}\" -Recurse | Where-Object {{ $_.CreationTime -ge \"{Adate}\" -or $_.LastWriteTime -ge \"{Adate}\" }} | % {{ $_.FullName }}"')).read()

    # Since the output of the powershell command is all the files created since previous run, on separate lines
    # therefore using the '\n' for splitting the data (which in turn would make the entries in a list), and then
    # removing the last entry (as after splitting the last '\n' we would end up with a empty string in the RHS)

    # Create and archive the backup
    today_date = time.strftime('%Y-%m-%d')
    backup_path = os.path.join(dest_dir, today_date)
    os.makedirs(backup_path, exist_ok=True)
    
    for folder in src_dir.split(";"):
        folder_name = os.path.basename(folder)
        dest_folder = os.path.join(backup_path, folder_name)
        os.makedirs(dest_folder, exist_ok=True)
        
        for dirpath, _, filenames in os.walk(folder):
            for file in filenames:
                shutil.copy(os.path.join(dirpath, file), dest_folder)
    
    archive_path = shutil.make_archive(backup_path, 'zip', dest_dir, today_date)
    
    # Removing the directory
    shutil.rmtree(backup_path)

    # Encryption
    with open(archive_path, 'rb') as f:
        data = f.read()
    
    key = b'rajamantrichorsi'
    iv = os.urandom(16)

    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(data) + padder.finalize()


    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
    
    enc_path = f"{archive_path[:-4]}.enc"
    with open(enc_path, 'wb') as enc_file:
        enc_file.write(encrypted_data + iv)
    
    # Uploading to Google Drive
    # gauth = GoogleAuth("settings.yaml")
    # gauth.LocalWebserverAuth()
    # drive = GoogleDrive(gauth)
    
    # drive_file = drive.CreateFile({"title": f"{today_date}.enc", "parents": [{"kind": "drive#fileLink", "id": "1ViSkVSr92IfxJVC5O2OsUmsxO33eSTeg"}]})
    # drive_file.SetContentFile(enc_path)
    # drive_file.Upload()
    
    messagebox.showinfo("Success", "Backup completed!")

# GUI setup
app = tk.Tk()
app.title("Enhanced Backup System")
app.geometry("600x400")
app.configure(bg="#f0f4fa")

# Title Label
title_label = tk.Label(app, text="Backup & Encryption System", font=("Helvetica", 18, "bold"), bg="#4a90e2", fg="white")
title_label.pack(fill="x", pady=10)

# Instruction Label
instruction_label = tk.Label(
    app,
    text="Select source and destination directories.\nThe system will create a backup, encrypt it, and upload to Google Drive.",
    font=("Arial", 12),
    bg="#f0f4fa",
    fg="#333"
)
instruction_label.pack(pady=20)

# Backup Button
backup_button = tk.Button(
    app,
    text="Create Backup",
    font=("Arial", 14),
    bg="#4a90e2",
    fg="white",
    width=20,
    command=create_backup
)
backup_button.pack(pady=30)

# Footer Label
footer_label = tk.Label(app, text="All rights reserved © 2023", font=("Arial", 10), bg="#f0f4fa", fg="#777")
footer_label.pack(side="bottom", pady=10)

app.mainloop()
