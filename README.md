# Backup-Utility

The Backup Utility project is an application designed for data security. It allows users to securely back up sensitive files by encrypting them (cloud storage via OAuth as an future addition), ensuring data confidentiality. This project explores encryption algorithms, secure file storage, and user-friendly interfaces, combining cryptographic theory with practical implementation.

The project was divided into two main modules: Encryptor and Decryptor.

* **Encryptor Module:** Selects files to back up, compresses and encrypts them.
* **Decryptor Module:** Retrieves encrypted files, decrypts them with a user-provided key, and restores them for user access.

Each module includes a graphical interface for seamless user interaction


# Libraries and Frameworks:
* **tkinter:** For creating a user-friendly GUI.
* **cryptography:** Provides AES encryption and decryption functionalities.
* **shutil:** Handles file archiving.

# Encryption Algorithm: AES (Advanced Encryption Standard)
* **Key Size:** 128 bits
* **Mode of Operation:** CBC (Cipher Block Chaining)

# Future Scope
* **Support for Different Key Lengths:** Adding options for 192-bit or 256-bit AES encryption for enhanced security.
* **Multi-Platform Storage Options:** Allowing cloud storage to platforms like Google Drive, Dropbox, AWS S3 etc.
* **User-Defined Settings:** Allow users to adjust encryption settings, including key length and encryption mode.
