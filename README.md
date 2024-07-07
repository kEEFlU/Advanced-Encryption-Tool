# Advanced-Encryption-Tool
This is a comprehensive encryption tool that allows users to encrypt and decrypt text and files using AES encryption. It supports password-based encryption and features a modern GUI.

## Features

- **Text Encryption/Decryption**: Encrypt and decrypt text using AES encryption.
- **File Encryption/Decryption**: Encrypt and decrypt files.
- **Password-Based Encryption**: Uses PBKDF2 for generating encryption keys from passwords.
- **User-Friendly GUI**: A modern and visually appealing interface.
- **Help Section**: Guidance for using the tool.

## Requirements

- Python 3.x
- `pycryptodome` library
- `tkinter` library (comes with Python)

## Installation

1. Clone the repository:
    ```bash
    git clone https://github.com/yourusername/AdvancedEncryptionTool.git
    cd AdvancedEncryptionTool
    ```

2. Install the required libraries:
    ```bash
    pip install pycryptodome
    ```

## Usage

1. Run the encryption tool:
    ```bash
    python encryption_tool.py
    ```

2. **Encrypting Data:**
    - Enter the data you want to encrypt in the "Data" field.
    - Enter a password in the "Password" field.
    - Click the "Encrypt" button to encrypt the data.
    - The nonce, ciphertext, tag, and salt will be displayed.

3. **Decrypting Data:**
    - Enter the nonce, ciphertext, tag, salt, and password used during encryption.
    - Click the "Decrypt" button to decrypt the data.

4. **Encrypting Files:**
    - Enter a password in the "Password" field.
    - Click the "Encrypt File" button and select the file you want to encrypt.
    - The encrypted file will be saved with a `.enc` extension.

5. **Decrypting Files:**
    - Enter the password used during encryption in the "Password" field.
    - Click the "Decrypt File" button and select the encrypted file.
    - The decrypted file will be saved with the original extension.

## Help

Click the "Help" button in the GUI for guidance on how to use the tool.

## License

This project is licensed under the MIT License.
