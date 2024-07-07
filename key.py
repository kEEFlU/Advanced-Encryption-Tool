import os
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes
import base64

# Function to generate a key from the password
def generate_key(password, salt):
    key = PBKDF2(password, salt, dkLen=32)
    return key

# Function to encrypt text
def encrypt_data():
    data = data_entry.get()
    password = password_entry.get()

    if not data or not password:
        messagebox.showerror("Error", "Data and password are required!")
        return

    salt = get_random_bytes(16)
    key = generate_key(password, salt)
    cipher = AES.new(key, AES.MODE_GCM)
    nonce = cipher.nonce
    ciphertext, tag = cipher.encrypt_and_digest(data.encode())

    nonce_entry.delete(0, tk.END)
    nonce_entry.insert(0, base64.b64encode(nonce).decode())
    ciphertext_entry.delete(0, tk.END)
    ciphertext_entry.insert(0, base64.b64encode(ciphertext).decode())
    tag_entry.delete(0, tk.END)
    tag_entry.insert(0, base64.b64encode(tag).decode())
    salt_entry.delete(0, tk.END)
    salt_entry.insert(0, base64.b64encode(salt).decode())

def decrypt_data():
    password = password_entry.get()
    nonce = base64.b64decode(nonce_entry.get())
    ciphertext = base64.b64decode(ciphertext_entry.get())
    tag = base64.b64decode(tag_entry.get())
    salt = base64.b64decode(salt_entry.get())

    if not nonce or not ciphertext or not tag or not salt or not password:
        messagebox.showerror("Error", "All fields are required!")
        return

    key = generate_key(password, salt)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)

    try:
        data = cipher.decrypt_and_verify(ciphertext, tag).decode()
        data_entry.delete(0, tk.END)
        data_entry.insert(0, data)
    except ValueError:
        messagebox.showerror("Error", "Decryption failed: MAC check failed")

def encrypt_file():
    file_path = filedialog.askopenfilename()
    if not file_path:
        return

    password = password_entry.get()
    if not password:
        messagebox.showerror("Error", "Password is required!")
        return

    with open(file_path, 'rb') as file:
        file_data = file.read()

    salt = get_random_bytes(16)
    key = generate_key(password, salt)
    cipher = AES.new(key, AES.MODE_GCM)
    nonce = cipher.nonce
    ciphertext, tag = cipher.encrypt_and_digest(file_data)

    encrypted_file_path = file_path + '.enc'
    with open(encrypted_file_path, 'wb') as file:
        for x in (salt, nonce, tag, ciphertext):
            file.write(x)

    messagebox.showinfo("Success", f"File encrypted and saved to {encrypted_file_path}")

def decrypt_file():
    file_path = filedialog.askopenfilename()
    if not file_path:
        return

    password = password_entry.get()
    if not password:
        messagebox.showerror("Error", "Password is required!")
        return

    with open(file_path, 'rb') as file:
        salt = file.read(16)
        nonce = file.read(16)
        tag = file.read(16)
        ciphertext = file.read()

    key = generate_key(password, salt)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)

    try:
        file_data = cipher.decrypt_and_verify(ciphertext, tag)
        decrypted_file_path = os.path.splitext(file_path)[0]
        with open(decrypted_file_path, 'wb') as file:
            file.write(file_data)
        messagebox.showinfo("Success", f"File decrypted and saved to {decrypted_file_path}")
    except ValueError:
        messagebox.showerror("Error", "Decryption failed: MAC check failed")

def show_help():
    help_text = (
        "Encryption Tool Help:\n\n"
        "1. Data Encryption/Decryption:\n"
        "   - Enter the data you want to encrypt in the 'Data' field.\n"
        "   - Enter a password in the 'Password' field.\n"
        "   - Click 'Encrypt' to encrypt the data.\n"
        "   - To decrypt, enter the nonce, ciphertext, tag, and salt along with the password, then click 'Decrypt'.\n\n"
        "2. File Encryption/Decryption:\n"
        "   - Enter a password in the 'Password' field.\n"
        "   - Click 'Encrypt File' to select a file for encryption.\n"
        "   - Click 'Decrypt File' to select an encrypted file for decryption.\n"
    )
    messagebox.showinfo("Help", help_text)

# GUI setup
window = tk.Tk()
window.title("Advanced Encryption Tool")

main_frame = ttk.Frame(window, padding="10")
main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))

data_label = ttk.Label(main_frame, text="Data")
data_label.grid(row=0, column=0, padx=5, pady=5)
data_entry = ttk.Entry(main_frame, width=50)
data_entry.grid(row=0, column=1, padx=5, pady=5, columnspan=2)

password_label = ttk.Label(main_frame, text="Password")
password_label.grid(row=1, column=0, padx=5, pady=5)
password_entry = ttk.Entry(main_frame, show='*', width=50)
password_entry.grid(row=1, column=1, padx=5, pady=5, columnspan=2)

nonce_label = ttk.Label(main_frame, text="Nonce (hex, for decryption)")
nonce_label.grid(row=2, column=0, padx=5, pady=5)
nonce_entry = ttk.Entry(main_frame, width=50)
nonce_entry.grid(row=2, column=1, padx=5, pady=5, columnspan=2)

ciphertext_label = ttk.Label(main_frame, text="Ciphertext (hex, for decryption)")
ciphertext_label.grid(row=3, column=0, padx=5, pady=5)
ciphertext_entry = ttk.Entry(main_frame, width=50)
ciphertext_entry.grid(row=3, column=1, padx=5, pady=5, columnspan=2)

tag_label = ttk.Label(main_frame, text="Tag (hex, for decryption)")
tag_label.grid(row=4, column=0, padx=5, pady=5)
tag_entry = ttk.Entry(main_frame, width=50)
tag_entry.grid(row=4, column=1, padx=5, pady=5, columnspan=2)

salt_label = ttk.Label(main_frame, text="Salt (hex, for decryption)")
salt_label.grid(row=5, column=0, padx=5, pady=5)
salt_entry = ttk.Entry(main_frame, width=50)
salt_entry.grid(row=5, column=1, padx=5, pady=5, columnspan=2)

encrypt_button = ttk.Button(main_frame, text="Encrypt", command=encrypt_data)
encrypt_button.grid(row=6, column=0, padx=5, pady=5)

decrypt_button = ttk.Button(main_frame, text="Decrypt", command=decrypt_data)
decrypt_button.grid(row=6, column=1, padx=5, pady=5)

file_label = ttk.Label(main_frame, text="File")
file_label.grid(row=7, column=0, padx=5, pady=5)

encrypt_file_button = ttk.Button(main_frame, text="Encrypt File", command=encrypt_file)
encrypt_file_button.grid(row=7, column=1, padx=5, pady=5)

decrypt_file_button = ttk.Button(main_frame, text="Decrypt File", command=decrypt_file)
decrypt_file_button.grid(row=7, column=2, padx=5, pady=5)

help_button = ttk.Button(main_frame, text="Help", command=show_help)
help_button.grid(row=8, column=0, columnspan=3, padx=5, pady=5)

# Main loop
window.mainloop()
