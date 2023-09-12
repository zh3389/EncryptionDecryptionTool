import tkinter as tk
import tkinter.messagebox as messagebox
from tkinter import ttk
import secrets
from SM4Module import *


class SM4EncryptionApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Python SM4 加密工具")

        self.tabControl = ttk.Notebook(self.root)
        self.ecbTab = ttk.Frame(self.tabControl)
        self.cbcTab = ttk.Frame(self.tabControl)

        self.tabControl.add(self.ecbTab, text="ECB")
        self.tabControl.add(self.cbcTab, text="CBC")
        self.tabControl.pack(expand=1, fill="both")

        self.create_ecb_tab()
        self.create_cbc_tab()

    def create_ecb_tab(self):
        self.ecb_key_label = ttk.Label(self.ecbTab, text="密钥:")
        self.ecb_key_label.grid(row=0, column=0, padx=10, pady=10)
        self.ecb_key_var = tk.StringVar()
        self.ecb_key_entry = ttk.Entry(self.ecbTab, textvariable=self.ecb_key_var)
        self.ecb_key_entry.insert(0, string=secrets.token_hex(16))
        self.ecb_key_entry.grid(row=0, column=1, padx=10, pady=10)
        self.copy = ttk.Button(self.ecbTab, text="复制", command=lambda: self.copy_to_clipboard(self.ecb_key_var.get()))
        self.copy.grid(row=0, column=2, columnspan=2, padx=10, pady=10)

        self.ecb_plaintext_label = ttk.Label(self.ecbTab, text="明文:")
        self.ecb_plaintext_label.grid(row=2, column=0, padx=10, pady=10)
        self.ecb_plaintext_entry = ttk.Entry(self.ecbTab)
        self.ecb_plaintext_entry.grid(row=2, column=1, padx=10, pady=10)
        self.ecb_encrypt_button = ttk.Button(self.ecbTab, text="加密", command=self.encrypt_ecb)
        self.ecb_encrypt_button.grid(row=2, column=2, columnspan=2, padx=10, pady=10)

        self.ecb_decrypt_label = ttk.Label(self.ecbTab, text="密文:")
        self.ecb_decrypt_label.grid(row=3, column=0, padx=10, pady=10)
        self.ecb_decrypt_entry = ttk.Entry(self.ecbTab)
        self.ecb_decrypt_entry.grid(row=3, column=1, padx=10, pady=10)
        self.ecb_decrypt_button = ttk.Button(self.ecbTab, text="解密", command=self.decrypt_ecb)
        self.ecb_decrypt_button.grid(row=3, column=2, columnspan=2, padx=10, pady=10)

        self.ecb_result_label = ttk.Label(self.ecbTab, text="结果:")
        self.ecb_result_label.grid(row=4, column=0, padx=10, pady=10)
        self.ecb_result_text = tk.Text(self.ecbTab, height=3, width=26)
        self.ecb_result_text.grid(row=4, column=1, padx=10, pady=10)
        self.copy = ttk.Button(self.ecbTab, text="复制", command=lambda: self.copy_to_clipboard(self.ecb_result_text.get(1.0, tk.END)))
        self.copy.grid(row=4, column=2, columnspan=2, padx=10, pady=10)

    def create_cbc_tab(self):
        self.cbc_key_label = ttk.Label(self.cbcTab, text="密钥:", )
        self.cbc_key_label.grid(row=0, column=0, padx=10, pady=10)
        self.cbc_key_var = tk.StringVar()
        self.cbc_key_entry = ttk.Entry(self.cbcTab, textvariable=self.cbc_key_var)
        self.cbc_key_entry.insert(0, string=secrets.token_hex(16))
        self.cbc_key_entry.grid(row=0, column=1, padx=10, pady=10)
        self.copy = ttk.Button(self.cbcTab, text="复制", command=lambda: self.copy_to_clipboard(self.cbc_key_var.get()))
        self.copy.grid(row=0, column=2, columnspan=2, padx=10, pady=10)

        self.cbc_key_label = ttk.Label(self.cbcTab, text="IV值:", )
        self.cbc_key_label.grid(row=1, column=0, padx=10, pady=10)
        self.cbc_iv_var = tk.StringVar()
        self.cbc_iv_entry = ttk.Entry(self.cbcTab, textvariable=self.cbc_iv_var)
        self.cbc_iv = secrets.token_bytes(16)
        self.cbc_iv_entry.insert(0, string=self.cbc_iv.hex())
        self.cbc_iv_entry.grid(row=1, column=1, padx=10, pady=10)
        self.copy = ttk.Button(self.cbcTab, text="复制", command=lambda: self.copy_to_clipboard(self.cbc_iv_var.get()))
        self.copy.grid(row=1, column=2, columnspan=2, padx=10, pady=10)

        self.cbc_plaintext_label = ttk.Label(self.cbcTab, text="明文:")
        self.cbc_plaintext_label.grid(row=2, column=0, padx=10, pady=10)
        self.cbc_plaintext_entry = ttk.Entry(self.cbcTab)
        self.cbc_plaintext_entry.grid(row=2, column=1, padx=10, pady=10)
        self.cbc_encrypt_button = ttk.Button(self.cbcTab, text="加密", command=self.encrypt_cbc)
        self.cbc_encrypt_button.grid(row=2, column=2, columnspan=2, padx=10, pady=10)

        self.cbc_decrypt_label = ttk.Label(self.cbcTab, text="密文:")
        self.cbc_decrypt_label.grid(row=3, column=0, padx=10, pady=10)
        self.cbc_decrypt_entry = ttk.Entry(self.cbcTab)
        self.cbc_decrypt_entry.grid(row=3, column=1, padx=10, pady=10)
        self.cbc_decrypt_button = ttk.Button(self.cbcTab, text="解密", command=self.decrypt_cbc)
        self.cbc_decrypt_button.grid(row=3, column=2, columnspan=2, padx=10, pady=10)

        self.cbc_result_label = ttk.Label(self.cbcTab, text="结果:")
        self.cbc_result_label.grid(row=4, column=0, padx=10, pady=10)
        self.cbc_result_text = tk.Text(self.cbcTab, height=3, width=26)
        self.cbc_result_text.grid(row=4, column=1, padx=10, pady=10)
        self.copy = ttk.Button(self.cbcTab, text="复制", command=lambda: self.copy_to_clipboard(self.cbc_result_text.get(1.0, tk.END)))
        self.copy.grid(row=4, column=2, columnspan=2, padx=10, pady=10)

    def copy_to_clipboard(self, text):
        self.root.clipboard_clear()  # 清空剪贴板
        self.root.clipboard_append(text)  # 添加要复制的文本
        messagebox.showinfo('Copied', '已复制到系统粘贴板')  # 显示提示消息

    def encrypt_ecb(self):
        key = self.ecb_key_var.get().encode('utf-8')
        plaintext = self.ecb_plaintext_entry.get().encode('utf-8')

        encryptor = SM4ecb(key)
        encrypted_data = encryptor.encrypt(plaintext)

        self.ecb_result_text.delete(1.0, tk.END)
        self.ecb_result_text.insert(tk.END, encrypted_data)

    def decrypt_ecb(self):
        key = self.ecb_key_var.get().encode('utf-8')
        ciphertext = self.ecb_decrypt_entry.get()

        decryptor = SM4ecb(key)
        decrypted_data = decryptor.decrypt(ciphertext)

        self.ecb_result_text.delete(1.0, tk.END)
        self.ecb_result_text.insert(tk.END, decrypted_data)

    def encrypt_cbc(self):
        key = self.cbc_key_var.get().encode('utf-8')
        iv = bytes.fromhex(self.cbc_iv_var.get())
        plaintext = self.cbc_plaintext_entry.get().encode('utf-8')

        encryptor = SM4cbc(key, iv)
        encrypted_data = encryptor.encrypt(plaintext)

        self.cbc_result_text.delete(1.0, tk.END)
        self.cbc_result_text.insert(tk.END, encrypted_data)

    def decrypt_cbc(self):
        key = self.cbc_key_var.get().encode('utf-8')
        iv = bytes.fromhex(self.cbc_iv_var.get())
        ciphertext = self.cbc_decrypt_entry.get()

        decryptor = SM4cbc(key, iv)
        decrypted_data = decryptor.decrypt(ciphertext)

        self.cbc_result_text.delete(1.0, tk.END)
        self.cbc_result_text.insert(tk.END, decrypted_data)


if __name__ == "__main__":
    root = tk.Tk()
    app = SM4EncryptionApp(root)
    root.mainloop()
