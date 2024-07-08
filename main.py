import customtkinter as ctk
from tkinter import filedialog, messagebox
import hashlib
from AES import AEScipher
class ChecksumFrame(ctk.CTkFrame):
    def __init__(self, master, **kwargs):
        super().__init__(master, **kwargs)
        self.grid_rowconfigure((0, 1, 2), weight=1)
        self.grid_columnconfigure((0, 1, 2), weight=1)

        self.file_label = ctk.CTkLabel(self, text="Select File:")
        self.file_label.grid(row=0, column=0, padx=10, pady=10, sticky="ew")

        self.file_entry = ctk.CTkEntry(self, width=300, state="disable")
        self.file_entry.grid(row=0, column=1, padx=10, pady=10, sticky="ew")

        self.browse_button = ctk.CTkButton(self, text="Browse", width=150, command=self.browse_file)
        self.browse_button.grid(row=0, column=2, padx=10, pady=10, sticky="w")

        self.md5_label = ctk.CTkLabel(self, text="MD5 Checksum:")
        self.md5_label.grid(row=1, column=0, padx=20, sticky="ew")

        self.md5_result = ctk.CTkEntry(self, state="readonly")
        self.md5_result.grid(row=1, column=1, columnspan=2, padx=10, pady=10, sticky="ew")

        self.sha2_label = ctk.CTkLabel(self, text="SHA-2 Checksum:")
        self.sha2_label.grid(row=2, column=0, padx=20, sticky="ew")

        self.sha2_result = ctk.CTkEntry(self, state="readonly")
        self.sha2_result.grid(row=2, column=1, columnspan=2, padx=10, pady=10, sticky="ew")

    def browse_file(self):
        file_path = filedialog.askopenfilename()
        if file_path:
            self.file_entry.configure(state="normal")
            self.file_entry.delete(0, ctk.END)
            self.file_entry.insert(0, file_path)
            self.file_entry.configure(state="disabled")
            self.calculate_checksums(file_path)

    def calculate_checksums(self, file_path):
        md5_hash = hashlib.md5()
        sha2_hash = hashlib.sha256()

        with open(file_path, "rb") as file:
            while chunk := file.read(8192):
                md5_hash.update(chunk)
                sha2_hash.update(chunk)

        self.md5_result.configure(state="normal")
        self.md5_result.insert(0, md5_hash.hexdigest())
        self.md5_result.configure(state="readonly")

        self.sha2_result.configure(state="normal")
        self.sha2_result.insert(0, sha2_hash.hexdigest())
        self.sha2_result.configure(state="readonly")

class EncryptFrame(ctk.CTkFrame):
    def __init__(self,master,**kwargs):
        super().__init__(master, **kwargs)
        self.grid_rowconfigure((0,1,2,3,4), weight=1)
        self.grid_columnconfigure((0,1,2,3,4), weight=1)

        self.input_label = ctk.CTkLabel(self, text="Input Data (Text or File):")
        self.input_label.grid(row=0, column=0, sticky="w", padx = 10)

        self.input_text = ctk.CTkEntry(self, width=300)
        self.input_text.grid(row=0, column=0, padx=10, sticky="esw")

        self.key_label = ctk.CTkLabel(self, text="Key:")
        self.key_label.grid(row=1, column=0, sticky="w", padx = 10)

        self.key_entry = ctk.CTkEntry(self, width=200)
        self.key_entry.grid(row=1, column = 0,pady=10)

        self.browse_button = ctk.CTkButton(self, text="Browse", width=100, command=self.browse_file)
        self.browse_button.grid(row = 0, column=1, sticky="wse")

        self.encypt_button = ctk.CTkButton(self, text = "Encrypt", width=100, fg_color="black", text_color="blue", command=self.encrypt_data)
        self.encypt_button.grid(row = 1, column = 2)

        self.decrypt_button = ctk.CTkButton(self, text="Decrypt", width=100, fg_color="black", text_color="blue", command=self.decrypt_data)
        self.decrypt_button.grid(row = 1, column= 2, sticky="s")

        self.status_label = ctk.CTkLabel(self, text="")
        self.status_label.grid(row=3, column=0, columnspan=2, padx=10, pady=5, sticky="w")

    def browse_file(self):
        file_path = filedialog.askopenfilename()
        if file_path:
            self.input_text.configure(state="normal")
            self.input_text.delete(0, ctk.END)
            self.input_text.insert(0, file_path)
            self.input_text.configure(state="disabled")

    def encrypt_data(self):
        file_path = self.input_text.get()
        key = self.key_entry.get()
        if file_path and key:
            try:
                aes = AEScipher(key)
                aes.encryption(file_path)
                self.status_label.configure(text="Encryption completed.")
            except Exception as e:
                messagebox.showerror("Error", f"An error occurred: {e}")
        else:
            messagebox.showwarning("Warning", "Please select a file and enter a key.")
    def decrypt_data(self):
        file_path = self.input_text.get()
        key = self.key_entry.get()
        if file_path and key:
            try:
                aes = AEScipher(key)
                aes.decryption(file_path)
                self.status_label.configure(text="Decryption completed.")
            except Exception as e:
                messagebox.showerror("Error", f"An error occurred: {e}")
        else:
            messagebox.showwarning("Warning", "Please select a file and enter a key.")


class App(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("File Checksum and Encryption Tool")
        self.geometry("650x500")

        self.grid_rowconfigure(0, weight=1)
        self.grid_columnconfigure(0, weight=1)
        self.tab_control = ctk.CTkTabview(self)
        self.tab_control.grid(row=0, column=0, sticky="nsew", padx=10, pady=10)
        self.tab_control.add("Checksum")
        self.tab_control.add("Encryption/Decryption")

        self.tabchecksum = ChecksumFrame(master=self.tab_control.tab("Checksum"))
        self.tabchecksum.pack(fill="both", expand=True)

        self.tabencrypt = EncryptFrame(master = self.tab_control.tab("Encryption/Decryption"))
        self.tabencrypt.pack(fill = "both", expand=True)
if __name__ == "__main__":
    app = App()
    app.mainloop()
