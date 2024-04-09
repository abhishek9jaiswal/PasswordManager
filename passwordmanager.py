from tkinter import *
from tkinter import messagebox
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
import base64
import os

# Function to simulate retrieving encrypted passwords (replace with your actual logic)
def get_encrypted_password(website, username):
    password_data = {
        ("example.com", "user1"): b'gAAAAABgCXWDZEDVQso0cb1oGMjFVcW6ZKrDe...',
        ("example.com", "user2"): b'gAAAAABgCXWDZEDVQso0cb1oGMjFVcW6ZKrDe...',
    }
    return password_data.get((website, username))

# Function to simulate saving encrypted passwords (replace with your actual logic)
def save_encrypted_password(website, username, encrypted_password):
    password_data = {
        ("example.com", "user1"): b'gAAAAABgCXWDZEDVQso0cb1oGMjFVcW6ZKrDe...',
        ("example.com", "user2"): b'gAAAAABgCXWDZEDVQso0cb1oGMjFVcW6ZKrDe...',
    }
    password_data[(website, username)] = encrypted_password

class PasswordManager:
    def _init_(self, master_password):
        self.master_password = master_password
        self.salt = os.urandom(16)  # Generate a random salt for key derivation

    def derive_key(self):
        kdf = Scrypt(
            salt=self.salt,
            length=32,
            n=2**14,  # Number of iterations (adjust as needed for security)
            r=8,
            p=1
        )
        return base64.urlsafe_b64encode(kdf.derive(self.master_password.encode()))

    def encrypt_password(self, password):
        key = self.derive_key()
        fernet = Fernet(key)
        encrypted_password = fernet.encrypt(password.encode())
        return encrypted_password

    def decrypt_password(self, encrypted_password):
        key = self.derive_key()
        fernet = Fernet(key)
        decrypted_password = fernet.decrypt(encrypted_password).decode()
        return decrypted_password

class PasswordManagerUI:
    def _init_(self, root):
        self.root = root
        self.root.title("Password Manager")

        self.master_password_label = Label(self.root, text="Enter Master Password:")
        self.master_password_label.pack()

        self.master_password_entry = Entry(self.root, show="*")
        self.master_password_entry.pack()

        self.submit_button = Button(self.root, text="Submit", command=self.submit_master_password)
        self.submit_button.pack()

        # Initialize local password storage (dictionary)
        self.password_storage = {}

    def submit_master_password(self):
        master_password = self.master_password_entry.get()
        if not master_password:
            messagebox.showerror("Error", "Please enter a master password.")
            return

        self.password_manager = PasswordManager(master_password)

        self.root.destroy()
        self.show_password_manager_ui()

    def show_password_manager_ui(self):
        self.main_window = Tk()
        self.main_window.title("Password Manager")

        # Set the size of the main window
        window_width = 800
        window_height = 600
        screen_width = self.main_window.winfo_screenwidth()
        screen_height = self.main_window.winfo_screenheight()
        x_coordinate = (screen_width - window_width) // 2
        y_coordinate = (screen_height - window_height) // 2
        self.main_window.geometry(f"{window_width}x{window_height}+{x_coordinate}+{y_coordinate}")

        self.website_label = Label(self.main_window, text="Website:")
        self.website_label.pack()

        self.website_entry = Entry(self.main_window)
        self.website_entry.pack()

        self.username_label = Label(self.main_window, text="Username:")
        self.username_label.pack()

        self.username_entry = Entry(self.main_window)
        self.username_entry.pack()

        self.password_label = Label(self.main_window, text="Password:")
        self.password_label.pack()

        self.password_entry = Entry(self.main_window, show="*")
        self.password_entry.pack()

        self.save_button = Button(self.main_window, text="Save Password", command=self.save_password)
        self.save_button.pack()

        self.retrieve_button = Button(self.main_window, text="Retrieve Password", command=self.retrieve_password)
        self.retrieve_button.pack()

    def save_password(self):
        website = self.website_entry.get()
        username = self.username_entry.get()
        password = self.password_entry.get()

        if not website or not username or not password:
            messagebox.showerror("Error", "Please fill in all fields.")
            return

        encrypted_password = self.password_manager.encrypt_password(password)
        # Save encrypted password locally
        self.password_storage[(website, username)] = encrypted_password
        messagebox.showinfo("Success", "Password saved successfully.")

    def retrieve_password(self):
        website = self.website_entry.get()
        username = self.username_entry.get()

        if not website or not username:
            messagebox.showerror("Error", "Please fill in Website and Username fields.")
            return

        encrypted_password = self.password_storage.get((website, username))

        if encrypted_password:
            decrypted_password = self.password_manager.decrypt_password(encrypted_password)
            messagebox.showinfo("Password", f"Decrypted Password: {decrypted_password}")
        else:
            messagebox.showerror("Error", "Password not found for the given Website and Username.")

if _name_ == "_main_":
    root = Tk()
    app = PasswordManagerUI(root)
    root.mainloop()
