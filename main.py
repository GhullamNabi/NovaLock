import tkinter as tk
from tkinterdnd2 import DND_FILES, TkinterDnD
from tkinter import ttk, filedialog, messagebox
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64
import os
import secrets
import webbrowser

# Modern color scheme
COLORS = {
    "background": "#2d3436",
    "primary": "#6c5ce7",
    "secondary": "#a29bfe",
    "danger": "#d63031",
    "success": "#00b894",
    "text": "#dfe6e9",
    "entry_bg": "#636e72",
    "highlight": "#0984e3"
}

# Improved key generation with PBKDF2 and random salt
def generate_key(password, salt=None):
    if salt is None:
        salt = secrets.token_bytes(16)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=390000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    return key, salt

# Enhanced file operations
def lock_file(filepath, password):
    try:
        if not os.path.exists(filepath):
            messagebox.showerror("Error", "File does not exist.")
            return False

        salt = secrets.token_bytes(16)
        key, salt = generate_key(password, salt)
        fernet = Fernet(key)

        with open(filepath, 'rb') as file:
            original = file.read()

        encrypted = fernet.encrypt(original)

        # Save with .novasafe extension and include salt
        locked_path = filepath + '.novasafe'
        with open(locked_path, 'wb') as encrypted_file:
            encrypted_file.write(salt + encrypted)

        os.remove(filepath)  # Remove original file after successful encryption
        return locked_path
    except Exception as e:
        messagebox.showerror("Error", f"Failed to lock file: {str(e)}")
        return None

def unlock_file(filepath, password):
    try:
        if not os.path.exists(filepath):
            messagebox.showerror("Error", "File does not exist.")
            return False

        with open(filepath, 'rb') as encrypted_file:
            data = encrypted_file.read()

        salt = data[:16]  # Extract salt from beginning of file
        encrypted = data[16:]
        
        key, _ = generate_key(password, salt)
        fernet = Fernet(key)

        decrypted = fernet.decrypt(encrypted)

        # Remove .novasafe extension if present
        unlocked_path = filepath[:-8] if filepath.endswith('.novasafe') else filepath
        with open(unlocked_path, 'wb') as decrypted_file:
            decrypted_file.write(decrypted)

        os.remove(filepath)  # Remove encrypted file after successful decryption
        return unlocked_path
    except Exception as e:
        messagebox.showerror("Error", f"Failed to unlock file: {str(e)}")
        return None

# Modern UI with ttk widgets
class NovaSafeApp:
    def __init__(self, root):
        self.root = root
        self.setup_ui()
        
    def setup_ui(self):
        self.root.title("🔐 NovaSafe - Secure File Locker")
        self.root.geometry("500x400")
        self.root.resizable(False, False)
        self.root.configure(bg=COLORS["background"])
        
        # Set window icon (comment out if no icon file)
        try:
            self.root.iconbitmap("ico.ico")
        except:
            pass
        
        # Main container
        main_frame = ttk.Frame(self.root, padding="20")
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Header
        header = ttk.Label(
            main_frame,
            text="NovaSafe",
            font=("Segoe UI", 24, "bold"),
            foreground=COLORS["primary"],
            background=COLORS["background"]
        )
        header.pack(pady=(0, 20))
        
        # File selection
        file_frame = ttk.LabelFrame(main_frame, text="📁 File Selection", padding=10)
        file_frame.pack(fill=tk.X, pady=5)
        
        self.filepath = tk.StringVar()
        file_entry = ttk.Entry(
            file_frame,
            textvariable=self.filepath,
            font=("Segoe UI", 10),
            width=40
        )
        file_entry.pack(side=tk.LEFT, padx=5)
        
        browse_btn = ttk.Button(
            file_frame,
            text="Browse",
            command=self.browse_file,
            style="Accent.TButton"
        )
        browse_btn.pack(side=tk.RIGHT)
        
        # Password entry
        pass_frame = ttk.LabelFrame(main_frame, text="🔑 Password", padding=10)
        pass_frame.pack(fill=tk.X, pady=5)
        
        self.password_entry = ttk.Entry(
            pass_frame,
            show="•",
            font=("Segoe UI", 10)
        )
        self.password_entry.pack(fill=tk.X, padx=5)
        
        # Action buttons
        btn_frame = ttk.Frame(main_frame)
        btn_frame.pack(pady=20)
        
        lock_btn = ttk.Button(
            btn_frame,
            text="🔒 Lock File",
            command=self.lock_action,
            style="Danger.TButton",
            width=15
        )
        lock_btn.pack(side=tk.LEFT, padx=10)
        
        unlock_btn = ttk.Button(
            btn_frame,
            text="🔓 Unlock File",
            command=self.unlock_action,
            style="Success.TButton",
            width=15
        )
        unlock_btn.pack(side=tk.RIGHT, padx=10)
        
        # Drag and drop hint
        drop_hint = ttk.Label(
            main_frame,
            text="✨ Tip: You can also drag and drop files here!",
            font=("Segoe UI", 9, "italic"),
            foreground=COLORS["secondary"],
            background=COLORS["background"]
        )
        drop_hint.pack(pady=(20, 0))
        
        # Footer
        footer = ttk.Label(
            main_frame,
            text="NovaSafe v1.0 · Secure File Encryption",
            font=("Segoe UI", 8),
            foreground=COLORS["text"],
            background=COLORS["background"]
        )
        footer.pack(side=tk.BOTTOM, pady=(20, 0))
        
        # Configure styles
        self.configure_styles()
        
        # Set up drag and drop
        self.setup_drag_drop()
    
    def configure_styles(self):
        style = ttk.Style()
        style.theme_use('clam')
        
        # Background colors
        style.configure('.', background=COLORS["background"], foreground=COLORS["text"])
        style.configure('TLabelFrame', background=COLORS["background"], bordercolor=COLORS["secondary"])
        style.configure('TLabelFrame.Label', background=COLORS["background"], foreground=COLORS["secondary"])
        
        # Buttons
        style.configure('TButton', font=("Segoe UI", 10), padding=6)
        style.configure('Accent.TButton', background=COLORS["primary"], foreground="white")
        style.configure('Danger.TButton', background=COLORS["danger"], foreground="white")
        style.configure('Success.TButton', background=COLORS["success"], foreground="white")
        
        # Entry
        style.configure('TEntry', fieldbackground=COLORS["entry_bg"], foreground=COLORS["text"])
    
    def setup_drag_drop(self):
        def handle_drop(event):
            if event.data:
                files = self.root.tk.splitlist(event.data)
                if files:
                    self.filepath.set(files[0])
        
        self.root.drop_target_register(tk.DND_FILES)
        self.root.dnd_bind('<<Drop>>', handle_drop)
    
    def browse_file(self):
        filename = filedialog.askopenfilename()
        if filename:
            self.filepath.set(filename)
    
    def lock_action(self):
        if self.filepath.get() and self.password_entry.get():
            result = lock_file(self.filepath.get(), self.password_entry.get())
            if result:
                messagebox.showinfo("Success", f"🔒 File locked successfully!\nSaved as: {os.path.basename(result)}")
                self.clear_fields()
        else:
            messagebox.showwarning("Warning", "Please select a file and enter a password.")
    
    def unlock_action(self):
        if self.filepath.get() and self.password_entry.get():
            result = unlock_file(self.filepath.get(), self.password_entry.get())
            if result:
                messagebox.showinfo("Success", f"🔓 File unlocked successfully!\nSaved as: {os.path.basename(result)}")
                self.clear_fields()
        else:
            messagebox.showwarning("Warning", "Please select a file and enter a password.")
    
    def clear_fields(self):
        self.filepath.set("")
        self.password_entry.delete(0, tk.END)

if __name__ == "__main__":
    root = TkinterDnD.Tk()
    app = NovaSafeApp(root)
    root.mainloop()