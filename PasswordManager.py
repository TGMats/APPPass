# # PasswordManager.py
# from vault.crypto import init_crypto
# from vault.storage import load_vault, save_vault, vault

# # Initialize
# crypto = init_crypto()
# load_vault(crypto)


# print("Vault loaded:", vault)

# # Example usage
# vault.append({"app": "TestApp", "password": "123"})
# save_vault(crypto)
# print("Vault saved!")
##

import tkinter as tk
from tkinter import messagebox

import customtkinter as ctk
from tkinter import messagebox

from cryptography.fernet import Fernet

KEY_FILE = "encryption.key"

import json
import os

DATA_FILE = "vault_data.json"

vault = []
vault_list = None

def generate_key():
    if not os.path.exists(KEY_FILE):
        key = Fernet.generate_key()
        with open(KEY_FILE, "wb") as f:
            f.write(key)
            
def load_key():
    with open(KEY_FILE, "rb") as f:
        return f.read()

generate_key()
fernet = Fernet(load_key())

def load_vault():
    global vault
    if os.path.exists(DATA_FILE):
        with open(DATA_FILE, "rb") as f:
            encrypted = f.read()
        try:
            decrypted = fernet.decrypt(encrypted)
            vault = json.loads(decrypted.decode())
        except:
            vault = []
    else:
        vault = []
        
        
def save_vault():
    data = json.dumps(vault).encode()
    encrypted = fernet.encrypt(data)
  
    with open(DATA_FILE, "wb") as f:
        f.write(encrypted)
    
    
    # with open(DATA_FILE, "w") as f:
    #     json.dump(vault, f, indent=4)
        
def refresh_vault_list():
    vault_list.delete(0, ctk.END)
    for item in vault:
        vault_list.insert(ctk.END, item["app"])
    

ctk.set_appearance_mode("light")
ctk.set_default_color_theme("blue")

    
# Create the main window
root = ctk.CTk()
load_vault()
root.title("Password Manager")
root.geometry("400x300")

# The master password we'll use for now (later we'll store this securely)
MASTER_PASSWORD = "1234"

  
def add_entry():
    popup = ctk.CTkToplevel(root)
    popup.title("Add New Entry")
    #popup.geometry("300x200")
    popup.grab_set()
    popup.focus()
    popup.lift()
    popup.attributes("-topmost", True)
    popup.after(10, lambda: popup.attributes("-topmost", False))
    
    ctk.CTkLabel(popup, text="App Name:").pack()
    app_entry = ctk.CTkEntry(popup)
    app_entry.pack()
    
    ctk.CTkLabel(popup,text="Password:").pack()
    password_entry = ctk.CTkEntry(popup)
    password_entry.pack()
    
    def save_entry():
        app = app_entry.get()
        password = password_entry.get()
        vault.append({"app": app, "password": password})
        vault_list.insert(ctk.END, app)
        save_vault()
        popup.destroy()
  
    
    #root.bind('<Return>', lambda event: save_entry())
    
    ctk.CTkButton(popup,text="Save", command=save_entry).pack(pady=10)
    
def show_item(event):
    selection = vault_list.curselection()
    if not selection:
        return
    
    index = selection[0]
    entry = vault[index]
    
    popup = tk.Toplevel(root)
    popup.resizable(False, True)
    popup.title(entry["app"])
    #popup.geometry("400x200")
    
    popup.grab_set()
    popup.focus()
    popup.lift()
    popup.attributes("-topmost", True)
    popup.after(10, lambda: popup.attributes("-topmost", False))
    
    app_label = ctk.CTkLabel(popup,text=f"App: {entry['app']}", font=("Arial", 12, "bold"))
    app_label.pack(pady=10, padx=10)
    
    pass_label = ctk.CTkLabel(popup, text=f"Password: {entry['password']}", font=("Arial", 12))
    pass_label.pack(pady=5, padx=10)
    
    #tk.Button(popup,text="Close", command=popup.destroy).pack(pady=10)
    
    def edit_entry(app_label, pass_label):
        edit_popup = ctk.CTkToplevel(root)
        edit_popup.title("Edit Entry")
        #edit_popup.geometry("400x200")
        edit_popup.title(f"Editing {entry['app']}")
        edit_popup.grab_set()
        edit_popup.focus()
        edit_popup.lift()
        edit_popup.attributes("-topmost", True)
        edit_popup.after(10, lambda: edit_popup.attributes("-topmost", False))
        
       
        def edit_name():
            editName_popup = ctk.CTkToplevel(root)
            editName_popup.title(f"Editing {entry['app']}'s name")
            #editName_popup.geometry("300x100")
            editName_popup.grab_set()
            editName_popup.focus()
            editName_popup.lift()
            editName_popup.attributes("-topmost", True)
            editName_popup.after(10, lambda: editName_popup.attributes("-topmost", False))
            
            ctk.CTkLabel(editName_popup, text="Enter the new name", font=("Arial", 12, "bold")).pack(pady=10)
            name_entry = ctk.CTkEntry(editName_popup)
            name_entry.pack()
                       
            
            def save_name():
                entry["app"] = name_entry.get()
                save_vault()
                refresh_vault_list()
                
                app_label.configure(text=f"App: {entry['app']}")
                
                edit_popup.title(f"Editing {entry['app']}")
                editName_popup.destroy()
                edit_popup.destroy()
                
                
        
            ctk.CTkButton(editName_popup, text="Save", command=save_name).pack(pady=10)
        
        def edit_password():
            editPass_popup = ctk.CTkToplevel(root)
            editPass_popup.title(f"Editing {entry['app']}'s password")
            #editPass_popup.geometry("300x100")
            editPass_popup.grab_set()
            editPass_popup.focus()
            editPass_popup.lift()
            editPass_popup.attributes("-topmost", True)
            editPass_popup.after(10, lambda: editPass_popup.attributes("-topmost", False))
            
            ctk.CTkLabel(editPass_popup, text="Enter the new password", font=("Arial", 12, "bold")).pack(pady=10)           
            pass_entry = ctk.CTkEntry(editPass_popup)
            pass_entry.pack()
            
            def save_pass():
                entry["password"] = pass_entry.get()
                save_vault()
                refresh_vault_list()
                
                pass_label.config(text=f"Password: {entry['password']}")
                
                
                editPass_popup.destroy()
                edit_popup.destroy()
            
            ctk.CTkButton(editPass_popup, text="Save", command=save_pass).pack(pady=10)
            
            
            
        ctk.CTkButton(edit_popup,text="Edit Name", command=edit_name).pack(pady=5)
        ctk.CTkButton(edit_popup,text="Edit Password", command=edit_password).pack(pady=5)
    
    def copy_password():       
        root.clipboard_clear()
        root.clipboard_append(entry["password"])
        
        # Create floating tooltip label
        feedback = ctk.CTkLabel(
            popup,
            text="Copied!",
            text_color="green",
            fg_color="transparent",  
            )
        feedback.pack(pady=5)
        # Position it above the Copy button
        copy_btn_x = popup.winfo_width() // 2 - 25  # center roughly
        copy_btn_y = 100  # adjust vertical position above button
        feedback.place(x=copy_btn_x, y=copy_btn_y)
        
        # Destroy after 1 second
        popup.after(1000, feedback.destroy)
    
    
    ctk.CTkButton(popup, text="Edit", command=lambda: edit_entry(app_label, pass_label)).pack(pady=5)    
    ctk.CTkButton(popup, text="Copy password", command=copy_password).pack(pady=5)
    ctk.CTkButton(popup, text="Close", command=popup.destroy).pack(pady=10)
    

def unlock():
    global vault_list
    entered = password_entry.get()
    if entered == MASTER_PASSWORD:
        for widget in root.winfo_children():
            widget.destroy()

        vault_label = ctk.CTkLabel(root, text="Welcome to your vault!", font=("Arial", 17, "bold"))
        vault_label.pack(pady=20, padx=20)

        add_button = ctk.CTkButton(root, text="Add New Entry", command=add_entry, font=("Arial", 14))
        add_button.pack(pady=10,padx=10)
        
        frame = ctk.CTkFrame(root)
        frame.pack(fill="both", expand=True, padx=10, pady=10)
        
        vault_list = tk.Listbox(frame, font=("Arial", 14))
        vault_list.pack(fill="both", expand=True)
        
        vault_list.bind("<Double-Button-1>", show_item)
        
        for entry in vault:
            vault_list.insert(tk.END, entry["app"])
    else:
        messagebox.showerror("Error", "Incorrect password!")

# Label and entry field
label = ctk.CTkLabel(root, text="Enter master password:", font=("Arial", 17, "bold"))
label.pack(pady=10, padx=10)

password_entry = ctk.CTkEntry(root, show="*")
password_entry.pack(pady=5,padx=5)

root.bind('<Return>', lambda event: unlock())

unlock_button = ctk.CTkButton(root, text="Unlock", command=unlock)
unlock_button.pack(pady=10)

root.mainloop()
