import tkinter as tk
from tkinter import messagebox
import random
import string
import pyperclip

class PasswordGenerator:
    def __init__(self, master):
        self.master = master
        self.master.title("Password Generator")

        self.length_label = tk.Label(master, text="Password Length:")
        self.length_label.grid(row=0, column=0, padx=10, pady=10)
        self.length_entry = tk.Entry(master)
        self.length_entry.grid(row=0, column=1, padx=10, pady=10)

        self.uppercase_var = tk.IntVar()
        self.uppercase_checkbox = tk.Checkbutton(master, text="Include Uppercase Letters", variable=self.uppercase_var)
        self.uppercase_checkbox.grid(row=1, column=0, columnspan=2, padx=10, pady=5, sticky=tk.W)

        self.lowercase_var = tk.IntVar()
        self.lowercase_checkbox = tk.Checkbutton(master, text="Include Lowercase Letters", variable=self.lowercase_var)
        self.lowercase_checkbox.grid(row=2, column=0, columnspan=2, padx=10, pady=5, sticky=tk.W)

        self.numbers_var = tk.IntVar()
        self.numbers_checkbox = tk.Checkbutton(master, text="Include Numbers", variable=self.numbers_var)
        self.numbers_checkbox.grid(row=3, column=0, columnspan=2, padx=10, pady=5, sticky=tk.W)

        self.symbols_var = tk.IntVar()
        self.symbols_checkbox = tk.Checkbutton(master, text="Include Symbols", variable=self.symbols_var)
        self.symbols_checkbox.grid(row=4, column=0, columnspan=2, padx=10, pady=5, sticky=tk.W)

        self.generate_button = tk.Button(master, text="Generate Password", command=self.generate_password)
        self.generate_button.grid(row=5, column=0, columnspan=2, padx=10, pady=10)

        self.password_label = tk.Label(master, text="")
        self.password_label.grid(row=6, column=0, columnspan=2, padx=10, pady=10)

        self.copy_button = tk.Button(master, text="Copy to Clipboard", command=self.copy_to_clipboard)
        self.copy_button.grid(row=7, column=0, columnspan=2, padx=10, pady=10)

    def generate_password(self):
        try:
            length = int(self.length_entry.get())
            if length <= 0:
                messagebox.showerror("Error", "Password length must be a positive integer.")
                return

            characters = ''
            if self.uppercase_var.get():
                characters += string.ascii_uppercase
            if self.lowercase_var.get():
                characters += string.ascii_lowercase
            if self.numbers_var.get():
                characters += string.digits
            if self.symbols_var.get():
                characters += string.punctuation

            if not characters:
                messagebox.showerror("Error", "Please select at least one character type.")
                return

            password = ''.join(random.choice(characters) for _ in range(length))
            self.password_label.config(text="Generated Password: " + password)
        except ValueError:
            messagebox.showerror("Error", "Invalid input. Please enter a valid integer for password length.")

    def copy_to_clipboard(self):
        password = self.password_label.cget("text")
        if password:
            password = password.split(": ")[1]
            pyperclip.copy(password)
            messagebox.showinfo("Success", "Password copied to clipboard.")

def main():
    root = tk.Tk()
    app = PasswordGenerator(root)
    root.mainloop()

if __name__ == "__main__":
    main()
