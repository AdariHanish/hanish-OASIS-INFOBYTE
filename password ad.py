import tkinter as tk
from tkinter import messagebox
import random
import string
class PasswordGenerator:
    def __init__(self, master):
        self.master = master
        master.title("Random Password Generator")

        self.length_label = tk.Label(master, text="Password Length:")
        self.length_label.pack()

        self.length_entry = tk.Entry(master, width=5)
        self.length_entry.pack()

        self.char_set_frame = tk.Frame(master)
        self.char_set_frame.pack()

        self.uppercase_var = tk.IntVar()
        self.lowercase_var = tk.IntVar()
        self.numbers_var = tk.IntVar()
        self.symbols_var = tk.IntVar()

        self.uppercase_checkbox = tk.Checkbutton(self.char_set_frame, text="Uppercase Letters", variable=self.uppercase_var)
        self.uppercase_checkbox.pack(side=tk.LEFT)

        self.lowercase_checkbox = tk.Checkbutton(self.char_set_frame, text="Lowercase Letters", variable=self.lowercase_var)
        self.lowercase_checkbox.pack(side=tk.LEFT)

        self.numbers_checkbox = tk.Checkbutton(self.char_set_frame, text="Numbers", variable=self.numbers_var)
        self.numbers_checkbox.pack(side=tk.LEFT)

        self.symbols_checkbox = tk.Checkbutton(self.char_set_frame, text="Symbols", variable=self.symbols_var)
        self.symbols_checkbox.pack(side=tk.LEFT)

        self.generate_button = tk.Button(master, text="Generate Password", command=self.generate_password)
        self.generate_button.pack()

        self.password_label = tk.Label(master, text="Generated Password:")
        self.password_label.pack()

        self.password_entry = tk.Entry(master, width=40)
        self.password_entry.pack()

        self.copy_button = tk.Button(master, text="Copy to Clipboard", command=self.copy_to_clipboard)
        self.copy_button.pack()

    def generate_password(self):
        length = int(self.length_entry.get())
        char_set = ''

        if self.uppercase_var.get():
            char_set += string.ascii_uppercase
        if self.lowercase_var.get():
            char_set += string.ascii_lowercase
        if self.numbers_var.get():
            char_set += string.digits
        if self.symbols_var.get():
            char_set += string.punctuation

        if not char_set:
            messagebox.showerror("Error", "You must select at least one character set.")
            return

        password = ''.join(random.choice(char_set) for _ in range(length))
        self.password_entry.delete(0, tk.END)
        self.password_entry.insert(0, password)

    def copy_to_clipboard(self):
        password = self.password_entry.get()
        pyperclip.copy(password)
        messagebox.showinfo("Success", "Password copied to clipboard.")

root = tk.Tk()
my_gui = PasswordGenerator(root)
root.mainloop()
import pyperclip #type:ignore