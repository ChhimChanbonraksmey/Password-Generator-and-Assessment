import random
import math
import tkinter as tk
from tkinter import messagebox, simpledialog, Toplevel
import re

common_passwords = {"123456", "password", "123456789", "qwerty", "abc123", "password1", "111111", "iloveyou"}

UPPERCASE_LETTERS = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
LOWERCASE_LETTERS = "abcdefghijklmnopqrstuvwxyz"
DIGITS = "0123456789"
SPECIAL_CHARACTERS = "!@#$%^&*()-_=+[]{};:,.<>?/|`~"

def custom_random_choice(sequence):
    index = int(random.random() * len(sequence))
    return sequence[index]

def calculate_entropy(password):
    char_pool = 0
    if any(c in LOWERCASE_LETTERS for c in password):
        char_pool += len(LOWERCASE_LETTERS)
    if any(c in UPPERCASE_LETTERS for c in password):
        char_pool += len(UPPERCASE_LETTERS)
    if any(c in DIGITS for c in password):
        char_pool += len(DIGITS)
    if any(c in SPECIAL_CHARACTERS for c in password):
        char_pool += len(SPECIAL_CHARACTERS)
    
    entropy = len(password) * math.log2(char_pool) if char_pool > 0 else 0
    return entropy

def evaluate_strength(password):
    if password in common_passwords:
        return 25, "red", "Weak"

    entropy = calculate_entropy(password)
    if len(password) < 8 or entropy < 28:
        return 25, "red", "Weak"
    elif 28 <= entropy < 50:
        return 50, "orange", "Moderately Good"
    elif entropy < 60:
        return 75, "blue", "Strong"
    else:
        return 100, "green", "Very Strong"

def generate_password(length=12, use_uppercase=True, use_lowercase=True, use_digits=True, use_special=True):
    pools = []
    if use_uppercase:
        pools.append(UPPERCASE_LETTERS)
    if use_lowercase:
        pools.append(LOWERCASE_LETTERS)
    if use_digits:
        pools.append(DIGITS)
    if use_special:
        pools.append(SPECIAL_CHARACTERS)

    if not pools:
        return ""  

    password = [custom_random_choice(pool) for pool in pools]

    all_characters = ''.join(pools)
    remaining_length = length - len(password)
    if remaining_length > 0:
        password += random.sample(all_characters * (remaining_length // len(all_characters) + 1), remaining_length)

    random.shuffle(password)
    return ''.join(password)

def on_generate_password():
    try:
        length_input = length_var.get().strip()

        if not length_input:
            raise ValueError("Invalid Input! Password length is empty. Please enter a positive integer.")

        try:
            length = int(length_input)
        except ValueError:
            raise ValueError("Invalid Input! Password length must only be entered as a positive integer.")

        if length <= 0:
            raise ValueError("Invalid Input! Password length must be a positive integer greater than zero.")

        use_uppercase = uppercase_var.get()
        use_lowercase = lowercase_var.get()
        use_digits = digits_var.get()
        use_special = special_var.get()
        
        if not use_digits or (not use_uppercase and not use_lowercase and not use_special):
            raise ValueError("Invalid Input! Please select 'Include Digits' and at least one other character type.")

        password = generate_password(length, use_uppercase, use_lowercase, use_digits, use_special)
        if password:
            password_display_var.set(password)
            update_strength_meter(password, strength_meter_canvas, strength_label_var)
    except ValueError as ve:
        messagebox.showerror("Invalid Input!", str(ve))
    except Exception as e:
        messagebox.showerror("Error", f"Invalid Input! An unexpected error occurred: {str(e)}")

def copy_to_clipboard():
    password = password_display_var.get()
    if password:
        root.clipboard_clear()
        root.clipboard_append(password)
        messagebox.showinfo("Copied", "Password copied to clipboard!")
    else:
        messagebox.showwarning("Copy Error", "Invalid Input! No password to copy.")

def update_strength_meter(password, canvas, label_var):
    """Update the strength meter bar and label based on password strength."""
    strength, color, label = evaluate_strength(password)
    
    canvas.delete("meter")
    canvas.create_rectangle(0, 0, strength * 2, 20, fill=color, tags="meter")

    label_var.set(f"Password Strength: {label}")

def suggest_improvements(password):
    suggestions = []
    if len(password) < 8:
        suggestions.append("Increase length to at least 8 characters.")
    if not any(c in UPPERCASE_LETTERS for c in password):
        suggestions.append("Add uppercase letters.")
    if not any(c in LOWERCASE_LETTERS for c in password):
        suggestions.append("Add lowercase letters.")
    if not any(c in DIGITS for c in password):
        suggestions.append("Add digits.")
    if not any(c in SPECIAL_CHARACTERS for c in password):
        suggestions.append("Add special characters.")
    return suggestions

def detect_patterns(password):
    patterns = []
    if re.search(r'(.)\1\1', password):
        patterns.append("Avoid repeated characters (e.g., 'aaa').")
    if re.search(r'012|123|234|345|456|567|678|789', password):
        patterns.append("Avoid sequences (e.g., '123').")
    if len(set(password)) < len(password) / 2:
        patterns.append("Increase character variety.")
    return patterns

def on_test_password():
    password = simpledialog.askstring("Password Test", "Enter the password to test:")
    if password:
        test_password_window(password)
    else:
        messagebox.showerror("Invalid Input!", "Invalid Input! No password entered to test.")

def test_password_window(password):
    window = Toplevel(root)
    window.title("Password Strength Test")
    window.geometry("300x400")

    tk.Label(window, text="Entered Password:").pack(anchor="w", pady=(10, 0))
    password_display = tk.Entry(window, width=50)
    password_display.insert(0, password)
    password_display.pack()
    password_display.config(state="readonly")

    strength_label_var = tk.StringVar(value="Password Strength: ")
    strength_label = tk.Label(window, textvariable=strength_label_var)
    strength_label.pack(anchor="w", pady=(10, 0))

    strength_meter_canvas = tk.Canvas(window, width=200, height=20, bg="lightgrey")
    strength_meter_canvas.pack()

    update_strength_meter(password, strength_meter_canvas, strength_label_var)

    pattern_warnings = detect_patterns(password)
    if pattern_warnings:
        tk.Label(window, text="Pattern Warnings:", fg="red").pack(anchor="w", pady=(10, 0))
        for warning in pattern_warnings:
            tk.Label(window, text="- " + warning, fg="red").pack(anchor="w")

    suggestions = suggest_improvements(password)
    if suggestions:
        tk.Label(window, text="Suggestions for Improvement:", fg="blue").pack(anchor="w", pady=(10, 0))
        for suggestion in suggestions:
            tk.Label(window, text="- " + suggestion, fg="blue").pack(anchor="w")

    if password in common_passwords:
        tk.Label(window, text="This password is commonly used and is not secure!", fg="red").pack(anchor="w", pady=(10, 0))

root = tk.Tk()
root.title("Password Generator and Assessment App")

length_var = tk.StringVar(value="12")
uppercase_var = tk.BooleanVar(value=True)
lowercase_var = tk.BooleanVar(value=True)
digits_var = tk.BooleanVar(value=True)
special_var = tk.BooleanVar(value=True)
password_display_var = tk.StringVar(value="")
strength_label_var = tk.StringVar(value="Password Strength: ")

tk.Label(root, text="Password Generator and Assessment", font=("Helvetica", 16)).pack(pady=10)

tk.Label(root, text="Password Length:").pack(anchor="w")
tk.Entry(root, textvariable=length_var).pack(anchor="w")

tk.Checkbutton(root, text="Include Uppercase Letters", variable=uppercase_var).pack(anchor="w")
tk.Checkbutton(root, text="Include Lowercase Letters", variable=lowercase_var).pack(anchor="w")
tk.Checkbutton(root, text="Include Digits", variable=digits_var).pack(anchor="w")
tk.Checkbutton(root, text="Include Special Characters", variable=special_var).pack(anchor="w")

tk.Button(root, text="Generate Password", command=on_generate_password).pack(pady=10)
tk.Entry(root, textvariable=password_display_var, state="readonly", width=50).pack()
tk.Button(root, text="Copy to Clipboard", command=copy_to_clipboard).pack(pady=5)

strength_label = tk.Label(root, textvariable=strength_label_var)
strength_label.pack(anchor="w", pady=(10, 0))
strength_meter_canvas = tk.Canvas(root, width=200, height=20, bg="lightgrey")
strength_meter_canvas.pack()

tk.Button(root, text="Test Password Strength", command=on_test_password).pack(pady=10)

root.mainloop()