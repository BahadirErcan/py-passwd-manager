import random
import sqlite3
import re
import sys
try:
    import pyperclip
except ImportError:
    pyperclip = None

from cryptography.fernet import Fernet

# Encryption key
key = b'1vLzdP1hvR8sSHFcpELoyq9HnuUL4_clqD2CEfJF6oY='
fernet = Fernet(key)

randpasschars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890:;!?@_-()"

def init_db():
    conn = sqlite3.connect('passwords.db')
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS passwords (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            account_name TEXT UNIQUE,
            password TEXT
        )
    ''')
    conn.commit()
    return conn

def encrypt(password):
    return fernet.encrypt(password.encode()).decode()

def decrypt(encrypted_password):
    return fernet.decrypt(encrypted_password.encode()).decode()

def save_password(conn, account_name, password):
    if not check_password_strength(password):
        print("WARNING: Your password is weak! It is recommended to choose a strong password.")
    c = conn.cursor()
    encrypted_password = encrypt(password)
    try:
        c.execute('INSERT INTO passwords (account_name, password) VALUES (?, ?)', (account_name, encrypted_password))
        conn.commit()
        print("Your password has been saved!")
    except sqlite3.IntegrityError:
        print(f"The account '{account_name}' is already registered. Use the update option to update it.")

def show_passwords(conn):
    c = conn.cursor()
    c.execute('SELECT account_name, password FROM passwords')
    records = c.fetchall()
    if not records:
        print("No saved passwords found.")
        return
    print("Saved Passwords:")
    for account_name, encrypted_password in records:
        try:
            password = decrypt(encrypted_password)
        except Exception:
            password = "<Decryption error>"
        print(f"{account_name} : {password}")
    if pyperclip:
        selection = input("Enter the account name to copy the password to clipboard (or press Enter to skip): ").strip()
        if selection:
            password = get_password(conn, selection)
            if password is not None:
                pyperclip.copy(password)
                print(f"The password for the account '{selection}' has been copied to the clipboard.")
            else:
                print(f"The account '{selection}' was not found.")
    else:
        print("Note: The pyperclip module is not installed, clipboard copying feature cannot be used.")

def get_password(conn, account_name):
    c = conn.cursor()
    c.execute('SELECT password FROM passwords WHERE account_name=?', (account_name,))
    record = c.fetchone()
    if record:
        try:
            return decrypt(record[0])
        except Exception:
            return None
    else:
        return None

def generate_password(length):
    if length > len(randpasschars):
        print(f"You can select a maximum of {len(randpasschars)} characters. Default length set to 12.")
        length = 12
    password = "".join(random.sample(randpasschars, length))
    print(f"Generated password: {password}")
    if pyperclip:
        pyperclip.copy(password)
        print("Password copied to clipboard.")
    return password

def delete_password(conn, account_name):
    c = conn.cursor()
    c.execute('SELECT * FROM passwords WHERE account_name = ?', (account_name,))
    if c.fetchone() is None:
        print(f"The account '{account_name}' was not found.")
        return
    confirm = input(f"Are you sure you want to delete the account '{account_name}'? (Y/N): ").strip().lower()
    if confirm == 'y':
        c.execute('DELETE FROM passwords WHERE account_name = ?', (account_name,))
        conn.commit()
        print(f"The account '{account_name}' has been deleted.")
    else:
        print("Delete operation canceled.")

def update_password(conn, account_name, new_password):
    if not check_password_strength(new_password):
        print("WARNING: Your new password is weak! It is recommended to choose a strong password.")
    c = conn.cursor()
    c.execute('SELECT * FROM passwords WHERE account_name = ?', (account_name,))
    if c.fetchone() is None:
        print(f"The account '{account_name}' was not found.")
        return
    encrypted_password = encrypt(new_password)
    c.execute('UPDATE passwords SET password = ? WHERE account_name = ?', (encrypted_password, account_name))
    conn.commit()
    print(f"The password for the account '{account_name}' has been updated.")

def check_password_strength(password):
    if len(password) < 8:
        return False
    if not re.search(r'[A-Z]', password):
        return False
    if not re.search(r'[a-z]', password):
        return False
    if not re.search(r'[0-9]', password):
        return False
    if not re.search(r'[!@#\$%\^&\*\(\)_\-\+=\[\]\{\};:\'",<>\./\?\\\|]', password):
        return False
    return True

def search_password(conn, query):
    c = conn.cursor()
    c.execute("SELECT account_name FROM passwords WHERE account_name LIKE ?", ('%'+query+'%',))
    results = c.fetchall()
    if not results:
        print("No accounts found matching your search.")
        return []
    print("Search results:")
    for i, (account_name,) in enumerate(results, 1):
        print(f"{i}. {account_name}")
    return [account_name for (account_name,) in results]

def export_passwords(conn, file_name):
    c = conn.cursor()
    c.execute('SELECT account_name, password FROM passwords')
    all_records = c.fetchall()
    if not all_records:
        print("No passwords to export.")
        return
    with open(file_name, 'w', encoding='utf-8') as f:
        for account_name, encrypted_password in all_records:
            f.write(f"{account_name}:{encrypted_password}\n")
    print(f"All passwords have been exported to '{file_name}'.")

def import_passwords(conn, file_name):
    try:
        with open(file_name, 'r', encoding='utf-8') as f:
            lines = f.readlines()
    except FileNotFoundError:
        print(f"The file '{file_name}' was not found.")
        return
    c = conn.cursor()
    added = 0
    for line in lines:
        if ':' not in line:
            continue
        account_name, encrypted_password = line.strip().split(':', 1)
        c.execute('SELECT * FROM passwords WHERE account_name = ?', (account_name,))
        if c.fetchone():
            continue 
        c.execute('INSERT INTO passwords (account_name, password) VALUES (?, ?)', (account_name, encrypted_password))
        added += 1
    conn.commit()
    print(f"{added} passwords have been imported into the database.")

def main():
    conn = init_db()
    while True:
        print("""
[1] Save password
[2] Generate and save password
[3] Show saved passwords
[4] Delete password
[5] Update password
[6] Search password
[7] Export passwords
[8] Import passwords
[0] Exit
""")
        try:
            operation = int(input("Enter the operation: "))
        except ValueError:
            print("Please enter a valid number.")
            continue

        if operation == 1:
            account_name = input("Account name: ")
            password = input("Password: ")
            save_password(conn, account_name, password)

        elif operation == 2:
            account_name = input("Account name: ")
            try:
                length = int(input(f"Password length (maximum {len(randpasschars)}): "))
            except ValueError:
                print("Please enter a valid number. Default length of 12 will be used.")
                length = 12
            password = generate_password(length)
            save_password(conn, account_name, password)

        elif operation == 3:
            show_passwords(conn)

        elif operation == 4:
            account_name = input("Account name to delete: ")
            delete_password(conn, account_name)

        elif operation == 5:
            account_name = input("Account name to update: ")
            new_password = input("New password: ")
            update_password(conn, account_name, new_password)

        elif operation == 6:
            query = input("Search term (within account name): ").strip()
            search_password(conn, query)

        elif operation == 7:
            file_name = input("File name to export to (e.g., backup.txt): ").strip()
            export_passwords(conn, file_name)

        elif operation == 8:
            file_name = input("File name to import from (e.g., backup.txt): ").strip()
            import_passwords(conn, file_name)

        elif operation == 0:
            print("Exiting...")
            break

        else:
            print("Invalid operation selection.")

    conn.close()

if __name__ == '__main__':
    main()
