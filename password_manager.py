import random
import string
import mysql.connector
import config
import bcrypt
import getpass 
import os

conn = mysql.connector.connect(
    host=config.DB_HOST,
    user=config.DB_USER,
    password=config.DB_PASSWORD,
    database=config.DB_NAME
)

cursor = conn.cursor()

def clear_console():
    if os.name == 'nt':  # For Windows
        os.system('cls')
    else:  # For Unix-like systems (Linux, macOS)
        os.system('clear')

def generate_password(length=12, use_uppercase=True, use_numbers=True, use_special=True):
    lowercase_letters = string.ascii_lowercase
    uppercase_letters = string.ascii_uppercase if use_uppercase else ''
    digits = string.digits if use_numbers else ''
    special_characters = string.punctuation if use_special else ''
    
    all_characters = lowercase_letters + uppercase_letters + digits + special_characters
    
    if not all_characters:
        print("Error: No character sets selected to generate a password.")
        return None

    password = ''.join(random.choice(all_characters) for _ in range(length))
    return password

def hash_password(password):
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(password.encode('utf-8'), salt)
    return hashed

def check_password(plain_password, hashed_password):
    if isinstance(hashed_password, str):
        hashed_password = hashed_password.encode('utf-8')
    return bcrypt.checkpw(plain_password.encode('utf-8'), hashed_password)

def insert_username():
    username = input("\nEnter new Username: ")
    cursor.execute("SELECT username FROM users WHERE username = %s", (username,))
    username_existance = cursor.fetchone()
    if not username_existance:
        password = getpass.getpass("Enter new password: ")
        hashed_password = hash_password(password) 
        cursor.execute("INSERT INTO users (username, password) VALUES (%s, %s)", (username, hashed_password,))
        conn.commit()
        print("Add username success!")
        return
    else:
        print("Username already registered!")        
    

def users_manager():
    while True:
        cursor.execute("SELECT id, username FROM users ORDER BY id")
        users = cursor.fetchall()
        if not users:
            print("\nNo Usernames found!")
        else:
            print("\nUsernames Manager")
            for user in users:
                print(f"{user[0]}. {user[1]}")
        print("\n99. Create new Username")
        print("0. Back")

        try:
            choice = int(input("\nEnter your choice: "))
        except ValueError:
            print("Invalid input! Please enter a number.")
            return
    
        if choice == 99:
            insert_username()
        elif choice == 0:
            return
        elif choice in [user[0] for user in users]:
            cursor.execute("SELECT password FROM users WHERE id = %s", (choice,))
            password = cursor.fetchone()
            while True:
                password_to_check = getpass.getpass("Enter User's Password: ")
                if check_password(password_to_check, password[0]):
                    cursor.execute("SELECT app, app_password FROM passwords WHERE user_id = %s", (choice,))
                    apps = cursor.fetchall()
                    if not apps:
                        print("\nApp Password not Found")
                    else:
                        print("\nPasswords Manager")
                        for index, app in enumerate(apps, start=1):
                            print(f"{index}. {app[0]}: {app[1]}")
                    input("\nPress enter to go back.")
                    return
                else:
                    print("Password doesn't match.")
                    break
        else:
            print("Invalid choice. Please select a valid user ID.")
                
def generate():
    while True:
        cursor.execute("SELECT id, username FROM users ORDER BY id")
        users = cursor.fetchall()
        if not users:
            print("\nNo Usernames found!")
        else:
            print("\nUsernames Manager")
            for user in users:
                print(f"{user[0]}. {user[1]}")
        print("\n0. Back")

        try:
            choice = int(input("\nEnter your choice: "))
        except ValueError:
            print("Invalid input! Please enter a number.")
            return
        
        if choice == 0:
            return
        elif choice in [user[0] for user in users]:
            cursor.execute("SELECT password FROM users WHERE id = %s", (choice,))
            password = cursor.fetchone()
            while True:
                password_to_check = getpass.getpass("Enter User's Password: ")
                if check_password(password_to_check, password[0]):                    
                    try:
                        length = int(input("Enter the desired password length (default is 12): ") or 12)
                    except ValueError:
                        print("Invalid input! Using default length of 12.")
                        length = 12

                    use_uppercase = input("Include uppercase letters? (y/n, default is y): ").lower() != 'n'
                    use_numbers = input("Include numbers? (y/n, default is y): ").lower() != 'n'
                    use_special = input("Include special characters? (y/n, default is y): ").lower() != 'n'
                    while True:
                        password = generate_password(length, use_uppercase, use_numbers, use_special)

                        if password:
                            print(f"\nGenerated Password: {password}")
                            regenerate = input("Generate again? (y/other key, default save): ").lower()
                            if regenerate == 'y':
                                continue
                            else:
                                app = input("\nApplication name: ")
                                cursor.execute("SELECT * FROM passwords WHERE user_id = %s AND app = %s",(choice,app))
                                exist = cursor.fetchall()
                                if exist:
                                    update = input("Password for this App is already registered, Update? (y/other key, default cancel): ").lower()
                                    if update == 'y':
                                        cursor.execute("UPDATE passwords SET app_password = %s WHERE user_id = %s AND app = %s",(password, choice, app))
                                        conn.commit()
                                        input("\nUpdate app password success!")
                                    else:
                                        input("\nCancel add password.")
                                        return
                                else:
                                    cursor.execute("INSERT INTO passwords (user_id, app, app_password) VALUES (%s, %s, %s)",(choice, app, password))
                                    conn.commit()
                                    input("\nAdd app password success!")
                                break
                    
                    return
                else:
                    print("Password doesn't match.")
                    break
        else:
            print("Invalid choice. Please select a valid user ID.")
           
def delete_password():
    while True:
        cursor.execute("SELECT id, username FROM users ORDER BY id")
        users = cursor.fetchall()
        if not users:
            print("\nNo Usernames found!")
        else:
            print("\nUsernames Manager")
            for user in users:
                print(f"{user[0]}. {user[1]}")
        print("\n0. Back")

        try:
            choice = int(input("\nEnter your choice: "))
        except ValueError:
            print("Invalid input! Please enter a number.")
            return
        
        if choice == 0:
            return
        elif choice in [user[0] for user in users]:
            cursor.execute("SELECT password FROM users WHERE id = %s", (choice,))
            password = cursor.fetchone()
            while True:
                password_to_check = getpass.getpass("Enter User's Password: ")
                if check_password(password_to_check, password[0]):
                    cursor.execute("SELECT app, app_password FROM passwords WHERE user_id = %s", (choice,))
                    apps = cursor.fetchall()
                    if not apps:
                        print("\nApp Password not Found")
                    else:
                        print("\nPasswords Manager")
                        for index, app in enumerate(apps, start=1):
                            print(f"{index}. {app[0]}: {app[1]}")
                        print("0. Back")
                    while True:
                        app_choice = input("\nEnter application name (case sensitive): ")

                        if app_choice == '0':
                            return
                        elif app_choice in [app[0] for app in apps]:
                            delete = input("Delete this app's password? (y/other key, default cancel): ").lower()
                            if delete == 'y':
                                cursor.execute("DELETE FROM passwords WHERE user_id = %s AND app = %s",(choice,app_choice))
                                conn.commit()
                                input("\nDelete App Password success!")
                                break
                            else:
                                return
                        else:
                            print("Invalid choice. Please select a valid user ID.")
                            continue
                    
                    return
                else:
                    print("Password doesn't match.")
                    break
        else:
            print("Invalid choice. Please select a valid user ID.")

def display_menu():
    print("\nWelcome to the Password Manager!")
    print("1. Users Manager")
    print("2. Generate a Password")
    print("3. Delete Password")
    print("0. Exit")           
                 
def main():
    while True:
        clear_console()
        display_menu()
        choice = int(input("\nEnter your choice: "))

        if choice == 1:
            users_manager()
        elif choice == 2:
            generate()
        elif choice == 3:
            delete_password()
        elif choice == 0:
            print("Exiting Password Manager. Goodbye!")
            break
        else:
            print("Invalid choice! Please enter a number between 1 and 5.")

if __name__ == "__main__":
    main()