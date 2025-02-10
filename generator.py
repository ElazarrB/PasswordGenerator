import re
import Levenshtein
from termcolor import colored
import random
import string

class NoError(Exception):
    pass    

class PasswordChecker:

    def __init__(self):
        pass

    @staticmethod
    def check_weak_password():
        while True:
            password = input("\nPlease enter a password to check (or type 'exit' to stop): ")
            if password.lower() == 'exit':
                print("Exiting password checking.")
                break

            weaknesses = PasswordChecker.evaluate_password(password)

            if weaknesses:
                for weakness in weaknesses:
                    print(colored(weakness, "red"))
                PasswordChecker.print_password_tips()
            else:
                print(colored("Your password is safe!", "green"))
            
                PasswordChecker.generate_password_prompt()

            
    @staticmethod
    def evaluate_password(password):
        weaknesses = []

        if len(password) < 8:
            weaknesses.append("Password length is less than 8.")
        if not re.search(r'[a-z]', password):
            weaknesses.append("Password must contain at least one lowercase letter.")
        if not re.search(r'[A-Z]', password):
            weaknesses.append("Password must contain at least one uppercase letter.")
        if not re.search(r'[0-9]', password):
            weaknesses.append("Password must contain at least one number.")
        if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
            weaknesses.append("Password must contain at least one special character.")

        weaknesses += PasswordChecker.is_password_in_breachdb(password)
        
        return weaknesses
    
    @staticmethod
    def generate_password_prompt():
        gen_password = input("\nWould you like to generate a strong password? (Y/y)/(N/n): ")

        if gen_password.lower() == 'y':
            while True:
                number = input("How many passwords? (Type 'exit' to stop): ")

                if number.lower() == 'exit':
                    print("Exiting password generation.")
                    break

                if number.isnumeric():
                    passwords = PasswordChecker.generate_password(int(number))
                    for password in passwords:
                        print(colored(password, "green"))
                else:
                    print("Invalid input. Please enter a valid number or type 'exit' to stop.")
    
    @staticmethod
    def generate_password(number_of_passwords=1):
        length = 12
        uppercase = string.ascii_uppercase
        lowercase = string.ascii_lowercase
        digits = string.digits
        special_chars = "!@#$%^&*()-_=+<>?/|~"
        all_characters = uppercase + lowercase + digits + special_chars

        passwords = []
        for _ in range(number_of_passwords):
            password = [
                random.choice(uppercase),
                random.choice(lowercase),
                random.choice(digits),
                random.choice(special_chars),
            ]
            password += random.choices(all_characters, k=length - 4)
            random.shuffle(password)
            passwords.append(''.join(password))

        return passwords
    
    @staticmethod
    def is_password_in_breachdb(password, breach_file='password_breach.txt'):
        weaknesses = []
        try:
            with open(breach_file, 'r', encoding='utf-8') as file:
                for line in file:
                    breached_password = line.strip()
                    if password == breached_password:
                        weaknesses.append("(ALERT) Found the same password in breach database!")
                    elif Levenshtein.distance(password, breached_password) <= 2:
                        weaknesses.append("(ALERT) Similar password found in breach database!")
        except FileNotFoundError:
            weaknesses.append("(ERROR) Breach database file not found.")
        except Exception as e:
            weaknesses.append(f"(ERROR) An error occurred: {e}")
        return weaknesses

    @staticmethod
    def print_password_tips():
        print("\n💡 Tips for Creating a Strong Password:")
        print("-" * 40)
        print("1. Use at least 12 characters.")
        print("2. Include a mix of uppercase and lowercase letters.")
        print("3. Add numbers (e.g., 0-9) and special characters (e.g., @, #, $, %).")
        print("4. Avoid common words or sequences like 'password', '123456', or 'qwerty'.")
        print("5. Don’t use easily guessable information, such as your name or birthdate.")
        print("6. Use unique passwords for each of your accounts.")
        print("7. Avoid keyboard patterns like 'asdfgh' or 'zxcvbn'.")
        print("8. Use a password manager to generate and store complex passwords.")
        print("9. Consider passphrases made of unrelated words, like 'Blue!River@Sky9'.")
        print("10. Change your passwords regularly, especially for sensitive accounts.")
        print("-" * 40)

if __name__ == "__main__":
    PasswordChecker.check_weak_password()
