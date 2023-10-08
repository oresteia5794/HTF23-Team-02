import random
import string

def generate_password():
    # Define the character sets
    uppercase_letters = string.ascii_uppercase
    lowercase_letters = string.ascii_lowercase
    digits = string.digits
    special_characters = "!@#$%&"
    
    # Ensure at least 2 characters from each category
    password = [random.choice(uppercase_letters) for _ in range(2)]
    password += [random.choice(digits) for _ in range(2)]
    password += [random.choice(special_characters) for _ in range(2)]
    
    # Fill the rest of the password with random characters
    remaining_length = max(0, 10 - len(password))
    all_characters = uppercase_letters + lowercase_letters + digits + special_characters
    password += [random.choice(all_characters) for _ in range(remaining_length)]
    
    # Shuffle the password to randomize the characters
    random.shuffle(password)
    
    # Convert the list of characters to a string and return
    return ''.join(password)

# Generate and print a random password
random_password = generate_password()
print("Random Password:", random_password)
