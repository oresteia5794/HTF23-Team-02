import string
import math

# AFFINE 
DIE = 95  # Number of characters in the printable ASCII range (32 to 126)

def aff_gcd(a, b):
    while b != 0:
        a, b = b, a % b
    return a

def aff_mod_inverse(a, m):
    for i in range(1, m):
        if (a * i) % m == 1:
            return i
    return None

def aff_generate_key():
    # Generate random coprime values for the key (a, b)
    a = 29
    while aff_gcd(a, DIE) != 1:
        a = 29
    b = 83
    return a, b
def aff_encrypt(plaintext, key):
    a, b = key
    aff_ciphertext = ""
    for char in plaintext:
        if char.isprintable():  # Check if the character is printable
            char_index = ord(char) - 32  # Shift to 0 to DIE-1 range
            encrypted_char = (a * char_index + b) % DIE
            aff_ciphertext += chr(encrypted_char + 32)  # Shift back to printable ASCII range
        else:
            aff_ciphertext += char  # Preserve non-printable characters
    return aff_ciphertext

def aff_decrypt(aff_ciphertext, key):
    a, b = key
    a_inverse = aff_mod_inverse(a, DIE)
    if a_inverse is not None:
        aff_plaintext = ""
        for char in aff_ciphertext:
            if char.isprintable():
                char_index = (ord(char) - 32)  # Shift to 0 to DIE-1 range
                decrypted_char = (a_inverse * (char_index - b)) % DIE  # Decrypt
                aff_plaintext += chr(decrypted_char + 32)  # Shift back to printable ASCII range
            else:
                aff_plaintext += char  # Preserve non-printable characters
        return aff_plaintext
    else:
        print("Error: Invalid 'a' value. 'a' must be coprime with the character set size.")
        return aff_ciphertext

# CAESAR
def caesar_encrypt(text, shift):
    encrypted_text = ""
    for char in text:
        if char.isprintable():
            shifted_char = chr((ord(char) + shift - ord(' ')) % DIE + ord(' '))
            encrypted_text += shifted_char
        else:
            encrypted_text += char
    return encrypted_text

def caesar_decrypt(encrypted_text, shift):
    if encrypted_text is None:
        return "Invalid input for decryption"
    
    decrypted_text = ""
    for char in encrypted_text:
        if char.isprintable():
            shifted_char = chr((ord(char) - shift - ord(' ')) % DIE + ord(' '))
            decrypted_text += shifted_char
        else:
            # Replace non-printable characters with a placeholder (underscore)
            decrypted_text += "_"
    return decrypted_text


# VIGENERE
ALL_CHARACTERS = string.printable

def vig_generateKey(password, key):
    key = list(key)
    if len(password) == len(key):
        return key
    else:
        for i in range(len(password) - len(key)):
            key.append(key[i % len(key)])  # Repeating the key if it's shorter than the password
    return "".join(key)

def vig_encryptPassword(password, key):
    key = vig_generateKey(password, key)
    vig_encrypted_password = ""
    for i in range(len(password)):
        if password[i].isprintable():
            x = (ALL_CHARACTERS.index(password[i]) + ALL_CHARACTERS.index(key[i])) % len(ALL_CHARACTERS)
            encrypted_char = ALL_CHARACTERS[x]
            vig_encrypted_password += encrypted_char
        else:
            # Replace non-printable characters with placeholder (underscore)
            vig_encrypted_password += "_"
    return vig_encrypted_password

def vig_decryptPassword(vig_encrypted_password, key):
    decrypted_password = ""
    for i in range(len(vig_encrypted_password)):
        encrypted_char = vig_encrypted_password[i]
        if encrypted_char == "_":
            decrypted_password += encrypted_char  # Preserve placeholder
        else:
            encrypted_index = ALL_CHARACTERS.index(encrypted_char)
            key_char = key[i % len(key)]
            key_index = ALL_CHARACTERS.index(key_char)
            decrypted_index = (encrypted_index - key_index) % len(ALL_CHARACTERS)
            decrypted_char = ALL_CHARACTERS[decrypted_index]
            decrypted_password += decrypted_char
    return decrypted_password

# multi


# MULTIPLICATIVE
def multi_mod_inverse(a, m):
    for i in range(1, m):
        if (a * i) % m == 1:
            return i
    return None

def multi_multiplicative_encrypt(plain_text, key):
    multi_encrypted_text = ""
    m = 128  # Modulus for ASCII characters (extend for additional special characters if needed)

    key_inverse = multi_mod_inverse(key, m)

    if key_inverse is None:
        return "The provided key is not invertible for the given modulus."

    for char in plain_text:
        char_code = ord(char)
        encrypted_char_code = (char_code * key) % m
        encrypted_char = chr(encrypted_char_code)
        multi_encrypted_text += encrypted_char

    return multi_encrypted_text

def multi_multiplicative_decrypt(encrypted_text, key):
    multi_decrypted_text = ""
    m = 128  # Modulus for ASCII characters (extend for additional special characters if needed)
    key_inverse = multi_mod_inverse(key, m)

    if key_inverse is None:
        return "The provided key is not invertible for the given modulus."

    for char in encrypted_text:
        char_code = ord(char)
        decrypted_char_code = (char_code * key_inverse) % m
        multi_decrypted_char = chr(decrypted_char_code)
        multi_decrypted_text += multi_decrypted_char

    return multi_decrypted_text
# TRANSPOSITION
key = "HACK"

def transp_encryptMessage(msg): 
    cipher = "" 
  
    # track key indices 
    k_indx = 0
  
    msg_len = float(len(msg)) 
    msg_lst = list(msg) 
    key_lst = sorted(list(key)) 
  
    # calculate column of the matrix 
    col = len(key) 
      
    # calculate maximum row of the matrix 
    row = int(math.ceil(msg_len / col)) 
  
    # add the padding character '_' in empty 
    # the empty cell of the matix  
    fill_null = int((row * col) - msg_len) 
    msg_lst.extend('_' * fill_null) 
  
    # create Matrix and insert message and  
    # padding characters row-wise  
    matrix = [msg_lst[i: i + col]  
              for i in range(0, len(msg_lst), col)] 
  
    # read matrix column-wise using key 
    for _ in range(col): 
        curr_idx = key.index(key_lst[k_indx]) 
        cipher += ''.join([row[curr_idx]  
                          for row in matrix]) 
        k_indx += 1
  
    return cipher 
# Decryption 
def transp_decryptMessage(cipher): 
    msg = "" 
  
    # track key indices 
    k_indx = 0
  
    # track msg indices 
    msg_indx = 0
    msg_len = float(len(cipher)) 
    msg_lst = list(cipher) 
  
    # calculate column of the matrix 
    col = len(key) 
      
    # calculate maximum row of the matrix 
    row = int(math.ceil(msg_len / col)) 
  
    # convert key into list and sort  
    # alphabetically so we can access  
    # each character by its alphabetical position. 
    key_lst = sorted(list(key)) 
  
    # create an empty matrix to  
    # store deciphered message 
    dec_cipher = [] 
    for _ in range(row): 
        dec_cipher += [[None] * col] 
  
    # Arrange the matrix column wise according  
    # to permutation order by adding into new matrix 
    for _ in range(col): 
        curr_idx = key.index(key_lst[k_indx]) 
  
        for j in range(row): 
            dec_cipher[j][curr_idx] = msg_lst[msg_indx] 
            msg_indx += 1
        k_indx += 1
  
    # convert decrypted msg matrix into a string 
    try: 
        msg = ''.join(sum(dec_cipher, [])) 
    except TypeError: 
        raise TypeError("This program cannot", 
                        "handle repeating words.") 
  
    null_count = msg.count('_') 
  
    if null_count > 0: 
        return msg[: -null_count] 
  
    return msg 

def main_encrypt(password, vigkey, affkey, multikey):
    layer1encrypt = vig_encryptPassword(password, vigkey)
    print("Layer 1 Encrypted:", layer1encrypt)  # Print the encrypted password after the first layer

    layer2encrypt = aff_encrypt(layer1encrypt, affkey)
    print("Layer 2 Encrypted:", layer2encrypt)  # Print the encrypted password after the second layer

    layer3encrypt = multi_multiplicative_encrypt(layer2encrypt, multikey)
    print("Layer 3 Encrypted:", layer3encrypt)  # Print the encrypted password after the third layer

    layer4encrypt = transp_encryptMessage(layer3encrypt)
    print("Layer 4 Encrypted:", layer4encrypt)  # Print the encrypted password after the fourth layer

    #layer5encrypt = caesar_encrypt(layer4encrypt, caeskey)
    #print("Layer 5 Encrypted:", layer5encrypt)  # Print the encrypted password after the fifth layer

    print("Final Encrypt:")
    print(layer4encrypt)

    return layer4encrypt

def main_decrypt(encryptedpw, multikey, affkey, vigkey):
    #layer1decrypt = caesar_decrypt(encryptedpw, caeskey)
    #print("Layer 1 Decrypted:", layer1decrypt)  # Print the encrypted password after the first layer

    layer2decrypt = transp_decryptMessage(encryptedpw)
    print("Layer 2 Decrypted:", layer2decrypt)  # Print the encrypted password after the second layer

    layer3decrypt = multi_multiplicative_decrypt(layer2decrypt, multikey)
    print("Layer 3 Decrypted:", layer3decrypt)  # Print the encrypted password after the third layer

    layer4decrypt = aff_decrypt(layer3decrypt, affkey)
    print("Layer 4 Decrypted:", layer4decrypt)  # Print the encrypted password after the fourth layer

    layer5decrypt = vig_decryptPassword(layer4decrypt, vigkey)
    print("Layer 5 Decrypted:", layer5decrypt)  # Print the encrypted password after the fifth layer

    print("Final Decrypt:")
    print(layer5decrypt)

    return layer5decrypt


# Example usage:
password = "H3LLO! W@Rld"
vigkey = "KEY"
affkey = aff_generate_key()
multikey = 7

print("Original Password:", password)
encr1 = main_encrypt(password, vigkey, affkey, multikey)
decr = main_decrypt(encr1, multikey, affkey, vigkey)
