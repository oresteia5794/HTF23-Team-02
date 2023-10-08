import random

def generate_otp():
    otp = random.randint(0000, 9999)
    return otp

otp = generate_otp()
print("Generated OTP:", otp) 

