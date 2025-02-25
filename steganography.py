from PIL import Image
import os
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto import Random
import base64
import getpass
from termcolor import cprint

# Function to count the total number of pixels in the image
def getPixelCount(img):
    width, height = Image.open(img).size
    return width * height

# Function to encrypt the message with AES
from Crypto.Util.Padding import pad, unpad

# Function to encrypt the message with AES
def encrypt(key, source):
    key = SHA256.new(key).digest()  # Hash the password to 32 bytes
    cipher = AES.new(key, AES.MODE_CBC)  # Use AES in CBC mode
    
    # Pad the message to be a multiple of 16 bytes
    padding_length = 16 - len(source) % 16
    source += bytes([padding_length]) * padding_length  # Add padding as bytes
    
    cipher_text = cipher.encrypt(source)  # Encrypt the message
    return base64.b64encode(cipher.iv + cipher_text).decode('utf-8')



# Function to decrypt the message with AES
def decrypt(key, source):
    source = base64.b64decode(source.encode('utf-8'))
    iv = source[:16]  # Extract IV
    cipher_text = source[16:]  # The actual encrypted text
    
    key = SHA256.new(key).digest()  # Hash the password
    cipher = AES.new(key, AES.MODE_CBC, iv)  # CBC mode cipher
    
    decrypted = cipher.decrypt(cipher_text)  # Decrypt the message
    
    # Remove padding (assumed to be PKCS#7 padding)
    padding_length = decrypted[-1]
    decrypted = decrypted[:-padding_length]  # Remove padding

    return decrypted.decode('utf-8')




# Function to encode the message into the image
def encodeImage(image, message, filename):
    width, height = image.size
    pix = image.load()

    message_index = 0
    message = ''.join(format(ord(c), '08b') for c in message)  # Convert message to binary
    message_length = len(message)
    
    for i in range(width):
        for j in range(height):
            r, g, b = pix[i, j]

            if message_index < message_length:
                r = (r & 0xFE) | int(message[message_index])  # Change the least significant bit
                message_index += 1
            if message_index < message_length:
                g = (g & 0xFE) | int(message[message_index])
                message_index += 1
            if message_index < message_length:
                b = (b & 0xFE) | int(message[message_index])
                message_index += 1
            
            pix[i, j] = (r, g, b)

            if message_index >= message_length:
                break

    image.save(filename)

# Function to decode the message from the image
def decodeImage(image):
    width, height = image.size
    pix = image.load()

    binary_message = ''
    
    for i in range(width):
        for j in range(height):
            r, g, b = pix[i, j]
            binary_message += str(r & 1)  # Get the least significant bit
            binary_message += str(g & 1)
            binary_message += str(b & 1)

    # Split the binary message into 8-bit chunks and convert to characters
    message = ''
    for i in range(0, len(binary_message), 8):
        byte = binary_message[i:i+8]
        message += chr(int(byte, 2))

    return message

# Main function to run the program
def main():
    print("Choose one: ")
    op = int(input("1. Encode\n2. Decode\n>> "))
    
    if op == 1:
        print("Image path (with extension): ")
        img = input(">> ")

        if not os.path.exists(img):
            raise Exception("Image not found!")

        print("Message to be hidden: ")
        message = input(">> ")

        if len(message) * 3 > getPixelCount(img):
            raise Exception("Given message is too long to be encoded in the image.")

        password = ""
        while True:
            print("Password to encrypt (leave empty if you want no password):")
            password = input("Enter password (will be shown for debugging): ")


            if password == "":
                break
            confirm_password =input("Re-enter password: ")
            if password != confirm_password:
                print("Passwords do not match, try again!")
            else:
                break

        cipher = ""
        if password != "":
            cipher = encrypt(key=password.encode(), source=message.encode())
        else:
            cipher = message

        image = Image.open(img)
        print("Image mode: %s" % image.mode)

        if image.mode != 'RGB':
            image = image.convert('RGB')
        newimg = image.copy()
        encodeImage(image=newimg, message=cipher, filename="encoded_" + os.path.basename(img))
        
        print(f"Saving encoded image as encoded_{os.path.basename(img)}")  # Debug line

        # Save the encoded image
        newimg.save(f"encoded_{os.path.basename(img)}")

    elif op == 2:
        print("Image path (with extension): ")
        img = input(">> ")

        if not os.path.exists(img):
            raise Exception("Image not found!")

        print("Enter password (leave empty if no password): ")
        password = input("Enter password (will be shown for debugging): ")


        image = Image.open(img)

        cipher = decodeImage(image)

        decrypted = ""
        if password != "":
            decrypted = decrypt(key=password.encode(), source=cipher)
        else:
            decrypted = cipher

        print("Decoded Text: \n%s" % decrypted)

if __name__ == "__main__":
    main()
