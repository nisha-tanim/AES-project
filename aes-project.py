import os
import time
import string
import random
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding, hashes
from cryptography.hazmat.primitives.hashes import SHA256
from os import urandom

def key_generation():
    #Generate a cryptographically secure random 16-byte key for AES-128 encryption
    return urandom(16)

def save_key(key, filename):
    #Save the encryption key to a file, ensuring directory exists if provided.
    directory_path = os.path.dirname(filename)
    if not os.path.exists(directory_path):
        os.makedirs(directory_path, exist_ok=True)
    with open(filename, 'wb') as file:
        file.write(key)

def key_loader(filename):
    #Load an encryption key from a file.
    with open(filename, 'rb') as file:
        return file.read()

def hash_data(data):
    #Hash data using SHA256.
    digest = hashes.Hash(SHA256(), backend=default_backend())
    digest.update(data)
    return digest.finalize()

class FileEncryption:
    def encrypt_file(self, input_file, output_file, key):
        #Encrypt a file using AES-128 with CBC mode using an alphanumeric IV.
        iv = ''.join(random.choices(string.ascii_letters + string.digits, k=16)).encode('utf-8')
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        padder = padding.PKCS7(algorithms.AES.block_size).padder()

        with open(input_file, 'rb') as f_in, open(output_file, 'wb') as f_out:
            f_out.write(iv)  # Write the IV to the output file first
            while True:
                chunk = f_in.read(4096)  # Read in 4096-byte chunks
                if not chunk:
                    break
                padded_chunk = padder.update(chunk)
                encrypted_chunk = encryptor.update(padded_chunk)
                f_out.write(encrypted_chunk)
            # Finalize encryption and padding
            f_out.write(encryptor.update(padder.finalize()) + encryptor.finalize())

    def decrypt_file(self, input_file, output_file, key):
        #Decrypt a file using AES-128 with CBC mode.
        with open(input_file, 'rb') as f_in, open(output_file, 'wb') as f_out:
            iv = f_in.read(16)  # Read the IV from the start of the file
            cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
            decryptor = cipher.decryptor()
            unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
            #using public key cryptographic standard for padding and undpadding data. 
            while True:
                chunk = f_in.read(4096)  # Read in 4096-byte chunks
                if not chunk:
                    break
                decrypted_chunk = decryptor.update(chunk)
                unpadded_chunk = unpadder.update(decrypted_chunk)
                f_out.write(unpadded_chunk)
            # Finalize decryption and padding
            f_out.write(unpadder.finalize() + decryptor.finalize())

if __name__ == "__main__":
    file_encryptor = FileEncryption()
    input_folder = 'input files'
    encrypted_folder = 'encrypted files'
    decrypted_folder = 'decrypted files'
    key_folder = 'stored keys'

    os.makedirs(encrypted_folder, exist_ok=True)
    os.makedirs(decrypted_folder, exist_ok=True)
    os.makedirs(key_folder, exist_ok=True)

    while True:
        action = input("Would you like to encrypt or decrypt a file? (encryption/decryption/exit): ").strip().lower()
        if action == "encryption":
            encryption = input("Do you want to encrypt a single file or all files? (single file/all files): ").strip().lower()
            if encryption == "single file":
                files = os.listdir(input_folder)
                if files:
                    print("List of Available files:")
                    for idx, file in enumerate(files):
                        print(f"{idx + 1}: {file}")
                    file_choice = int(input("Select the file number to encrypt: ")) - 1
                    if 0 <= file_choice < len(files):
                        file_path = os.path.join(input_folder, files[file_choice])
                        key = key_generation()
                        save_key(key, os.path.join(key_folder, files[file_choice] + ".key"))
                        encrypted_file = os.path.join(encrypted_folder, files[file_choice] + ".enc")
                        start_time = time.time()
                        file_encryptor.encrypt_file(file_path, encrypted_file, key)
                        end_time = time.time()
                        print(f"File {files[file_choice]} encrypted as {encrypted_file} in {end_time - start_time} seconds")
                    else:
                        print("Invalid file selection. Please try again")
                else:
                    print("No files found in the input folder. Please try again")
            elif encryption == "all files":
                files = os.listdir(input_folder)
                if files:
                    for file in files:
                        file_path = os.path.join(input_folder, file)
                        key = key_generation()
                        save_key(key, os.path.join(key_folder, file + ".key"))
                        encrypted_file = os.path.join(encrypted_folder, file + ".enc")
                        start_time = time.time()
                        file_encryptor.encrypt_file(file_path, encrypted_file, key)
                        end_time = time.time()
                        print(f"File {file} encrypted as {encrypted_file} in {end_time - start_time} seconds")
                else:
                    print("No files found in the input folder. Please try again")
        elif action == "decryption":
            decrypt_option = input("Do you want to decrypt a single file or all files? (single file/all files): ").strip().lower()
            if decrypt_option == "single file":
                files = os.listdir(encrypted_folder)
                if files:
                    print("List of available encrypted files:")
                    for idx, file in enumerate(files):
                        print(f"{idx + 1}: {file}")
                    file_choice = int(input("Select the file number to decrypt: ")) - 1
                    if 0 <= file_choice < len(files):
                        encrypted_file_path = os.path.join(encrypted_folder, files[file_choice])
                        key_file = os.path.join(key_folder, files[file_choice].replace(".enc", ".key"))
                        key = key_loader(key_file)
                        output_file = os.path.join(decrypted_folder, files[file_choice].replace(".enc", ""))
                        start_time = time.time()
                        with open(output_file, 'wb') as f_out:  # Ensure file output context is correctly set
                            file_encryptor.decrypt_file(encrypted_file_path, output_file, key)
                        end_time = time.time()
                        print(f"File {files[file_choice]} decrypted and saved as {output_file} in {end_time - start_time} seconds")
                    else:
                        print("Invalid file selection. Please try again")
                else:
                    print("No encrypted files found.")
            elif decrypt_option == "all files":
                files = os.listdir(encrypted_folder)
                if files:
                    for file in files:
                        encrypted_file_path = os.path.join(encrypted_folder, file)
                        key_file = os.path.join(key_folder, file.replace(".enc", ".key"))
                        key = key_loader(key_file)
                        output_file = os.path.join(decrypted_folder, file.replace(".enc", ""))
                        start_time = time.time()
                        with open(output_file, 'wb') as f_out:  # Ensure file output context is correctly set for all files
                            file_encryptor.decrypt_file(encrypted_file_path, output_file, key)
                        end_time = time.time()
                        print(f"File {file} decrypted and saved as {output_file} in {end_time - start_time} seconds")
                else:
                    print("No encrypted files found. Please try again")
        elif action == "exit":
            print("Exiting the program.")
            break
        else:
            print("Invalid action. Please type 'encryption', 'decryption', or 'exit'.")
