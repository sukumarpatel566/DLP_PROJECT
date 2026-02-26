import os
import base64
from cryptography.fernet import Fernet
from dotenv import load_dotenv

load_dotenv()

class EncryptionService:
    def __init__(self):
        # Load environment variables just in case
        load_dotenv()
        
        raw_key = os.getenv('AES_KEY')
        self.key = None

        if raw_key:
            try:
                # Ensure it's a string for processing
                if not isinstance(raw_key, str):
                    raw_key = str(raw_key)
                
                # Fernet keys are 32 bytes URL-safe base64 encoded -> 44 chars
                if len(raw_key.strip()) != 44:
                    raise ValueError(f"Key must be exactly 44 characters (found {len(raw_key.strip())})")
                
                # Test the key by creating a Fernet instance
                self.key = raw_key.strip().encode()
                Fernet(self.key)
            except Exception as e:
                print(f"WARNING: Invalid AES_KEY '{raw_key}' in .env: {str(e)}")
                self.key = None

        if not self.key:
            # Generate a secure fallback key
            self.key = Fernet.generate_key()
            print("="*60)
            print("CRITICAL: USING TEMPORARY ENCRYPTION KEY.")
            print(f"Please add this to your .env: AES_KEY={self.key.decode()}")
            print("="*60)
        
        try:
            self.cipher = Fernet(self.key)
        except Exception as e:
            # Absolute fallback if even generation failed or something went weird
            self.key = Fernet.generate_key()
            self.cipher = Fernet(self.key)
            print(f"EMERGENCY: Encryption re-initialized due to error: {e}")

    def encrypt(self, data):
        if isinstance(data, str):
            data = data.encode()
        return self.cipher.encrypt(data)

    def decrypt(self, encrypted_data):
        return self.cipher.decrypt(encrypted_data).decode()

    def encrypt_file(self, file_path, output_path):
        with open(file_path, 'rb') as f:
            data = f.read()
        
        encrypted_data = self.cipher.encrypt(data)
        
        with open(output_path, 'wb') as f:
            f.write(encrypted_data)

    def decrypt_file(self, encrypted_path):
        with open(encrypted_path, 'rb') as f:
            encrypted_data = f.read()
            
        return self.cipher.decrypt(encrypted_data)
