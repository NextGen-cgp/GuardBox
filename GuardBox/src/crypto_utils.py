import bcrypt
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import scrypt
from Crypto.Random import get_random_bytes
import base64
from .constants import *

class CryptoHandler:
    """Maneja las operaciones criptográficas"""
    
    @staticmethod
    def hash_master_key(master_key: str) -> bytes:
        return bcrypt.hashpw(master_key.encode(ENCODING), bcrypt.gensalt())
    
    @staticmethod
    def verify_master_key(master_key: str, stored_hash: bytes) -> bool:
        return bcrypt.checkpw(master_key.encode(ENCODING), stored_hash)
    
    @staticmethod
    def derive_key(master_key: str, salt: bytes) -> bytes:
        return scrypt(
            master_key.encode(ENCODING), 
            salt=salt, 
            **SCRYPT_PARAMS
        )
    
    @staticmethod
    def encrypt_password(password: str, master_key: str) -> str:
        password_with_verification = password + VERIFICATION_SUFFIX
        salt = get_random_bytes(SALT_SIZE)
        key = CryptoHandler.derive_key(master_key, salt)
        iv = get_random_bytes(AES.block_size)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        
        padded = CryptoHandler._pad(password_with_verification)
        encrypted = cipher.encrypt(padded.encode())
        final_data = salt + iv + encrypted
        
        return base64.b64encode(final_data).decode()

    @staticmethod
    def decrypt_password(encrypted_data: str, master_key: str) -> str:
        try:
            data = base64.b64decode(encrypted_data)
            salt = data[:SALT_SIZE]
            iv = data[SALT_SIZE:SALT_SIZE + AES.block_size]
            encrypted = data[SALT_SIZE + AES.block_size:]
            
            key = CryptoHandler.derive_key(master_key, salt)
            cipher = AES.new(key, AES.MODE_CBC, iv)
            
            decrypted = cipher.decrypt(encrypted).decode()
            unpadded = CryptoHandler._unpad(decrypted)
            
            if not unpadded.endswith(VERIFICATION_SUFFIX):
                raise ValueError(ERRORS['wrong_password'])
                
            return unpadded[:-len(VERIFICATION_SUFFIX)]
            
        except (ValueError, UnicodeDecodeError) as e:
            raise ValueError(ERRORS['data_corrupted'])

    @staticmethod
    def _pad(text: str) -> str:
        padding_size = AES.block_size - len(text) % AES.block_size
        return text + chr(padding_size) * padding_size

    @staticmethod
    def _unpad(text: str) -> str:
        padding_size = ord(text[-1])
        return text[:-padding_size]