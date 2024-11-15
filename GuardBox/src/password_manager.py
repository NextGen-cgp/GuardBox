import os
import random
import string
import getpass
import shutil
import os
from typing import List, Optional
from datetime import datetime
from src.crypto_utils import CryptoHandler
from src.db_handler import DatabaseHandler
from src.constants import *

class PasswordManager:
    """Gestor de contraseñas con cifrado y almacenamiento seguro."""

    def __init__(self):
        self.base_path = os.path.join(os.getenv('LOCALAPPDATA'), 'GestorCryptPass')
        self.db_path = os.path.join(self.base_path, 'guard.db')
        self.master_key_path = os.path.join(self.base_path, 'filebox')
        self.master_key = None
        
        self._ensure_base_path()
        self.db = DatabaseHandler(self.db_path)
        
    def _ensure_base_path(self) -> None:
        """Asegura que existe el directorio base."""
        if not os.path.exists(self.base_path):
            os.makedirs(self.base_path)

    def validate_input(self, input_text: str, input_type: str) -> str:
        """Valida que la entrada no contenga espacios y no esté vacía."""
        while " " in input_text or not input_text:
            print(ERRORS['space_validation'].format(input_type))
            input_text = input(f"Introduce {input_type} nuevamente: ").strip()
        return input_text

    def setup_master_key(self) -> bool:
        """Configura una nueva clave maestra."""
        master_key = self.validate_input(
            getpass.getpass("Configura una clave maestra: ").strip(),
            "Clave maestra"
        )
        verification = getpass.getpass("Vuelve a introducir la clave maestra: ")
    
        if master_key != verification:
            print(ERRORS['master_mismatch'])
            return False
    
        # Primero renombramos la base de datos si existe
        if os.path.exists(self.db_path):
            self._backup_old_db()
    
        # Guardamos la nueva clave maestra
        hashed = CryptoHandler.hash_master_key(master_key)
        with open(self.master_key_path, 'wb') as f:
            f.write(hashed)
        
        # Inicializamos una nueva base de datos
        self.db = DatabaseHandler(self.db_path)
        self.master_key = master_key
        return True

    def verify_master_key(self) -> bool:
        """Verifica la clave maestra existente."""
        master_key = getpass.getpass("Introduce la clave maestra: ")
        
        with open(self.master_key_path, 'rb') as f:
            stored_hash = f.read()
            
        if CryptoHandler.verify_master_key(master_key, stored_hash):
            self.master_key = master_key
            return True
        return False

    def initialize_master_key(self) -> bool:
        """Inicializa o verifica la clave maestra."""
        if not os.path.exists(self.master_key_path):
            return self.setup_master_key()
        
        while True:
            if self.verify_master_key():
                print("Acceso permitido.")
                return True
            print("Clave incorrecta.")
            if input("¿Desea intentar de nuevo? (s/n): ").lower() != 's':
                return False

    def save_password(self, service: str, password: str) -> None:
        """Guarda una contraseña encriptada."""
        encrypted = CryptoHandler.encrypt_password(password, self.master_key)
        self.db.save_password(service, encrypted)

    def get_password(self, service: str) -> Optional[str]:
        """Recupera y descifra una contraseña."""
        encrypted = self.db.get_password(service)
        if not encrypted:
            return None
        
        try:
            return CryptoHandler.decrypt_password(encrypted, self.master_key)
        except ValueError as e:
            print(str(e))
            return None

    def list_passwords(self, decrypt: bool = False) -> None:
        """Lista todas las contraseñas."""
        passwords = self.db.get_all_passwords()
        if not passwords:
            print(ERRORS['no_passwords'])
            return

        for service, encrypted in passwords:
            if decrypt:
                try:
                    decrypted = CryptoHandler.decrypt_password(encrypted, self.master_key)
                    print(f"Servicio: {service}, Contraseña: {decrypted}")
                except ValueError as e:
                    print(f"Servicio: {service}, Error: {str(e)}")
            else:
                print(f"Servicio: {service}, Contraseña cifrada: {encrypted}")

    def delete_passwords(self, services: List[str]) -> None:
        """Elimina las contraseñas especificadas."""
        for service, success in self.db.delete_passwords(services):
            if success:
                print(f"Servicio '{service}' eliminado.")
            else:
                print(ERRORS['service_not_found'].format(service))

    def export_passwords(self, decrypt: bool = False) -> None:
        """Exporta las contraseñas a CSV."""
        passwords = self.db.get_all_passwords()
        if not passwords:
            print(ERRORS['no_export_data'])
            return

        export_data = []
        for service, encrypted in passwords:
            if decrypt:
                try:
                    password = CryptoHandler.decrypt_password(encrypted, self.master_key)
                    export_data.append([service, password, 'AES-CBC'])
                except ValueError:
                    continue
            else:
                export_data.append([service, encrypted, 'AES-CBC'])

        filename = 'contraseñas_descifradas.csv' if decrypt else 'contraseñas_exportadas.csv'
        self.db.export_to_csv(filename, export_data)
        print(f"Datos exportados a '{filename}'.")

    def create_backup(self) -> None:
        """Realiza una copia de seguridad de los datos."""
        backup_dir = os.path.join(os.getcwd(), 'backupGuard')
        os.makedirs(backup_dir, exist_ok=True)
        
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        db_backup = os.path.join(backup_dir, f'guard_backup_{timestamp}.db')
        key_backup = os.path.join(backup_dir, f'filebox_backup_{timestamp}')
        
        try:
            shutil.copy2(self.db_path, db_backup)
            shutil.copy2(self.master_key_path, key_backup)
            print(f"Backup realizado en 'backupGuard':")
            print(f"- Base de datos: {db_backup}")
            print(f"- Clave maestra: {key_backup}")
        except Exception as e:
            print(f"Error en el backup: {e}")

    def _backup_old_db(self) -> None:
    #Renombra la base de datos antigua.
        """Gestiona el respaldo de la base de datos antigua y la creación de la nueva."""
        try:
            # Primero creamos la nueva base de datos con nombre temporal
            new_db_path = self.db_path.replace('.db', '.new.db')
            old_db_path = self.db_path.replace('.db', '.old.db')
            
            # Creamos la nueva base de datos temporal
            self.db = DatabaseHandler(new_db_path)
            self.db.close_connection()
            
            # Cerramos la conexión actual con la base de datos antigua
            if hasattr(self, 'db'):
                self.db.close_connection()
                
            # Ahora renombramos la antigua a .old
            if os.path.exists(old_db_path):
                os.remove(old_db_path)
            os.rename(self.db_path, old_db_path)
            
            # Finalmente renombramos la nueva a su nombre final
            os.rename(new_db_path, self.db_path)
            
            print(f"Base de datos anterior respaldada como: {old_db_path}")
            
            # Reabrimos la conexión con la nueva base de datos
            self.db = DatabaseHandler(self.db_path)
            
        except Exception as e:
            raise Exception(f"Error al hacer backup de la base de datos: {e}")
    
    def handle_password_listing(self, option: str) -> None:
        """Maneja las opciones de listado y eliminación de contraseñas."""
        if option == "L":
            self.list_passwords()
        elif option == "LD":
            self.list_passwords(decrypt=True)
        elif option == "E":
            services = input("Servicios a eliminar (separados por espacios): ").split()
            self.delete_passwords(services)
        else:
            print("Opción no válida")

    def handle_export(self, option: str) -> None:
        """Maneja las opciones de exportación de contraseñas."""
        if option in ["C", "D"]:
            self.export_passwords(decrypt=option=="D")
        else:
            print("Opción no válida")

    @staticmethod
    def generate_password(length: int = DEFAULT_PASSWORD_LENGTH) -> str:
        """Genera una contraseña segura aleatoria."""
        chars = string.ascii_letters + string.digits + string.punctuation
        return ''.join(random.choice(chars) for _ in range(length))