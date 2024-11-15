import os
import random
import string
import sqlite3
import csv
import bcrypt
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import scrypt
from Crypto.Random import get_random_bytes
import base64
import getpass
import shutil
from datetime import datetime


class PasswordManager:
    """Clase para gestionar contraseñas con cifrado y almacenamiento seguro."""

    def __init__(self):
        """Inicializa rutas y verifica la existencia de directorios necesarios."""
        self.RUTA_BASE = os.path.join(os.getenv('LOCALAPPDATA'), 'GestorCryptPass')
        self.RUTA_DB = os.path.join(self.RUTA_BASE, 'guard.db')
        self.RUTA_PASSWORD = os.path.join(self.RUTA_BASE, 'filebox')
        self.AES_BLOCK_SIZE = AES.block_size
        self.clave_maestra = None  # Clave maestra ingresada por el usuario
        self._initialize_paths()

    def _initialize_paths(self):
        """Crea el directorio base si no existe."""
        if not os.path.exists(self.RUTA_BASE):
            os.makedirs(self.RUTA_BASE)

    def _initialize_database(self):
        """Inicializa la base de datos SQLite con las tablas requeridas."""
        with sqlite3.connect(self.RUTA_DB) as conn:
            cursor = conn.cursor()
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS guard (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    servicio TEXT NOT NULL,
                    password_encriptada TEXT NOT NULL,
                    algoritmo TEXT NOT NULL
                )
            ''')
            conn.commit()

    def validar_espacios(self, input_text, tipo):
        """Valida que la entrada no contenga espacios y no esté vacía."""
        while " " in input_text or input_text == "":
            print(f"Error: {tipo} no debe contener espacios ni estar vacío.")
            input_text = input(f"Introduce {tipo} nuevamente: ").strip()
        return input_text

    def guardar_clave_maestra(self, clave_maestra):
        """Hash y guarda la clave maestra."""
        hashed = bcrypt.hashpw(clave_maestra.encode(), bcrypt.gensalt())
        with open(self.RUTA_PASSWORD, 'wb') as f:
            f.write(hashed)

    def verificar_clave_maestra(self, clave_maestra):
        """Verifica la clave maestra contra el hash almacenado."""
        with open(self.RUTA_PASSWORD, 'rb') as f:
            hashed = f.read()
        return bcrypt.checkpw(clave_maestra.encode(), hashed)

    def solicitar_clave_maestra(self):
        """Solicita al usuario la clave maestra y la verifica o la configura."""
        if not os.path.exists(self.RUTA_PASSWORD):
            clave_maestra = self.validar_espacios(getpass.getpass(
                "Para acceder a tu almacén de contraseñas protegidas, configura una clave maestra: ").strip(),
                "Clave maestra")
            clave_maestra_verificacion = getpass.getpass("Vuelve a introducir la clave maestra para verificar: ")
            if clave_maestra == clave_maestra_verificacion:
                self.guardar_clave_maestra(clave_maestra)
                if os.path.exists(self.RUTA_DB):
                    self.renombrar_bd_antigua()
                # Inicializamos la base de datos aquí
                self._initialize_database()
                print("Clave maestra configurada exitosamente.")
                self.clave_maestra = clave_maestra
            else:
                print("Las claves maestras no coinciden.")
                self.clave_maestra = None
        else:
            while True:
                clave_maestra = getpass.getpass("Introduce la clave maestra: ")
                if self.verificar_clave_maestra(clave_maestra):
                    print("Acceso permitido.")
                    self.clave_maestra = clave_maestra
                    # Inicializamos la base de datos aquí
                    self._initialize_database()
                    break
                else:
                    print("Clave incorrecta.")

    def _pad(self, s):
        """Aplica padding PKCS#7 al texto."""
        padding_length = self.AES_BLOCK_SIZE - len(s) % self.AES_BLOCK_SIZE
        return s + chr(padding_length) * padding_length

    def _unpad(self, s):
        """Elimina el padding PKCS#7 del texto."""
        padding_length = ord(s[-1])
        return s[:-padding_length]

    def cifrar_password(self, password):
        """Cifra la contraseña utilizando AES y un salt único."""
        password_con_verificacion = password + "END"
        salt = get_random_bytes(16)  # Generar un salt aleatorio de 16 bytes
        clave_derivada = scrypt(self.clave_maestra.encode(), salt=salt, key_len=32, N=2**14, r=8, p=1)
        iv = get_random_bytes(self.AES_BLOCK_SIZE)
        cipher = AES.new(clave_derivada, AES.MODE_CBC, iv)
        password_padded = self._pad(password_con_verificacion)
        encrypted_password = cipher.encrypt(password_padded.encode())
        # Concatenar salt + iv + encrypted_password
        encrypted_data = salt + iv + encrypted_password
        # Retornar el dato cifrado en base64 para almacenarlo
        return base64.b64encode(encrypted_data).decode()

    def descifrar_password(self, encrypted_password):
        """Descifra la contraseña encriptada utilizando AES y el salt almacenado."""
        try:
            encrypted_data = base64.b64decode(encrypted_password)
            # Extraer salt, iv y el texto cifrado
            salt = encrypted_data[:16]
            iv = encrypted_data[16:16 + self.AES_BLOCK_SIZE]
            encrypted_password_bytes = encrypted_data[16 + self.AES_BLOCK_SIZE:]
            clave_derivada = scrypt(self.clave_maestra.encode(), salt=salt, key_len=32, N=2**14, r=8, p=1)
            cipher = AES.new(clave_derivada, AES.MODE_CBC, iv)
            decrypted_padded = cipher.decrypt(encrypted_password_bytes).decode()
            decrypted_password = self._unpad(decrypted_padded)
            if decrypted_password.endswith("END"):
                return decrypted_password[:-3]
            else:
                print("Error: la clave maestra introducida es incorrecta.")
                return None
        except (ValueError, UnicodeDecodeError):
            print("Error: la clave maestra introducida es incorrecta o los datos están dañados.")
            return None

    def guardar_en_bd(self, servicio, encrypted_password):
        """Guarda la contraseña encriptada en la base de datos SQLite."""
        with sqlite3.connect(self.RUTA_DB) as conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO guard (servicio, password_encriptada, algoritmo)
                VALUES (?, ?, ?)
            ''', (servicio, encrypted_password, 'AES-CBC'))
            conn.commit()

    def listar_contraseñas(self):
        """Lista todas las contraseñas encriptadas en la base de datos."""
        with sqlite3.connect(self.RUTA_DB) as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT servicio, password_encriptada FROM guard')
            registros = cursor.fetchall()
        if registros:
            for servicio, password_encriptada in registros:
                print(f"Servicio: {servicio}, Password Encriptada: {password_encriptada}")
        else:
            print("No hay contraseñas guardadas en el almacén.")

    def listar_contraseñas_descifradas(self):
        """Lista todas las contraseñas descifradas en la base de datos."""
        with sqlite3.connect(self.RUTA_DB) as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT servicio, password_encriptada FROM guard')
            registros = cursor.fetchall()
        if registros:
            for servicio, encrypted_password in registros:
                password_descifrada = self.descifrar_password(encrypted_password)
                if password_descifrada is not None:
                    print(f"Servicio: {servicio}, Password Descifrada: {password_descifrada}")
        else:
            print("No hay contraseñas guardadas en el almacén.")

    def eliminar_contraseñas(self, servicios):
        """Elimina las contraseñas especificadas de la base de datos."""
        with sqlite3.connect(self.RUTA_DB) as conn:
            cursor = conn.cursor()
            for servicio in servicios:
                cursor.execute('SELECT COUNT(*) FROM guard WHERE servicio = ?', (servicio,))
                existe = cursor.fetchone()[0]
                if existe:
                    cursor.execute('DELETE FROM guard WHERE servicio = ?', (servicio,))
                    print(f"El servicio '{servicio}' ha sido eliminado de la base de datos.")
                else:
                    print(f"El servicio '{servicio}' no se ha encontrado en la base de datos.")
            conn.commit()

    def exportar_a_csv(self):
        """Exporta las contraseñas encriptadas a un archivo CSV."""
        with sqlite3.connect(self.RUTA_DB) as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT servicio, password_encriptada, algoritmo FROM guard')
            registros = cursor.fetchall()
        if registros:
            with open('contraseñas_exportadas.csv', 'w', newline='', encoding='utf-8') as csvfile:
                writer = csv.writer(csvfile)
                writer.writerow(['Servicio', 'Password Encriptada', 'Algoritmo'])
                writer.writerows(registros)
            print("Los datos han sido exportados a 'contraseñas_exportadas.csv'.")
        else:
            print("No hay datos para exportar.")

    def exportar_descifradas_a_csv(self):
        """Exporta las contraseñas descifradas a un archivo CSV."""
        with sqlite3.connect(self.RUTA_DB) as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT servicio, password_encriptada, algoritmo FROM guard')
            registros = cursor.fetchall()
        if registros:
            with open('contraseñas_descifradas.csv', 'w', newline='', encoding='utf-8') as csvfile:
                writer = csv.writer(csvfile)
                writer.writerow(['Servicio', 'Password Descifrada', 'Algoritmo'])
                for servicio, encrypted_password, algoritmo in registros:
                    password_descifrada = self.descifrar_password(encrypted_password)
                    if password_descifrada is not None:
                        writer.writerow([servicio, password_descifrada, algoritmo])
            print("Los datos han sido exportados a 'contraseñas_descifradas.csv'.")
        else:
            print("No hay datos para exportar.")

    def generar_password(self, longitud=16):
        """Genera una contraseña segura aleatoria."""
        caracteres = string.ascii_letters + string.digits + string.punctuation
        password = ''.join(random.choice(caracteres) for _ in range(longitud))
        return password

    def realizar_backup(self):
        """Realiza un backup de la base de datos y del archivo de clave maestra."""
        backup_dir = os.path.join(os.getcwd(), 'backupGuard')
        if not os.path.exists(backup_dir):
            os.makedirs(backup_dir)
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        backup_db_path = os.path.join(backup_dir, f'guard_backup_{timestamp}.db')
        backup_password_path = os.path.join(backup_dir, f'filebox_backup_{timestamp}')
        try:
            shutil.copy2(self.RUTA_DB, backup_db_path)
            shutil.copy2(self.RUTA_PASSWORD, backup_password_path)
            print(f"Backup realizado correctamente en la carpeta 'backupGuard':")
            print(f"- Base de datos: {backup_db_path}")
            print(f"- Clave maestra: {backup_password_path}")
        except Exception as e:
            print(f"Error al realizar el backup: {e}")

    def renombrar_bd_antigua(self):
        """Renombra el archivo de la base de datos antigua."""
        if os.path.exists(self.RUTA_DB):
            ruta_db_old = self.RUTA_DB.replace('.db', '.old.db')
            os.rename(self.RUTA_DB, ruta_db_old)


def main():
    """Función principal que ejecuta el menú del gestor de contraseñas."""
    pm = PasswordManager()
    pm.solicitar_clave_maestra()
    if not pm.clave_maestra:
        return
    print("¡Bienvenido a GuardBox! tu gestor de contraseñas seguras.")
    while True:
        print("\n--- Gestor de Contraseñas ---")
        print("1) Generar y guardar contraseña aleatoria")
        print("2) Guardar una contraseña encriptada a partir de una introducida")
        print("3) Listar o eliminar contraseñas en el almacén")
        print("4) Desencriptar una contraseña")
        print("5) Exportar todas las contraseñas a un archivo CSV")
        print("6) Realizar backup de la base de datos y clave maestra")
        print("7) Salir")
        opcion = input("Selecciona una opción: ")

        if opcion == "1":
            servicio = pm.validar_espacios(input("Introduce el nombre del servicio: ").strip(), "Nombre del servicio")
            password = pm.generar_password()
            encrypted_password = pm.cifrar_password(password)
            pm.guardar_en_bd(servicio, encrypted_password)
            print(f"Contraseña generada y guardada para el servicio: {servicio}")
            print(f"Contraseña original: {password}")

        elif opcion == "2":
            servicio = pm.validar_espacios(input("Introduce el nombre del servicio: ").strip(), "Nombre del servicio")
            password = pm.validar_espacios(input("Introduce la contraseña a encriptar: ").strip(), "Contraseña")
            encrypted_password = pm.cifrar_password(password)
            pm.guardar_en_bd(servicio, encrypted_password)
            print(f"Contraseña encriptada y guardada para el servicio: {servicio}")

        elif opcion == "3":
            sub_opcion = input("¿Deseas (L)istar encriptadas, (LD) listar descifradas o (E)liminar una o varias contraseñas? ").strip().upper()
            if sub_opcion == "L":
                pm.listar_contraseñas()
            elif sub_opcion == "LD":
                pm.listar_contraseñas_descifradas()
            elif sub_opcion == "E":
                servicios = input("Introduce los nombres de los servicios a eliminar, separados por espacios: ").split()
                pm.eliminar_contraseñas(servicios)
            else:
                print("Opción no válida. Intenta de nuevo.")

        elif opcion == "4":
            servicio = pm.validar_espacios(input("Introduce el nombre del servicio a descifrar: ").strip(), "Nombre del servicio")
            with sqlite3.connect(pm.RUTA_DB) as conn:
                cursor = conn.cursor()
                cursor.execute('SELECT password_encriptada FROM guard WHERE servicio = ?', (servicio,))
                registro = cursor.fetchone()
            if registro:
                encrypted_password = registro[0]
                password_descifrada = pm.descifrar_password(encrypted_password)
                if password_descifrada is not None:
                    print(f"La contraseña descifrada para el servicio {servicio} es: {password_descifrada}")
                else:
                    print("No se pudo descifrar la contraseña. Verifica que la clave maestra sea correcta.")
            else:
                print("Servicio no encontrado.")

        elif opcion == "5":
            sub_opcion = input("¿Deseas exportar las contraseñas (C)ifradas o (D)escifradas: ").strip().upper()
            if sub_opcion == "C":
                pm.exportar_a_csv()
            elif sub_opcion == "D":
                pm.exportar_descifradas_a_csv()
            else:
                print("Opción no válida. Intenta de nuevo.")

        elif opcion == "6":
            pm.realizar_backup()

        elif opcion == "7":
            print("Saliendo del programa...")
            break

        else:
            print("Opción no válida. Intenta de nuevo.")


if __name__ == "__main__":
    main()
