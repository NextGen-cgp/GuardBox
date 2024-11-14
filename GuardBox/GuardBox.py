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


# Definir la ruta de almacenamiento en AppData\Local en Windows
def obtener_ruta_base():
    ruta_base = os.path.join(os.getenv('LOCALAPPDATA'), 'GestorCryptPass')
    if not os.path.exists(ruta_base):
        os.makedirs(ruta_base)
    return ruta_base

RUTA_DB = os.path.join(obtener_ruta_base(), 'guard.db')
RUTA_PASSWORD = os.path.join(obtener_ruta_base(), 'filebox')

# Inicializar la base de datos SQLite
def inicializar_bd():
    conn = sqlite3.connect(RUTA_DB)
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
    conn.close()

# Función para validar que no haya espacios en el input del usuario
def validar_espacios(input_text, tipo):
    while " " in input_text or input_text == "":
        print(f"Error: {tipo} no debe contener espacios ni estar vacío.")
        input_text = input(f"Introduce {tipo} nuevamente: ").strip()
    return input_text


# Función para renombrar la base de datos antigua
def renombrar_bd_antigua():
    if os.path.exists(RUTA_DB):
        ruta_db_old = RUTA_DB.replace('.db', '.old.db')
        os.rename(RUTA_DB, ruta_db_old)

# Función para realizar un backup de la base de datos y del archivo de clave maestra
def realizar_backup():
    # Crear una carpeta de backup si no existe
    if not os.path.exists('backupGuard'):
        os.makedirs('backupGuard')

    # Generar un timestamp para el nombre de los archivos de backup
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')

    # Copiar la base de datos y el archivo de clave maestra con el timestamp en el nombre
    backup_db_path = os.path.join('backupGuard', f'guard_backup_{timestamp}.db')
    backup_password_path = os.path.join('backupGuard', f'filebox_backup_{timestamp}')

    # Copiar los archivos
    try:
        shutil.copy2(RUTA_DB, backup_db_path)
        shutil.copy2(RUTA_PASSWORD, backup_password_path)
        print(f"Backup realizado correctamente en la carpeta 'backupGuard':")
        print(f"- Base de datos: {backup_db_path}")
        print(f"- Clave maestra: {backup_password_path}")
    except Exception as e:
        print(f"Error al realizar el backup: {e}")

# Función para generar una contraseña segura
def generar_password(longitud=16):
    caracteres = string.ascii_letters + string.digits + string.punctuation
    password = ''.join(random.choice(caracteres) for _ in range(longitud))
    return password

# Función para cifrar la contraseña con AES
def cifrar_password(password, clave):
    password_con_verificacion = password + "END"
    clave_derivada = scrypt(clave.encode(), salt=b'salt', key_len=16, N=2**14, r=8, p=1)
    iv = get_random_bytes(AES.block_size)
    cipher = AES.new(clave_derivada, AES.MODE_CBC, iv)
    password_padded = password_con_verificacion + ' ' * (AES.block_size - len(password_con_verificacion) % AES.block_size)
    encrypted_password = cipher.encrypt(password_padded.encode())
    return base64.b64encode(iv + encrypted_password).decode()

# Función para descifrar la contraseña con AES
def descifrar_password(encrypted_password, clave):
    try:
        clave_derivada = scrypt(clave.encode(), salt=b'salt', key_len=16, N=2**14, r=8, p=1)
        encrypted_data = base64.b64decode(encrypted_password)
        iv = encrypted_data[:AES.block_size]
        cipher = AES.new(clave_derivada, AES.MODE_CBC, iv)
        decrypted_password = cipher.decrypt(encrypted_data[AES.block_size:]).decode().strip()
        if decrypted_password.endswith("END"):
            return decrypted_password[:-3]
        else:
            print("Error: la clave maestra introducida es incorrecta.")
            return None
    except (ValueError, UnicodeDecodeError):
        print("Error: la clave maestra introducida es incorrecta o los datos están dañados.")
        return None

# Función para guardar la clave maestra hashada
def guardar_clave_maestra(clave_maestra):
    hashed = bcrypt.hashpw(clave_maestra.encode(), bcrypt.gensalt())
    with open(RUTA_PASSWORD, 'wb') as f:
        f.write(hashed)

# Función para verificar la clave maestra hashada
def verificar_clave_maestra(clave_maestra):
    with open(RUTA_PASSWORD, 'rb') as f:
        hashed = f.read()
    return bcrypt.checkpw(clave_maestra.encode(), hashed)

# Función para guardar la contraseña en SQLite
def guardar_en_bd(servicio, encrypted_password):
    conn = sqlite3.connect(RUTA_DB)
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO guard (servicio, password_encriptada, algoritmo)
        VALUES (?, ?, ?)
    ''', (servicio, encrypted_password, 'AES-CBC'))
    conn.commit()
    conn.close()

# Función para listar todas las contraseñas encriptadas en la base de datos
def listar_contraseñas():
    conn = sqlite3.connect(RUTA_DB)
    cursor = conn.cursor()
    cursor.execute('SELECT servicio, password_encriptada FROM guard')
    registros = cursor.fetchall()
    conn.close()
    if registros:
        for registro in registros:
            print(f"Servicio: {registro[0]}, Password Encriptada: {registro[1]}")
    else:
        print("No hay contraseñas guardadas en el almacén.")

# Función para listar todas las contraseñas descifradas en la base de datos
def listar_contraseñas_descifradas(clave_maestra):
    conn = sqlite3.connect(RUTA_DB)
    cursor = conn.cursor()
    cursor.execute('SELECT servicio, password_encriptada FROM guard')
    registros = cursor.fetchall()
    conn.close()
    if registros:
        for servicio, encrypted_password in registros:
            password_descifrada = descifrar_password(encrypted_password, clave_maestra)
            if password_descifrada is not None:
                print(f"Servicio: {servicio}, Password Descifrada: {password_descifrada}")
    else:
        print("No hay contraseñas guardadas en el almacén.")

# Función para eliminar múltiples contraseñas específicas de la base de datos
def eliminar_contraseñas(servicios):
    conn = sqlite3.connect(RUTA_DB)
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
    conn.close()


# Función para exportar los datos a un archivo CSV
def exportar_a_csv():
    conn = sqlite3.connect(RUTA_DB)
    cursor = conn.cursor()
    cursor.execute('SELECT servicio, password_encriptada, algoritmo FROM guard')
    registros = cursor.fetchall()
    conn.close()
    
    if registros:
        with open('contraseñas_exportadas.csv', 'w', newline='', encoding='utf-8') as csvfile:
            writer = csv.writer(csvfile)
            writer.writerow(['Servicio', 'Password Encriptada', 'Algoritmo'])
            writer.writerows(registros)
        print("Los datos han sido exportados a 'contraseñas_exportadas.csv'.")
    else:
        print("No hay datos para exportar.")

# Nueva función para exportar los datos a un archivo CSV con contraseñas descifradas
def exportar_descifradas_a_csv(clave_maestra):
    conn = sqlite3.connect(RUTA_DB)
    cursor = conn.cursor()
    cursor.execute('SELECT servicio, password_encriptada, algoritmo FROM guard')
    registros = cursor.fetchall()
    conn.close()
    
    if registros:
        with open('contraseñas_descifradas.csv', 'w', newline='', encoding='utf-8') as csvfile:
            writer = csv.writer(csvfile)
            writer.writerow(['Servicio', 'Password Descifrada', 'Algoritmo'])
            for registro in registros:
                servicio, encrypted_password, algoritmo = registro
                password_descifrada = descifrar_password(encrypted_password, clave_maestra)
                if password_descifrada is not None:
                    writer.writerow([servicio, password_descifrada, algoritmo])
        print("Los datos han sido exportados a 'contraseñas_descifradas.csv'.")
    else:
        print("No hay datos para exportar.")

# Función para pedir y verificar la clave maestra
def solicitar_clave_maestra():
    if not os.path.exists(RUTA_PASSWORD):
        clave_maestra = validar_espacios(getpass.getpass("Para acceder a tu almacén de contraseñas protegidas, configura una clave maestra: ").strip(),"Clave maestra")
        clave_maestra_verificacion = getpass.getpass("Vuelve a introducir la clave maestra para verificar: ")
        
        if clave_maestra == clave_maestra_verificacion:
            guardar_clave_maestra(clave_maestra)
            if os.path.exists(RUTA_DB):
                renombrar_bd_antigua()
            inicializar_bd()  # Crear la base de datos nueva con la tabla si no existe
            print("Clave maestra configurada exitosamente.")
            return clave_maestra
        else:
            print("Las claves maestras no coinciden.")
            return None
    else:
        while True:
            clave_maestra = getpass.getpass("Introduce la clave maestra: ")
            if verificar_clave_maestra(clave_maestra):
                print("Acceso permitido.")
                return clave_maestra
            else:
                print("Clave incorrecta.")

# Función principal con opciones de menú
def menu():
    print("¡Bienvenido a GuardBox! tu gestor de contraseñas seguras.")
    
    clave_maestra = solicitar_clave_maestra()
    if not clave_maestra:
        return
    
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
            servicio = validar_espacios(input("Introduce el nombre del servicio: ").strip(), "Nombre del servicio")
            password = generar_password()
            encrypted_password = cifrar_password(password, clave_maestra)
            guardar_en_bd(servicio, encrypted_password)
            print(f"Contraseña generada y guardada para el servicio: {servicio}")
            print(f"Contraseña original: {password}")
        
        elif opcion == "2":
            servicio = validar_espacios(input("Introduce el nombre del servicio: ").strip(), "Nombre del servicio")
            password = validar_espacios(input("Introduce la contraseña a encriptar: ").strip(), "Contraseña")
            encrypted_password = cifrar_password(password, clave_maestra)
            guardar_en_bd(servicio, encrypted_password)
            print(f"Contraseña encriptada y guardada para el servicio: {servicio}")
        
        elif opcion == "3":
            sub_opcion = input("¿Deseas (L)istar encriptadas, (LD) listar descifradas o (E)liminar una o varias contraseñas? ").strip().upper()
            if sub_opcion == "L":
                listar_contraseñas()
            elif sub_opcion == "LD":
                listar_contraseñas_descifradas(clave_maestra)
            elif sub_opcion == "E":
                servicios = input("Introduce los nombres de los servicios a eliminar, separados por espacios: ").split()
                eliminar_contraseñas(servicios)
            else:
                print("Opción no válida. Intenta de nuevo.")
        
        elif opcion == "4":
            servicio = validar_espacios(input("Introduce el nombre del servicio a descifrar: ").strip(),"Nombre del servicio")
            conn = sqlite3.connect(RUTA_DB)
            cursor = conn.cursor()
            cursor.execute('SELECT password_encriptada FROM guard WHERE servicio = ?', (servicio,))
            registro = cursor.fetchone()
            conn.close()
            if registro:
                encrypted_password = registro[0]
                password_descifrada = descifrar_password(encrypted_password, clave_maestra)
                if password_descifrada is not None:
                    print(f"La contraseña descifrada para el servicio {servicio} es: {password_descifrada}")
                else:
                    print("No se pudo descifrar la contraseña. Verifica que la clave maestra sea correcta.")
            else:
                print("Servicio no encontrado.")
        
        elif opcion == "5":
            sub_opcion = input("¿Deseas exportar las contraseñas (C)ifradas o (D)escifradas: ").strip().upper()
            if sub_opcion == "C":
                exportar_a_csv()
            if sub_opcion == "D":
                exportar_descifradas_a_csv(clave_maestra)

        elif opcion == "6":
            realizar_backup()
        
        elif opcion == "7":
            print("Saliendo del programa...")
            break
        
        else:
            print("Opción no válida. Intenta de nuevo.")

# Ejecutar el menú
menu()

