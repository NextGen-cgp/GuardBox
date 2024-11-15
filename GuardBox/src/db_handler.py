import sqlite3
from typing import List, Tuple
import csv
from datetime import datetime
from src.constants import *

class DatabaseHandler:
    """Maneja las operaciones de base de datos"""
    
    def __init__(self, db_path: str):
        self.db_path = db_path
        self._initialize_database()

    def _initialize_database(self):
        with sqlite3.connect(self.db_path) as conn:
            conn.execute('''
                CREATE TABLE IF NOT EXISTS guard (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    servicio TEXT NOT NULL,
                    password_encriptada TEXT NOT NULL,
                    algoritmo TEXT NOT NULL
                )
            ''')

    def save_password(self, service: str, encrypted_password: str):
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                'INSERT INTO guard (servicio, password_encriptada, algoritmo) VALUES (?, ?, ?)',
                (service, encrypted_password, 'AES-CBC')
            )

    def get_all_passwords(self) -> List[Tuple[str, str]]:
        with sqlite3.connect(self.db_path) as conn:
            return conn.execute(
                'SELECT servicio, password_encriptada FROM guard'
            ).fetchall()

    def get_password(self, service: str) -> str:
        with sqlite3.connect(self.db_path) as conn:
            result = conn.execute(
                'SELECT password_encriptada FROM guard WHERE servicio = ?',
                (service,)
            ).fetchone()
            return result[0] if result else None

    def delete_passwords(self, services: List[str]):
        with sqlite3.connect(self.db_path) as conn:
            for service in services:
                exists = conn.execute(
                    'SELECT COUNT(*) FROM guard WHERE servicio = ?',
                    (service,)
                ).fetchone()[0]
                
                if exists:
                    conn.execute('DELETE FROM guard WHERE servicio = ?', (service,))
                    yield service, True
                else:
                    yield service, False
    def close_connection(self):
    #Cierra la conexión a la base de datos.
        try:
            if hasattr(self, 'conn') and self.conn:
                self.conn.close()
        except Exception as e:
            print(f"Error al cerrar la conexión: {e}")

    def export_to_csv(self, filename: str, data: List[Tuple]):
        if not data:
            raise ValueError(ERRORS['no_export_data'])
            
        with open(filename, 'w', newline='', encoding=ENCODING) as csvfile:
            writer = csv.writer(csvfile)
            writer.writerow(['Servicio', 'Password', 'Algoritmo'])
            writer.writerows(data)