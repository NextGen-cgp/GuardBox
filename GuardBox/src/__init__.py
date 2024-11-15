"""
GuardBox - Gestor de Contraseñas Seguro
"""

from .password_manager import PasswordManager
from .crypto_utils import CryptoHandler
from .db_handler import DatabaseHandler
from .constants import *

__version__ = '2.0.0'
__author__ = 'CGP'
__email__ = 'soluciones.informaticas.cgp@email.com'

# Definir qué se expone cuando se hace "from guardbox import *"
__all__ = [
    'PasswordManager',
    'CryptoHandler',
    'DatabaseHandler'
]