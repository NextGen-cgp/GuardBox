# Constantes del sistema
ENCODING = 'utf-8'
DEFAULT_PASSWORD_LENGTH = 16
SCRYPT_PARAMS = {
    'N': 2**14,
    'r': 8,
    'p': 1,
    'key_len': 32
}
SALT_SIZE = 16
VERIFICATION_SUFFIX = "END"

# Mensajes de error
ERRORS = {
    'space_validation': "Error: {} no debe contener espacios ni estar vacío.",
    'master_mismatch': "Las claves maestras no coinciden.",
    'wrong_password': "Error: la clave maestra introducida es incorrecta.",
    'data_corrupted': "Error: la clave maestra introducida es incorrecta o los datos están dañados.",
    'no_passwords': "No hay contraseñas guardadas en el almacén.",
    'service_not_found': "El servicio '{}' no se ha encontrado en la base de datos.",
    'no_export_data': "No hay datos para exportar."
}