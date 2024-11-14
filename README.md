# GuardBox

## Descripción  
GuardBox es un gestor de contraseñas seguro basado en Python. Utiliza encriptación AES y almacenamiento seguro con una clave maestra protegida por hash de bcrypt. Permite generar, almacenar y recuperar contraseñas encriptadas, además de realizar backups y exportar datos.

## Características  
- Generación y almacenamiento seguro de contraseñas cifradas.
- Encriptación AES con clave derivada de scrypt.
- Almacenamiento en SQLite en una base de datos protegida.
- Funcionalidad de backup y exportación de datos a CSV (cifrados o descifrados).
- Clave maestra protegida con bcrypt.

## Ejecución  
El ejecutable del archivo se encuentra en la carpeta `\dist\GuardBox.exe`. Simplemente ejecuta este archivo para iniciar GuardBox.

## Uso  
1. Al iniciar GuardBox, configura una clave maestra.
2. Accede al menú principal y selecciona opciones como:
   - Generar y guardar contraseña aleatoria.
   - Encriptar y guardar una contraseña introducida.
   - Listar, desencriptar o eliminar contraseñas.
   - Exportar contraseñas a CSV.
   - Realizar un backup de la base de datos y clave maestra.

## Seguridad  
La clave maestra y la base de datos de contraseñas, se almacenan en un archivo seguro ubicado en la siguiente ruta user\AppData\Local\GestorCryptPass y todas las contraseñas se encriptan utilizando AES en modo CBC. La verificación de la clave maestra se realiza a través de bcrypt para mayor seguridad.

## Contribuciones  
Las contribuciones son bienvenidas. Por favor, crea una rama nueva y haz pull requests para sugerencias de mejora o nuevas características.

## Licencia  
Este proyecto está bajo la Licencia Creative Commons BY-NC.
