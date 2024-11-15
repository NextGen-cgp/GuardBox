
from src.password_manager import PasswordManager

def show_menu():
    """Muestra el menú principal."""
    return """
--- Gestor de Contraseñas ---
1) Generar y guardar contraseña aleatoria
2) Guardar contraseña manual
3) Listar o eliminar contraseñas
4) Desencriptar contraseña
5) Exportar contraseñas a CSV
6) Realizar backup
7) Salir
Selecciona una opción: """

def main():
    """Función principal del programa."""
    pm = PasswordManager()
    
    if not pm.initialize_master_key():
        return
    
    print("¡Bienvenido a GuardBox!")
    
    actions = {
        "1": lambda: pm.save_password(
            pm.validate_input(input("Servicio: ").strip(), "servicio"),
            pm.generate_password()
        ),
        "2": lambda: pm.save_password(
            pm.validate_input(input("Servicio: ").strip(), "servicio"),
            pm.validate_input(input("Contraseña: ").strip(), "contraseña")
        ),
        "3": lambda: pm.handle_password_listing(
            input("(L)istar encriptadas, (LD) listar descifradas o (E)liminar: ").strip().upper()
        ),
        "4": lambda: print(pm.get_password(
            pm.validate_input(input("Servicio: ").strip(), "servicio")
        ) or "Servicio no encontrado"),
        "5": lambda: pm.handle_export(
            input("Exportar (C)ifradas o (D)escifradas: ").strip().upper()
        ),
        "6": lambda: pm.create_backup(),
        "7": lambda: print("¡Hasta pronto!")
    }
    
    while True:
        option = input(show_menu())
        
        if option == "7":
            break
            
        action = actions.get(option)
        if action:
            action()
        else:
            print("Opción no válida")