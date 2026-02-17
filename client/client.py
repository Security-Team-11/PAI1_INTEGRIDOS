import socket
import hmac
import hashlib
import secrets # Para generar nonces seguros criptográficamente
import sys
import getpass

HOST = "127.0.0.1"
PORT = 3030
HMAC_SECRET_KEY = b'esta_es_una_clave_muy_segura_y_larga_para_evitar_bruteforce_2026'

def generar_nonce():
    """Genera un nonce aleatorio seguro (hexadecimal)."""
    return secrets.token_hex(16)

def enviar_comando_seguro(sock, comando, *args):
    """
    Empaqueta los datos con Seguridad:
    FORMATO: NONCE|COMANDO|ARG1|ARG2...|MAC
    """
    nonce = generar_nonce()
    
    # Construir la carga útil (Payload)
    # Ejemplo: a1b2...|LOGIN|pepe|1234
    partes = [nonce, comando] + list(args)
    mensaje_sin_mac = "|".join(partes)
    
    # Calcular MAC sobre todo lo anterior
    mac = hmac.new(HMAC_SECRET_KEY, mensaje_sin_mac.encode(), hashlib.sha256).hexdigest()
    
    # Mensaje final
    mensaje_final = f"{mensaje_sin_mac}|{mac}"
    
    sock.sendall(mensaje_final.encode())
    respuesta = sock.recv(4096).decode()
    print("DEBUG SENT:", mensaje_final)
    return respuesta

# --- INTERFAZ DE USUARIO ---

def menu_principal():
    print("\n--- BANCO SEGURO: MENÚ PRINCIPAL ---")
    print("1. Registrarse")
    print("2. Iniciar Sesión")
    print("3. Salir")
    return input("Seleccione una opción: ")

def menu_sesion(usuario):
    print(f"\n--- BIENVENIDO {usuario} ---")
    print("1. Realizar Transferencia")
    print("2. Cerrar Sesión")
    return input("Seleccione una opción: ")

if __name__ == "__main__":
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((HOST, PORT))
    except ConnectionRefusedError:
        print("ERROR: No se puede conectar al servidor. Asegúrate de iniciar server.py primero.")
        sys.exit()

    usuario_actual = None

    while True:
        if usuario_actual is None:
            opcion = menu_principal()
            
            if opcion == "1": # REGISTER
                u = input("Nuevo Usuario: ")
                p = getpass.getpass("Contraseña: ")
                resp = enviar_comando_seguro(s, "REGISTER", u, p)
                print(f"\nSERVIDOR: {resp}")
                
            elif opcion == "2": # LOGIN
                u = input("Usuario: ")
                p = getpass.getpass("Contraseña: ")
                resp = enviar_comando_seguro(s, "LOGIN", u, p)
                print(f"\nSERVIDOR: {resp}")
                if "OK" in resp:
                    usuario_actual = u
                    
            elif opcion == "3": # SALIR
                print("Saliendo...")
                break
            else:
                print("Opción no válida.")
                
        else:
            # ESTAMOS LOGUEADOS
            opcion = menu_sesion(usuario_actual)
            
            if opcion == "1": # TRANSFERENCIA
                # Requisito 6: Origen, Destino, Cantidad
                print("\n--- NUEVA TRANSFERENCIA ---")
                origen = input("Cuenta Origen: ") # Normalmente sería usuario_actual, pero el requisito pide escribirlo
                destino = input("Cuenta Destino: ")
                cantidad = input("Cantidad (€): ")
                
                resp = enviar_comando_seguro(s, "TRANSFER", origen, destino, cantidad)
                print(f"\nRESULTADO: {resp}")
                
            elif opcion == "2": # LOGOUT
                usuario_actual = None
                print("\nSesión cerrada.")
            else:
                print("Opción no válida.")

    s.close()