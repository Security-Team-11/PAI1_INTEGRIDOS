import socket
import sqlite3
import bcrypt
import hmac
import hashlib
import time
import os

# --- CONFIGURACIÓN ---
HOST = "127.0.0.1"
PORT = 3030
DB_FILE = "banco_seguro.db"

# CLAVE SECRETA (Debe ser larga y compleja para evitar ataques de fuerza bruta a la clave)
# En un entorno real, esto estaría en variables de entorno.
HMAC_SECRET_KEY = b'esta_es_una_clave_muy_segura_y_larga_para_evitar_bruteforce_2026'

# MEMORIA VOLÁTIL PARA SEGURIDAD
# Almacena los Nonces usados para evitar ataques de Replay
nonces_vistos = set()

# Control de Fuerza Bruta (IP o Usuario)
intentos_fallidos = {}

def conectar_db():
    return sqlite3.connect(DB_FILE)

def inicializar_db():
    """Cumple el requisito de Persistencia y Usuarios Preexistentes."""
    con = conectar_db()
    cur = con.cursor()
    
    # Tabla de Usuarios
    cur.execute('''
        CREATE TABLE IF NOT EXISTS users (
            username TEXT PRIMARY KEY,
            password TEXT NOT NULL
        )
    ''')
    
    # Crear usuarios preexistentes si no existen (Requisito 5)
    usuarios_base = [("admin", "admin123"), ("usuario1", "user123")]
    for user, pwd in usuarios_base:
        try:
            salt = bcrypt.gensalt()
            pw_hash = bcrypt.hashpw(pwd.encode(), salt).decode('utf-8')
            cur.execute("INSERT INTO users (username, password) VALUES (?, ?)", (user, pw_hash))
        except sqlite3.IntegrityError:
            pass # Ya existen
            
    con.commit()
    con.close()
    print(f"--- BASE DE DATOS '{DB_FILE}' INICIALIZADA ---")

def verificar_seguridad(datos_raw):
    """
    Verifica Integridad (MAC) y Anti-Replay (Nonce).
    Formato esperado: NONCE|COMANDO|ARGUMENTOS|MAC
    """
    try:
        partes = datos_raw.split("|")
        # El MAC siempre es el último elemento
        nonce = partes[0]
        mac_recibido = partes[-1]
        
        # Reconstruir el mensaje sin el MAC para calcularlo nosotros
        # El mensaje que se firmó fue: NONCE + COMANDO + ARGUMENTOS
        datos_para_firmar = "|".join(partes[:-1]) 
        
        # 1. VERIFICAR REPLAY (Requisito Seguridad)
        if nonce in nonces_vistos:
            return False, "ATAQUE REPLAY DETECTADO: Nonce reutilizado."
        
        # 2. VERIFICAR INTEGRIDAD (MAC)
        mac_calculado = hmac.new(HMAC_SECRET_KEY, datos_para_firmar.encode(), hashlib.sha256).hexdigest()
        
        # Usamos compare_digest para evitar ataques de canal lateral (Timing Attacks)
        if not hmac.compare_digest(mac_calculado, mac_recibido):
            return False, "FALLO INTEGRIDAD: La firma MAC no coincide."
            
        # Si todo es correcto, guardamos el Nonce y devolvemos los datos limpios
        nonces_vistos.add(nonce)
        # Devolvemos el comando y los argumentos (quitamos nonce y mac)
        return True, partes[1:-1] 
        
    except Exception as e:
        return False, f"Error de protocolo: {e}"

def procesar_comando(comando, args):
    """Lógica de negocio del Banco."""
    con = conectar_db()
    cur = con.cursor()
    
    try:
        if comando == "REGISTER":
            # Args: Usuario, Password
            if len(args) != 2: return "ERROR: Datos incorrectos"
            user, pwd = args[0], args[1]
            
            salt = bcrypt.gensalt()
            pw_hash = bcrypt.hashpw(pwd.encode(), salt).decode('utf-8')
            
            try:
                cur.execute("INSERT INTO users (username, password) VALUES (?, ?)", (user, pw_hash))
                con.commit()
                return "OK: Usuario registrado exitosamente."
            except sqlite3.IntegrityError:
                return "ERROR: El usuario ya existe."
                
        elif comando == "LOGIN":
            # Args: Usuario, Password
            if len(args) != 2: return "ERROR: Datos incorrectos"
            user, pwd = args[0], args[1]
            
            cur.execute("SELECT password FROM users WHERE username = ?", (user,))
            row = cur.fetchone()
            
            if row and bcrypt.checkpw(pwd.encode(), row[0].encode()):
                return "OK: Inicio de sesion exitoso."
            else:
                # Protección contra fuerza bruta (Retardo)
                time.sleep(2) 
                return "ERROR: Credenciales invalidas."
                
        elif comando == "TRANSFER":
            # Args: Origen, Destino, Cantidad
            # Requisito 6: No validar cuentas, solo formato.
            if len(args) != 3: return "ERROR: Formato de transaccion incorrecto"
            origen, destino, cantidad = args[0], args[1], args[2]
            
            # Aquí solo confirmamos integridad, no saldo real (según el enunciado)
            return f"OK: Transferencia de {cantidad} de {origen} a {destino} realizada con integridad."
            
        else:
            return "ERROR: Comando desconocido."
            
    finally:
        con.close()

# --- BUCLE PRINCIPAL ---
if __name__ == "__main__":
    inicializar_db()
    
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((HOST, PORT))
        s.listen()
        print(f"--- SERVIDOR BANCO SEGURO ESCUCHANDO EN {PORT} ---")
        
        while True:
            conn, addr = s.accept()
            with conn:
                print(f"Conexión: {addr}")
                while True:
                    data = conn.recv(4096).decode()
                    if not data: break
                    
                    # 1. VERIFICAR SEGURIDAD
                    es_seguro, resultado = verificar_seguridad(data)
                    
                    if not es_seguro:
                        print(f"ALERTA SEGURIDAD: {resultado}")
                        conn.sendall(f"ERROR_SEGURIDAD: {resultado}".encode())
                    else:
                        # 2. PROCESAR SI ES SEGURO
                        # resultado es una lista: [COMANDO, ARG1, ARG2...]
                        if not resultado: continue # Lista vacia
                        
                        cmd = resultado[0]
                        argumentos = resultado[1:]
                        
                        print(f"Procesando comando seguro: {cmd}")
                        respuesta = procesar_comando(cmd, argumentos)
                        conn.sendall(respuesta.encode())