import socket
import sqlite3
import bcrypt
import hmac
import hashlib
import time

# --- CONFIGURACION ---
HOST = "127.0.0.1"
PORT = 3030
DB_FILE = "banco_seguro.db"

# CLAVE SECRETA
HMAC_SECRET_KEY = b'esta_es_una_clave_muy_segura_y_larga_para_evitar_bruteforce_2026'

# MEMORIA VOLATIL PARA SEGURIDAD
nonces_vistos = set()

# Control de Fuerza Bruta
intentos_fallidos = {}
MAX_INTENTOS = 5
TIEMPO_BLOQUEO_SEGUNDOS = 300  # 5 minutos


def conectar_db():
    return sqlite3.connect(DB_FILE)


def inicializar_db():
    con = conectar_db()
    cur = con.cursor()

    cur.execute(
        '''
        CREATE TABLE IF NOT EXISTS users (
            username TEXT PRIMARY KEY,
            password TEXT NOT NULL
        )
        '''
    )

    usuarios_base = [("admin", "admin123"), ("usuario1", "user123")]
    for user, pwd in usuarios_base:
        try:
            salt = bcrypt.gensalt()
            pw_hash = bcrypt.hashpw(pwd.encode(), salt).decode("utf-8")
            cur.execute("INSERT INTO users (username, password) VALUES (?, ?)", (user, pw_hash))
        except sqlite3.IntegrityError:
            pass

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
        nonce = partes[0]
        mac_recibido = partes[-1]
        datos_para_firmar = "|".join(partes[:-1])

        if nonce in nonces_vistos:
            return False, "ATAQUE REPLAY DETECTADO: Nonce reutilizado."

        mac_calculado = hmac.new(
            HMAC_SECRET_KEY, datos_para_firmar.encode(), hashlib.sha256
        ).hexdigest()

        if not hmac.compare_digest(mac_calculado, mac_recibido):
            return False, "FALLO INTEGRIDAD: La firma MAC no coincide."

        nonces_vistos.add(nonce)
        return True, partes[1:-1]

    except Exception as e:
        return False, f"Error de protocolo: {e}"


def procesar_comando(comando, args):
    con = conectar_db()
    cur = con.cursor()

    try:
        if comando == "REGISTER":
            if len(args) != 2:
                return "ERROR: Datos incorrectos"
            user, pwd = args[0], args[1]

            salt = bcrypt.gensalt()
            pw_hash = bcrypt.hashpw(pwd.encode(), salt).decode("utf-8")

            try:
                cur.execute("INSERT INTO users (username, password) VALUES (?, ?)", (user, pw_hash))
                con.commit()
                return "OK: Usuario registrado exitosamente."
            except sqlite3.IntegrityError:
                return "ERROR: El usuario ya existe."

        elif comando == "LOGIN":
            if len(args) != 2:
                return "ERROR: Datos incorrectos"
            user, pwd = args[0], args[1]

            info = intentos_fallidos.get(user)
            if info and info["count"] >= MAX_INTENTOS:
                restante = TIEMPO_BLOQUEO_SEGUNDOS - (time.time() - info["bloqueado_desde"])
                if restante > 0:
                    return f"ERROR: Usuario bloqueado temporalmente. Intenta en {int(restante)} segundos."
                intentos_fallidos.pop(user, None)

            cur.execute("SELECT password FROM users WHERE username = ?", (user,))
            row = cur.fetchone()

            if row and bcrypt.checkpw(pwd.encode(), row[0].encode()):
                intentos_fallidos.pop(user, None)
                return "OK: Inicio de sesion exitoso."
            else:
                if user not in intentos_fallidos:
                    intentos_fallidos[user] = {"count": 0, "bloqueado_desde": 0}
                intentos_fallidos[user]["count"] += 1

                if intentos_fallidos[user]["count"] >= MAX_INTENTOS:
                    intentos_fallidos[user]["bloqueado_desde"] = time.time()
                    return "ERROR: Demasiados intentos fallidos. Usuario bloqueado 5 minutos."

                time.sleep(2)
                return "ERROR: Credenciales invalidas."

        elif comando == "TRANSFER":
            if len(args) != 3:
                return "ERROR: Formato de transaccion incorrecto"
            origen, destino, cantidad = args[0], args[1], args[2]
            return f"OK: Transferencia de {cantidad} de {origen} a {destino} realizada con integridad."

        else:
            return "ERROR: Comando desconocido."

    finally:
        con.close()


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
                print(f"Conexion: {addr}")
                while True:
                    data = conn.recv(4096).decode()
                    if not data:
                        break

                    es_seguro, resultado = verificar_seguridad(data)

                    if not es_seguro:
                        print(f"ALERTA SEGURIDAD: {resultado}")
                        conn.sendall(f"ERROR_SEGURIDAD: {resultado}".encode())
                    else:
                        if not resultado:
                            continue

                        cmd = resultado[0]
                        argumentos = resultado[1:]

                        print(f"Procesando comando seguro: {cmd}")
                        respuesta = procesar_comando(cmd, argumentos)
                        conn.sendall(respuesta.encode())
