import socket
import psycopg2
import bcrypt
import os
import hmac
import hashlib
import base64
from datetime import datetime, timedelta


MAX_ATTEMPTS = 5
LOCK_TIME = timedelta(minutes=5)

# Diccionario en memoria para controlar bloqueos: {username: {"attempts": int, "locked_until": datetime}}
locked_users = {}
failed_attempts = {}

# Clave secreta para HMAC (en un sistema real debería venir de una variable de entorno)
HMAC_SECRET_KEY = b'secret_key_for_hmac'  # Cambia esto por una clave segura en producción

DB_CONFIG = {
    "dbname": "insegus",
    "user": "st09",
    "password": "paulaylucia",
    "host": "localhost",
    "port": "5432"
}

def generate_nonce(length = 16):
    """Genera un nonce aleatorio codificado en base64 URL-safe"""
    random_bytes = os.urandom(length)
    return base64.urlsafe_b64encode(random_bytes).decode("utf-8")

def generate_hmac(data, nonce, secret_key=HMAC_SECRET_KEY):
    """Genera un HMAC-SHA256 sobre (nonce || data)"""
    message = f"{nonce}:{data}".encode("utf-8")
    mac = hmac.new(secret_key, message, hashlib.sha256)
    return mac.hexdigest()

def verify_hmac(data, nonce, mac_hex):
    """Verifica que el HMAC recibido coincide con el calculado"""
    expected = generate_hmac(data, nonce)
    return hmac.compare_digest(expected, mac_hex)

def conectardb(): 
    try:
        con = psycopg2.connect(**DB_CONFIG)
        print("Conectado a la base de datos")
        return con, con.cursor()
    except Exception as e:
        print(f"Error al conectar a la base de datos: {e}")
        return None, None

def hash_password(password):
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(password.encode("utf-8"), salt)

def create_user_table():
    con, cursor = conectardb()
    if not con or not cursor:
        return
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id SERIAL PRIMARY KEY,
            username VARCHAR(50) UNIQUE NOT NULL,
            password VARCHAR(255) NOT NULL)
        ''')
    con.commit()
    cursor.close()
    con.close()

def register_user(username, password_hash):
    try:
        con, cursor = conectardb()
        if not con or not cursor:
            return
        cursor.execute("INSERT INTO users (username, password) VALUES (%s, %s)",
                        (username, password_hash.decode('utf-8')))
        con.commit()
        return True
    except psycopg2.IntegrityError:
        return False
    finally:
        if cursor:
            cursor.close()
        if con:
            con.close()

def verify_user(username, password):
    """Verifica las credenciales de un usuario contra la BD y gestiona bloqueos"""
    global locked_users, failed_attempts
    now = datetime.now()

    if username in locked_users:
        if now < locked_users[username]:
            # Usuario bloqueado: incrementar intentos fallidos
            return "Usuario bloqueado temporalmente"
        else: del locked_users[username]

    con, cursor = conectardb()
    if not con or not cursor:
        return False

    try:
        cursor.execute("SELECT password FROM users WHERE username = %s", (username,))
        user = cursor.fetchone()

        if not user:
            return "Acceso denegado: Credenciales incorrectas"

        stored_hash = user[0]

        if isinstance(stored_hash, memoryview):
            stored_hash = stored_hash.tobytes().decode("utf-8")

        if not bcrypt.checkpw(password.encode("utf-8"), stored_hash):
            failed_attempts[username] = failed_attempts.get(username, 0) + 1
            if failed_attempts[username] >= MAX_ATTEMPTS:
                # Bloquear usuario
                locked_users[username] = {
                    "locked_until": now + LOCK_TIME
                }
                return(f"Usuario '{username}' bloqueado por demasiados intentos fallidos")
            return "Acceso denegado: Bloqueado temporalmente"
        failed_attempts.pop(username, None)
        return "Acceso concedido"
    finally:
        if cursor:
            cursor.close()
        if con:
            con.close()