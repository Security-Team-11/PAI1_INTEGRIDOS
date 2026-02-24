import socket
import threading

# Configuración
PROXY_HOST = "127.0.0.1"
PROXY_PORT = 3031  # El cliente debe conectarse aquí
SERVER_HOST = "127.0.0.1"
SERVER_PORT = 3030 # El servidor real

def interceptar(cliente_sock):
    # Conectar al servidor real
    servidor_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    servidor_sock.connect((SERVER_HOST, SERVER_PORT))

    while True:
        # 1. Recibir datos del Cliente
        data = cliente_sock.recv(4096)
        if not data: break
        
        mensaje = data.decode()
        print(f"\n[MitM] Interceptado: {mensaje}")

        # 2. INTENTO DE ATAQUE: Modificar transferencia
        # Si el mensaje contiene "TRANSFER", intentamos cambiar la cuenta destino
        if "TRANSFER" in mensaje:
            print("[MitM] Detectada transferencia. Intentando modificar destino a 'cuenta_hacker'...")
            partes = mensaje.split("|")
            # partes: [nonce, comando, origen, destino, cantidad, mac]
            if len(partes) >= 5:
                partes[3] = "cuenta_hacker" # Alteramos el destino
                mensaje = "|".join(partes)
                print(f"[MitM] Mensaje modificado: {mensaje}")

        # 3. Enviar al servidor (ya sea el original o el modificado)
        servidor_sock.sendall(mensaje.encode())

        # 4. Recibir respuesta del servidor y devolver al cliente
        respuesta = servidor_sock.recv(4096)
        print(f"[MitM] Respuesta del servidor: {respuesta.decode()}")
        cliente_sock.sendall(respuesta)

    cliente_sock.close()
    servidor_sock.close()

if __name__ == "__main__":
    proxy = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    proxy.bind((PROXY_HOST, PROXY_PORT))
    proxy.listen(5)
    print(f"--- PROXY MITM ESCUCHANDO EN {PROXY_PORT} ---")

    while True:
        conn, addr = proxy.accept()
        threading.Thread(target=interceptar, args=(conn,)).start()