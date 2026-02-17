import socket

HOST = "127.0.0.1"
PORT = 3030

# Pega aquí un mensaje REAL capturado (nonce|comando|args...|mac)
REPLAY_MSG = "e3bff4c507df39d74eb09d09981ce4a7|TRANSFER|1 |2|3|bf67cd83cae12acc2ed7c52aaec33a0eeb3bc72f63fbb3c91f57b942aeacfa79"

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect((HOST, PORT))

    print("[1] Enviando primera vez...")
    s.sendall(REPLAY_MSG.encode())
    print("Respuesta:", s.recv(4096).decode())

    print("\n[2] Reenviando el MISMO mensaje (replay)...")
    s.sendall(REPLAY_MSG.encode())
    print("Respuesta:", s.recv(4096).decode())
