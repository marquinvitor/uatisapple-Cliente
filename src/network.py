import socket
from src.crypto import gerar_chaves_efemeras

def enviar_frame_tcp(sock: socket.socket, payload: bytes):
    """envia um payload prefixado por um tamanho de 4 bytes"""
    tamanho = len(payload)
    header = tamanho.to_bytes(4, byteorder='big')
    sock.sendall(header + payload)

def receber_frame_tcp(sock: socket.socket) -> bytes:
    """lê o prefixo de 4 bytes e em seguida lê exatamente o tamanho do frame especificado."""
    header = sock.recv(4)
    if not header:
        raise ConnectionError("[-] Conexão encerrada pelo servidor durante a leitura do framing.")
    
    tamanho = int.from_bytes(header, byteorder='big')
    
    dados = bytearray()
    while len(dados) < tamanho:
        chunk = sock.recv(tamanho - len(dados))
        if not chunk:
            raise ConnectionError("[-] Conexão perdida enquanto recebia os dados do frame.")
        dados.extend(chunk)
        
    return bytes(dados)
