import socket
import uuid
import os
from src.network import enviar_frame_tcp, receber_frame_tcp
from src.crypto import (
    gerar_chaves_efemeras,
    verificar_handshake_servidor,
    calcular_segredo_e_derivar_chaves,
    cifrar_mensagem_e2e,
    decifrar_mensagem_e2e
)

HOST = "127.0.0.1"
PORT = 6767
CLIENT_ID_STR = str(uuid.uuid4())
CERT_PINADO_PATH = "certs/server.crt"
MSG_TYPE_CLIENT_HELLO = 0x01

def main():
    print(f"[*] Iniciando cliente com ID (UUID v4): {CLIENT_ID_STR}")
    
    priv_client, pk_client = gerar_chaves_efemeras()
    print("[+] RC01: Chaves efêmeras X25519 geradas localmente.")

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((HOST, PORT))
    print(f"[+] RC02: Conectado ao servidor em {HOST}:{PORT}")

    client_id_bytes = uuid.UUID(CLIENT_ID_STR).bytes
    payload_handshake = bytes([MSG_TYPE_CLIENT_HELLO]) + client_id_bytes + pk_client
    enviar_frame_tcp(sock, payload_handshake)
    print("[+] RC02: Frame CLIENT_HELLO enviado com sucesso.")

    resposta_servidor = receber_frame_tcp(sock)
    if resposta_servidor[0] != 0x02:
        raise ValueError("Esperado SERVER_HELLO (0x02)")
    
    body = resposta_servidor[1:]
    offset = 0
    pk_server_raw = body[offset:offset+32]; offset += 32
    salt_srv = body[offset:offset+16]; offset += 16
    
    sig_len = int.from_bytes(body[offset:offset+2], byteorder='big'); offset += 2
    assinatura = body[offset:offset+sig_len]; offset += sig_len
    
    cert_len = int.from_bytes(body[offset:offset+2], byteorder='big'); offset += 2
    cert_servidor_bytes = body[offset:offset+cert_len]

    verificar_handshake_servidor(
        cert_servidor_bytes=cert_servidor_bytes,
        caminho_cert_pinado=CERT_PINADO_PATH,
        pk_server_raw=pk_server_raw,
        pk_client_raw=pk_client,
        client_id_bytes=client_id_bytes,
        salt_srv=salt_srv,
        assinatura=assinatura
    )
    print("[+] RC03: Servidor autenticado com sucesso via RSA-PSS e Pinning[cite: 16]!")

    priv_peer_falso, pk_peer_falso = gerar_chaves_efemeras()
    peer_id_bytes = uuid.uuid4().bytes
    
    key_a2b, key_b2a = calcular_segredo_e_derivar_chaves(priv_client, pk_peer_falso, salt_srv)
    print("[+] RC04: Chaves E2E derivadas com sucesso via HKDF-SHA256[cite: 9, 10, 16]!")

    peers = {
        peer_id_bytes: {
            "public_key": pk_peer_falso,
            "key_send": key_a2b,
            "key_recv": key_b2a,
            "seq_send": 0,
            "seq_recv": -1, 
            "IV_base_send": os.urandom(4),
            "IV_base_recv": os.urandom(4)
        }
    }

    peer_session = peers[peer_id_bytes]

    mensagem = b"Mensagem secreta validada ponta a ponta!"
    
    frame_e2e, peer_session["seq_send"] = cifrar_mensagem_e2e(
        peer_session["key_send"],
        peer_session["IV_base_send"],
        peer_session["seq_send"],
        client_id_bytes,
        peer_id_bytes,
        mensagem
    )
    print(f"[+] RC05: Mensagem cifrada com AES-128-GCM e frame E2E gerado ({len(frame_e2e)} bytes)[cite: 8, 11, 17].")

    print("[*] Simulando recepção do frame pelo destinatário...")
    
    
    plaintext, sender_id, recipient_id, seq_no = decifrar_mensagem_e2e(
        peer_session["key_send"], # Chave simétrica correspondente
        frame_e2e,
        peer_session["seq_recv"]
    )
    peer_session["seq_recv"] = seq_no 
    
    print(f"[+] RC06/RC07/RC08: Mensagem decifrada com sucesso: '{plaintext.decode('utf-8')}'[cite: 17, 18]")

    #TESTE DE ADULTERAÇÃO
    print("\n[*] Executando teste obrigatório: Adulteração de payload (Bitflip)...")
    frame_adulterado = bytearray(frame_e2e)
    frame_adulterado[-1] ^= 0xFF # Altera o último byte da tag GCM
    
    try:
        decifrar_mensagem_e2e(peer_session["key_send"], bytes(frame_adulterado), peer_session["seq_recv"])
    except ValueError as e:
        print(f"[+] SUCESSO NO TESTE DE TAMPERING: {e}[cite: 18]")

    #TESTE DE REPLAY
    print("\n[*] Executando teste obrigatório: Ataque Replay (Reenvio do mesmo seq_no)...")
    try:
        decifrar_mensagem_e2e(peer_session["key_send"], frame_e2e, peer_session["seq_recv"])
    except ValueError as e:
        print(f"[+] SUCESSO NO TESTE DE REPLAY: {e}[cite: 18]")

    sock.close()

if __name__ == "__main__":
    main()