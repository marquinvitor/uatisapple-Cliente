from cryptography.hazmat.primitives.asymmetric import x25519, padding, utils
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography import x509
from cryptography.exceptions import InvalidSignature, InvalidTag
import hashlib
import struct
import uuid


MSG_TYPE_E2E = 0x10

def gerar_chaves_efemeras():
    """gera par de chaves X25519 e retorna a chave pública em 32 bytes puro"""
    private_key = x25519.X25519PrivateKey.generate()
    public_key = private_key.public_key()
    pk_C = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )
    return private_key, pk_C


def verificar_handshake_servidor(
    cert_servidor_bytes: bytes, 
    caminho_cert_pinado: str, 
    pk_server_raw: bytes, 
    pk_client_raw: bytes, 
    client_id_bytes: bytes, 
    salt_srv: bytes, 
    assinatura: bytes
):
    """valida o certificdo pinado e a assinatura rsa-pss do servidor."""

    cert_recebido = x509.load_der_x509_certificate(cert_servidor_bytes)
    with open(caminho_cert_pinado, "rb") as f:
        cert_pinado_bytes = f.read()
    
    cert_pinado = x509.load_pem_x509_certificate(cert_pinado_bytes) if b"BEGIN CERTIFICATE" in cert_pinado_bytes else x509.load_der_x509_certificate(cert_pinado_bytes)
    
    if cert_recebido.public_bytes(serialization.Encoding.DER) != cert_pinado.public_bytes(serialization.Encoding.DER):
        raise ValueError("[-] ALERTA: Falha no Certificate Pinning (MitM detectado)!")

    #reconstrucao do hash H = SHA256(pk_server || pk_client || client_id || salt)
    h_data = pk_server_raw + pk_client_raw + client_id_bytes + salt_srv
    digest_h = hashlib.sha256(h_data).digest()

    #padding pss igualzin ao configurado no servidor
    client_pss_padding = padding.PSS(
        mgf=padding.MGF1(hashes.SHA256()),
        salt_length=padding.PSS.DIGEST_LENGTH
    )

    #verificacao da Assinatura rsa-pss com Prehashed
    chave_publica_servidor = cert_recebido.public_key()
    try:
        chave_publica_servidor.verify(
            assinatura,
            digest_h,
            client_pss_padding,
            utils.Prehashed(hashes.SHA256())
        )
        print("[+] Assinatura RSA-PSS do servidor verificada com sucesso!")
        return True
    except InvalidSignature:
        raise ValueError("[-] FALHA: Assinatura RSA-PSS invalida do servidor!")


def calcular_segredo_e_derivar_chaves(priv_client_sk: x25519.X25519PrivateKey, pk_peer_bytes: bytes, salt_srv: bytes):
    """calcula o segredo compartilhado via ECDH e deriva as chaves simétricas A2B e B2A via HKDF-SHA256."""
    #reconstroi o objeto de chave pública do peer a partir dos 32 bytes
    pk_peer_obj = x25519.X25519PublicKey.from_public_bytes(pk_peer_bytes)
    
    #calcula o segredo compartilhado Z_AB (IKM para o HKDF)
    z_ab = priv_client_sk.exchange(pk_peer_obj)
    
    #derivacao de chaves simétricas usando HKDF-SHA256 (com salt_srv de 16 bytes)
    #key_A2B (para enviar)
    key_a2b = HKDF(
        algorithm=hashes.SHA256(),
        length=16,  # AES-128 exige 16 bytes
        salt=salt_srv,
        info=b"A2B",
    ).derive(z_ab)
    
    #key_B2A (para receber)
    key_b2a = HKDF(
        algorithm=hashes.SHA256(),
        length=16,
        salt=salt_srv,
        info=b"B2A",
    ).derive(z_ab)
    
    print("[+] RC04: Segredo Z_AB calculado e chaves simetricas E2E derivadas com sucesso via HKDF!")
    return key_a2b, key_b2a   


def cifrar_mensagem_e2e(
    key_a2b: bytes, 
    iv_base_send: bytes, 
    seq_send: int, 
    sender_id_bytes: bytes, 
    recipient_id_bytes: bytes, 
    plaintext: bytes
) -> tuple[bytes, int]:
    """incrementa contador, constroi o nonce, monta o AAD, cifra com AES-128-GCM e retorna o frame E2E completo para envio."""
    #incrementa o contador seq_send
    seq_send += 1
    
    #monta o nonce de 12 bytes: IV_base (4B) || seq_no (8B, Big-Endian)
    seq_bytes = struct.pack(">Q", seq_send)
    nonce = iv_base_send + seq_bytes
    
    #monta o AAD (Associated Data): sender_id (16B) || recipient_id (16B) || seq_no (8B)
    aad = sender_id_bytes + recipient_id_bytes + seq_bytes
    
    #cifra os dados usando AES-128-GCM (o AESGCM ja concatena a tag de 16 bytes ao final do ciphertext)
    aesgcm = AESGCM(key_a2b)
    ciphertext_com_tag = aesgcm.encrypt(nonce, plaintext, aad)
    
    #monta o frame E2E completo:
    # [Tipo (0x10)] + [Nonce (12B)] + [sender_id (16B)] + [recipient_id (16B)] + [seq_no (8B)] + [ciphertext+tag]
    frame_e2e = (
        bytes([MSG_TYPE_E2E])
        + nonce
        + aad  # O AAD ja tem sender_id, recipient_id e seq_bytes
        + ciphertext_com_tag
    )
    
    return frame_e2e, seq_send


def decifrar_mensagem_e2e(
    key_b2a: bytes, 
    frame_recebido: bytes,
    seq_recv_atual: int = -1
) -> tuple[bytes, uuid.UUID, uuid.UUID, int]:
    """desmonta o frame E2E recebido, valida o anti-replay, reconstrói o nonce e o AAD, e decifra a mensagem validando a tag GCM."""
    #valida o tipo de mensagem E2E (0x10)
    if frame_recebido[0] != MSG_TYPE_E2E:
        raise ValueError("Frame recebido não é do tipo E2E (0x10)")
        
    offset = 1
    
    #extrai o nonce (12 bytes)
    nonce = frame_recebido[offset:offset+12]
    offset += 12
    
    #extrai o sender_id (16 bytes)
    sender_id_bytes = frame_recebido[offset:offset+16]
    offset += 16
    
    #extrai o recipient_id (16 bytes)
    recipient_id_bytes = frame_recebido[offset:offset+16]
    offset += 16
    
    #extrai o seq_no (8 bytes)
    seq_bytes = frame_recebido[offset:offset+8]
    (seq_no,) = struct.unpack(">Q", seq_bytes)
    offset += 8
    
    #o que sobra é o ciphertext + tag de 16 bytes
    ciphertext_com_tag = frame_recebido[offset:]
    
    #reconstroi o AAD para validar a integridade
    aad = sender_id_bytes + recipient_id_bytes + seq_bytes
    
    #protecao antireplay
    if seq_no <= seq_recv_atual:
        raise ValueError(f"[-] REJECTED: Ataque Replay detectado! seq_no {seq_no} menor ou igual ao último visto ({seq_recv_atual}).")
    
    #decifragem e antitampering
    try:
        aesgcm = AESGCM(key_b2a)
        plaintext = aesgcm.decrypt(nonce, ciphertext_com_tag, aad)
    except InvalidTag:
        raise ValueError("[-] REJECTED: Falha na Tag GCM! Mensagem adulterada ou corrompida na rede (Anti-Tampering).")
    
    return plaintext, uuid.UUID(bytes=sender_id_bytes), uuid.UUID(bytes=recipient_id_bytes), seq_no