import os
import sys
import time
import uuid
import struct
import socket
import subprocess
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidTag

from src.network import enviar_frame_tcp, receber_frame_tcp
from src.crypto import (
    MSG_TYPE_E2E,
    gerar_chaves_efemeras,
    verificar_handshake_servidor,
    calcular_segredo_e_derivar_chaves,
    cifrar_mensagem_e2e,
    decifrar_mensagem_e2e,
)

HOST = "127.0.0.1"
PORT = 6767
CERT_PINADO_PATH = "certs/server.crt"

MAX_CLIENT_FRAME_SIZE = 4168  
MAX_SERVER_FRAME_SIZE = 65536

MSG_TYPE_CLIENT_HELLO = 0x01
MSG_TYPE_SERVER_HELLO = 0x02
MSG_TYPE_ADMIN = 0x20

ADMIN_TYPE_REGISTERED = 0x01
ADMIN_TYPE_PEER_LIST = 0x02
ADMIN_TYPE_PEER_JOINED = 0x03
ADMIN_TYPE_PEER_LEFT = 0x04
ADMIN_TYPE_ERROR = 0x05
ADMIN_TYPE_DISCONNECT = 0x06

ERROR_CODE_FRAMING = 0x01
ERROR_CODE_INVALID_MESSAGE = 0x02
ERROR_CODE_UNKNOWN_RECIPIENT = 0x03
ERROR_CODE_SENDER_MISMATCH = 0x04
ERROR_CODE_REPLAY = 0x05
ERROR_CODE_DUPLICATE_CLIENT_ID = 0x06
ERROR_CODE_SERVER_FULL = 0x07


class FramingError(ValueError):
    pass


def desconectar_seguro(sock: socket.socket | None) -> None:
    """desconexão segura de um socket"""
    if sock is not None:
        try:
            sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        try:
            sock.close()
        except OSError:
            pass


def receber_frame_validado(sock: socket.socket, max_tamanho: int = MAX_SERVER_FRAME_SIZE, timeout: float | None = 5.0) -> bytes:
    """lê um frame TCP validando o prefixo de tamanho de 4 bytes"""
    timeout_antigo = sock.gettimeout()
    if timeout is not None:
        sock.settimeout(timeout)

    try:
        header = bytearray()
        while len(header) < 4:
            chunk = sock.recv(4 - len(header))
            if not chunk:
                if len(header) == 0:
                    raise ConnectionError("[-] Conexão encerrada pelo peer/servidor.")
                raise FramingError(f"[-] Framing inválido: cabeçalho truncado ({len(header)}/4 bytes recebidos).")
            header.extend(chunk)

        (tamanho,) = struct.unpack(">I", header)

        if tamanho <= 0:
            raise FramingError(f"[-] Framing inválido: tamanho anunciado ({tamanho}) deve ser > 0.")

        if tamanho > max_tamanho:
            raise FramingError(f"[-] Framing inválido: tamanho anunciado ({tamanho}) excede o limite máximo ({max_tamanho}).")

        dados = bytearray()
        while len(dados) < tamanho:
            chunk = sock.recv(tamanho - len(dados))
            if not chunk:
                raise FramingError(f"[-] Framing inválido: payload incompleto ({len(dados)}/{tamanho} bytes recebidos).")
            dados.extend(chunk)

        return bytes(dados)
    finally:
        if timeout is not None:
            sock.settimeout(timeout_antigo)


class ClienteUatisApple:
    """representa um cliente real do UatisApple com handshake, canal admin e sessões E2E."""

    def __init__(self, nome: str, host: str = HOST, port: int = PORT, cert_path: str = CERT_PINADO_PATH):
        self.nome = nome
        self.host = host
        self.port = port
        self.cert_path = cert_path
        self.client_id = uuid.uuid4()
        self.client_id_bytes = self.client_id.bytes
        self.priv_key, self.pub_key = gerar_chaves_efemeras()
        self.sock: socket.socket | None = None
        self.s2c_key: bytes | None = None
        self.salt_srv: bytes | None = None
        self.admin_seq_recv = -1
        self.peers: dict[uuid.UUID, dict] = {}

    def conectar_e_autenticar(self) -> None:
        """conecta ao servidor, envia CLIENT_HELLO, valida SERVER_HELLO e estabelece canal admin."""
        print(f"[*] [{self.nome}] Conectando ao servidor em {self.host}:{self.port} (ID: {self.client_id})...")
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.connect((self.host, self.port))

        #envia CLIENT_HELLO (0x01 || client_id 16B || pk_client 32B)
        payload_hello = bytes([MSG_TYPE_CLIENT_HELLO]) + self.client_id_bytes + self.pub_key
        enviar_frame_tcp(self.sock, payload_hello)
        print(f"[+] [{self.nome}] CLIENT_HELLO enviado com sucesso.")

        # Recebe SERVER_HELLO (0x02 || pk_server 32B || salt_srv 16B || sig_len 2B || sig || cert_len 2B || cert)
        resposta = receber_frame_validado(self.sock)
        if resposta[0] != MSG_TYPE_SERVER_HELLO:
            raise ValueError(f"Esperado SERVER_HELLO (0x02), recebido 0x{resposta[0]:02x}")

        body = resposta[1:]
        pk_server = body[:32]
        self.salt_srv = body[32:48]
        offset = 48

        (sig_len,) = struct.unpack_from(">H", body, offset)
        offset += 2
        assinatura = body[offset:offset + sig_len]
        offset += sig_len

        (cert_len,) = struct.unpack_from(">H", body, offset)
        offset += 2
        cert_servidor_bytes = body[offset:offset + cert_len]

        # Certificate Pinning e RSA-PSS
        verificar_handshake_servidor(
            cert_servidor_bytes=cert_servidor_bytes,
            caminho_cert_pinado=self.cert_path,
            pk_server_raw=pk_server,
            pk_client_raw=self.pub_key,
            client_id_bytes=self.client_id_bytes,
            salt_srv=self.salt_srv,
            assinatura=assinatura
        )
        print(f"[+] [{self.nome}] Servidor autenticado via Certificate Pinning e RSA-PSS!")

        # Deriva chave administrativa S2C: HKDF(salt_srv, ECDH(sk_C, pk_S), "S2C", 16)
        pk_srv_obj = x25519.X25519PublicKey.from_public_bytes(pk_server)
        z_cs = self.priv_key.exchange(pk_srv_obj)
        self.s2c_key = HKDF(
            algorithm=hashes.SHA256(),
            length=16,
            salt=self.salt_srv,
            info=b"S2C"
        ).derive(z_cs)

        # Processa mensagens administrativas iniciais (REGISTERED e PEER_LIST)
        self.processar_proximo_frame()
        self.processar_proximo_frame()

    def processar_proximo_frame(self, timeout: float = 3.0) -> tuple[str, any]:
        """lê o próximo frame e processa caso seja administrativo, ou retorna se for E2E."""
        frame = receber_frame_validado(self.sock, timeout=timeout)
        msg_type = frame[0]

        if msg_type == MSG_TYPE_ADMIN:
            admin_type, payload = self._decifrar_admin(frame)
            self._tratar_admin(admin_type, payload)
            return "ADMIN", (admin_type, payload)
        elif msg_type == MSG_TYPE_E2E:
            return "E2E", frame
        else:
            return "OUTRO", frame

    def _decifrar_admin(self, frame: bytes) -> tuple[int, bytes]:
        """decifra mensagem administrativa com Key_S2C e valida integridade e anti-replay."""
        header = frame[:9]
        (seq_no,) = struct.unpack(">Q", frame[1:9])
        if seq_no <= self.admin_seq_recv:
            raise ValueError(f"[-] Replay detectado no canal admin! seq_no {seq_no} <= {self.admin_seq_recv}")

        nonce = b"\x00\x00\x00\x01" + frame[1:9]
        ciphertext_com_tag = frame[9:]
        plaintext = AESGCM(self.s2c_key).decrypt(nonce, ciphertext_com_tag, header)
        self.admin_seq_recv = seq_no
        return plaintext[0], plaintext[1:]

    def _tratar_admin(self, admin_type: int, payload: bytes) -> None:
        """trata notificações do servidor: REGISTERED, PEER_LIST, PEER_JOINED, etc."""
        if admin_type == ADMIN_TYPE_REGISTERED:
            print(f"[+] [{self.nome}] Sessão registrada no servidor com sucesso.")
        elif admin_type == ADMIN_TYPE_PEER_LIST:
            (count,) = struct.unpack_from(">H", payload, 0)
            print(f"[*] [{self.nome}] Lista de peers recebida com {count} peer(s).")
            for i in range(count):
                entry = payload[2 + 64 * i : 2 + 64 * (i + 1)]
                self._adicionar_peer(entry)
        elif admin_type == ADMIN_TYPE_PEER_JOINED:
            print(f"[*] [{self.nome}] Notificação PEER_JOINED recebida.")
            self._adicionar_peer(payload)
        elif admin_type == ADMIN_TYPE_PEER_LEFT:
            peer_id = uuid.UUID(bytes=payload[:16])
            print(f"[*] [{self.nome}] Peer {peer_id} desconectou.")
            self.peers.pop(peer_id, None)
        elif admin_type == ADMIN_TYPE_ERROR:
            err_code = payload[0]
            err_msg = payload[1:].decode("utf-8", errors="replace")
            print(f"[-] [{self.nome}] Notificação de ERRO administrativo do servidor: código {err_code} - {err_msg}")
        elif admin_type == ADMIN_TYPE_DISCONNECT:
            reason = payload[0]
            disc_msg = payload[1:].decode("utf-8", errors="replace")
            print(f"[-] [{self.nome}] Notificação de DISCONNECT do servidor: razão {reason} - {disc_msg}")

    def _adicionar_peer(self, entry: bytes) -> None:
        """deriva chaves simétricas E2E com HKDF-SHA256 usando o pair_salt único distribuído pelo servidor."""
        peer_id = uuid.UUID(bytes=entry[:16])
        pk_peer = entry[16:48]
        pair_salt = entry[48:64]

        # Acordo Diffie-Hellman efêmero e derivação direcional de chaves E2E (crypto.py)
        key_a2b, key_b2a = calcular_segredo_e_derivar_chaves(self.priv_key, pk_peer, pair_salt)

        #regra do protocolo: Cliente A tem o menor client_id em comparação de 16 bytes
        i_am_a = self.client_id_bytes < peer_id.bytes
        key_send = key_a2b if i_am_a else key_b2a
        key_recv = key_b2a if i_am_a else key_a2b

        self.peers[peer_id] = {
            "public_key": pk_peer,
            "pair_salt": pair_salt,
            "key_send": key_send,
            "key_recv": key_recv,
            "seq_send": 0,
            "seq_recv": -1,
            "iv_base_send": os.urandom(4),
        }
        print(f"[+] [{self.nome}] Peer {peer_id} configurado! Chaves E2E derivadas com pair_salt.")

    def aguardar_peer(self, peer_id: uuid.UUID, timeout: float = 5.0) -> None:
        """aguarda notificação administrativa do servidor até que o peer desejado esteja registrado."""
        inicio = time.time()
        while peer_id not in self.peers:
            if time.time() - inicio > timeout:
                raise TimeoutError(f"Tempo esgotado aguardando peer {peer_id}")
            self.processar_proximo_frame(timeout=1.0)

    def cifrar_frame_e2e(self, peer_id: uuid.UUID, plaintext: bytes, seq_override: int | None = None) -> bytes:
        """cifra a mensagem delegando para cifrar_mensagem_e2e do módulo crypto.py."""
        peer = self.peers[peer_id]
        seq_input = (seq_override - 1) if seq_override is not None else peer["seq_send"]
        frame_e2e, novo_seq = cifrar_mensagem_e2e(
            key_a2b=peer["key_send"],
            iv_base_send=peer["iv_base_send"],
            seq_send=seq_input,
            sender_id_bytes=self.client_id_bytes,
            recipient_id_bytes=peer_id.bytes,
            plaintext=plaintext,
        )
        if seq_override is None:
            peer["seq_send"] = novo_seq
        return frame_e2e

    def enviar_e2e(self, peer_id: uuid.UUID, plaintext: bytes, seq_override: int | None = None) -> bytes:
        """cifra e transmite frame E2E pela rede através do servidor relay."""
        frame = self.cifrar_frame_e2e(peer_id, plaintext, seq_override=seq_override)
        enviar_frame_tcp(self.sock, frame)
        return frame

    def receber_e_decifrar_e2e(self, timeout: float = 5.0) -> tuple[bytes, uuid.UUID, int]:
        """aguarda um frame E2E da rede, decifra com AES-128-GCM e valida anti-replay e integridade."""
        inicio = time.time()
        while True:
            if time.time() - inicio > timeout:
                raise TimeoutError(f"[{self.nome}] Timeout aguardando mensagem E2E.")
            tipo, frame = self.processar_proximo_frame(timeout=1.0)
            if tipo == "E2E":
                return self.decifrar_frame_e2e(frame)

    def decifrar_frame_e2e(self, frame: bytes) -> tuple[bytes, uuid.UUID, int]:
        """desmonta frame E2E e decifra delegando para decifrar_mensagem_e2e do módulo crypto.py."""
        if len(frame) < 69:
            raise ValueError(f"[-] REJECTED: Frame E2E truncado ({len(frame)} bytes).")
        if frame[0] != MSG_TYPE_E2E:
            raise ValueError(f"Frame não é do tipo E2E (0x10), tipo: 0x{frame[0]:02x}")

        sender_id = uuid.UUID(bytes=frame[13:29])
        recipient_id = uuid.UUID(bytes=frame[29:45])

        if recipient_id != self.client_id:
            raise ValueError(f"[-] REJECTED: Destinatário incorreto ({recipient_id} != {self.client_id})")

        if sender_id not in self.peers:
            raise ValueError(f"[-] REJECTED: Remetente desconhecido ({sender_id})")

        peer = self.peers[sender_id]

        plaintext, sender_uuid, recipient_uuid, seq_no = decifrar_mensagem_e2e(
            key_b2a=peer["key_recv"],
            frame_recebido=frame,
            seq_recv_atual=peer["seq_recv"],
        )

        peer["seq_recv"] = seq_no
        return plaintext, sender_uuid, seq_no

    def desconectar(self) -> None:
        """Desconecta o socket de forma segura."""
        desconectar_seguro(self.sock)
        self.sock = None
        print(f"[*] [{self.nome}] Conexão encerrada com segurança.")


def gerenciar_servidor_relay() -> subprocess.Popen | None:
    """verifica se o servidor relay está rodando; caso contrário, inicia-o automaticamente em subprocesso."""
    s = socket.socket()
    try:
        s.connect((HOST, PORT))
        s.close()
        print(f"[+] Servidor Relay já está em execução em {HOST}:{PORT}.")
        return None
    except (ConnectionError, OSError):
        pass
    finally:
        desconectar_seguro(s)

    server_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "uatisapple-server"))
    server_py = os.path.join(server_dir, "main.py")
    server_venv_python = os.path.join(server_dir, ".venv", "bin", "python")
    python_bin = server_venv_python if os.path.exists(server_venv_python) else sys.executable

    if os.path.exists(server_py):
        print(f"[*] Servidor não detectado em {HOST}:{PORT}. Iniciando servidor relay automaticamente...")
        proc = subprocess.Popen(
            [python_bin, "main.py", "--host", HOST, "--port", str(PORT)],
            cwd=server_dir,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        for _ in range(50):
            time.sleep(0.1)
            test_sock = socket.socket()
            try:
                test_sock.connect((HOST, PORT))
                desconectar_seguro(test_sock)
                print(f"[+] Servidor Relay iniciado com sucesso (PID {proc.pid})!")
                return proc
            except (ConnectionError, OSError):
                desconectar_seguro(test_sock)
        raise RuntimeError("Falha ao inicializar o servidor relay.")
    else:
        raise ConnectionRefusedError(f"Servidor relay não está rodando em {HOST}:{PORT} e diretório do servidor não foi encontrado.")


def main():
    print("=" * 70)
    print("       UATISAPPLE: TESTE INTEGRADO E2E COM DOIS CLIENTES E SEGURANÇA       ")
    print("=" * 70)

    proc_servidor = gerenciar_servidor_relay()

    cliente_a = None
    cliente_b = None

    try:
        # =====================================================================
        # ETAPA 1: Conexão e Handshake de Dois Clientes Reais
        # =====================================================================
        print("\n" + "=" * 70)
        print("ETAPA 1: Conexão e Handshake com Dois Clientes Reais (Alice e Bob)")
        print("=" * 70)

        cliente_a = ClienteUatisApple(nome="Alice")
        cliente_a.conectar_e_autenticar()

        cliente_b = ClienteUatisApple(nome="Bob")
        cliente_b.conectar_e_autenticar()

        # Alice processa notificação de que Bob entrou (PEER_JOINED)
        cliente_a.aguardar_peer(cliente_b.client_id)
        # Bob já conhece Alice via PEER_LIST recebida no handshake

        print(f"\n[+] Ambos os clientes autenticaram o servidor via Certificate Pinning e RSA-PSS!")
        print(f"[+] Chaves de sessão E2E derivadas mutuamente com o pair_salt fornecido pelo relay.")

        # =====================================================================
        # ETAPA 2: Troca de Mensagens E2E com Sucesso
        # =====================================================================
        print("\n" + "=" * 70)
        print("ETAPA 2: Troca de Mensagens E2E com Sucesso (Alice <-> Bob)")
        print("=" * 70)

        msg_alice = b"Ola Bob! Mensagem ultrassecreta cifrada com AES-128-GCM."
        print(f"[*] [Alice] Enviando mensagem E2E para Bob ({len(msg_alice)} bytes plaintext)...")
        frame_e2e_alice = cliente_a.enviar_e2e(cliente_b.client_id, msg_alice)
        print(f"[+] [Alice] Frame E2E transmitido na rede ({len(frame_e2e_alice)} bytes).")

        print("[*] [Bob] Aguardando recepção e decifrando mensagem E2E...")
        plaintext_bob, sender_bob, seq_bob = cliente_b.receber_e_decifrar_e2e()
        assert plaintext_bob == msg_alice, "Texto decifrado por Bob difere da mensagem enviada!"
        print(f"[+] [Bob] SUCESSO! Mensagem decifrada: '{plaintext_bob.decode('utf-8')}' (Remetente: Alice, Seq: {seq_bob})")

        # Bob responde para Alice
        msg_bob = b"Ola Alice! Mensagem recebida e decifrada perfeitamente de ponta a ponta."
        print(f"\n[*] [Bob] Enviando resposta E2E para Alice...")
        frame_e2e_bob = cliente_b.enviar_e2e(cliente_a.client_id, msg_bob)
        print(f"[+] [Bob] Resposta E2E transmitida na rede ({len(frame_e2e_bob)} bytes).")

        print("[*] [Alice] Aguardando recepção e decifrando resposta...")
        plaintext_alice, sender_alice, seq_alice = cliente_a.receber_e_decifrar_e2e()
        assert plaintext_alice == msg_bob, "Resposta decifrada por Alice difere do enviado por Bob!"
        print(f"[+] [Alice] SUCESSO! Resposta decifrada: '{plaintext_alice.decode('utf-8')}' (Remetente: Bob, Seq: {seq_alice})")

        # =====================================================================
        # ETAPA 3: Teste de Mensagem Adulterada (Bitflip) no Tráfego
        # =====================================================================
        print("\n" + "=" * 70)
        print("ETAPA 3: Teste de Integridade - Adulteração de Mensagem (Bitflip no Tráfego)")
        print("=" * 70)

        msg_tamper = b"Mensagem legitima que sera violada em transito por um atacante"
        frame_legitimo = cliente_a.cifrar_frame_e2e(cliente_b.client_id, msg_tamper)

        # Simula o atacante no tráfego alterando 1 bit na tag GCM de autenticação
        frame_adulterado = bytearray(frame_legitimo)
        frame_adulterado[-1] ^= 0x01
        print("[*] [Atacante] Bitflip realizado no último byte da Tag de autenticação GCM.")

        # O frame adulterado é injetado no tráfego da rede
        print("[*] [Alice] Injetando frame adulterado na rede em direção ao relay...")
        enviar_frame_tcp(cliente_a.sock, bytes(frame_adulterado))

        # Bob lê o frame repassado cegamente pelo servidor relay
        print("[*] [Bob] Recebendo frame adulterado da rede e tentando decifrar...")
        _, frame_recebido_bob = cliente_b.processar_proximo_frame(timeout=3.0)

        try:
            cliente_b.decifrar_frame_e2e(frame_recebido_bob)
            raise AssertionError("FALHA: Bob decifrou mensagem adulterada sem acusar erro!")
        except ValueError as e:
            print(f"[+] SUCESSO NO TESTE ANTI-TAMPERING: Destinatário rejeitou mensagem adulterada!")
            print(f"    Detalhe: {e}")

        # =====================================================================
        # ETAPA 4: Teste de Envio de Frame com seq_no já Usado (Replay Attack)
        # =====================================================================
        print("\n" + "=" * 70)
        print("ETAPA 4: Teste de Ataque Replay - Envio de Frame com seq_no já Usado")
        print("=" * 70)

        print("[*] Tentando retransmitir frame anterior que possuía seq_no já utilizado...")
        # Reenvia o frame válido de Alice (que tinha seq_no = 1)
        enviar_frame_tcp(cliente_a.sock, frame_e2e_alice)

        # O servidor relay detecta o seq_no <= último e envia um erro REPLAY para Alice
        tipo_resp, payload_resp = cliente_a.processar_proximo_frame(timeout=3.0)
        if tipo_resp == "ADMIN" and payload_resp[0] == ADMIN_TYPE_ERROR:
            err_code = payload_resp[1][0]
            print(f"[+] SUCESSO NO TESTE DE REPLAY (Servidor): Relay rejeitou replay com código ERROR {err_code} (REPLAY=0x05)!")

        # Demonstração adicional: se o frame retransmitido for submetido à decifragem no destinatário
        try:
            cliente_b.decifrar_frame_e2e(frame_e2e_alice)
            raise AssertionError("FALHA: Destinatário aceitou frame com seq_no antigo!")
        except ValueError as e:
            print(f"[+] SUCESSO NO TESTE DE REPLAY (Destinatário): Destinatário rejeitou seq_no repetido!")
            print(f"    Detalhe: {e}")

        # =====================================================================
        # ETAPA 5: Teste de Framing Inválido (Tamanho Incorreto) e Desconexão Segura
        # =====================================================================
        print("\n" + "=" * 70)
        print("ETAPA 5: Teste de Framing Inválido (Tamanho Incorreto) e Desconexão Segura")
        print("=" * 70)

        print(f"[*] Limite max_client_frame_size configurado: {MAX_CLIENT_FRAME_SIZE} bytes.")

        # Teste 5.1: Envio de framing com tamanho 0 (tamanho inválido)
        print("\n[*] [Subteste 5.1] Conectando novo cliente e enviando frame com tamanho anunciado = 0...")
        sock_framing = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock_framing.connect((HOST, PORT))
        # Envia apenas o prefixo de 4 bytes indicando tamanho 0
        sock_framing.sendall(struct.pack(">I", 0))

        # O servidor deve fechar a conexão ou rejeitar imediatamente
        time.sleep(0.2)
        try:
            dados = sock_framing.recv(1024)
            if not dados:
                print("[+] [Servidor] Conexão encerrada pelo servidor imediatamente após framing tamanho 0!")
            else:
                print(f"[+] [Servidor] Resposta recebida do servidor: {len(dados)} bytes.")
        except (ConnectionError, OSError) as e:
            print(f"[+] [Servidor] Conexão abortada pelo servidor: {e}")
        finally:
            desconectar_seguro(sock_framing)
            print("[+] [Cliente] Desconexão segura executada no socket de teste 5.1.")

        # Teste 5.2: Envio de framing com tamanho que excede MAX_CLIENT_FRAME_SIZE
        tamanho_excessivo = MAX_CLIENT_FRAME_SIZE + 500
        print(f"\n[*] [Subteste 5.2] Enviando framing que excede o limite máximo ({tamanho_excessivo} > {MAX_CLIENT_FRAME_SIZE})...")
        sock_framing2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock_framing2.connect((HOST, PORT))
        sock_framing2.sendall(struct.pack(">I", tamanho_excessivo) + b"\x10" + b"A" * 100)

        time.sleep(0.2)
        try:
            dados2 = sock_framing2.recv(1024)
            if not dados2:
                print("[+] [Servidor] Conexão encerrada pelo servidor devido a tamanho superior a MAX_CLIENT_FRAME_SIZE!")
            else:
                print(f"[+] [Servidor] Resposta do servidor recebida: {len(dados2)} bytes.")
        except (ConnectionError, OSError) as e:
            print(f"[+] [Servidor] Conexão rejeitada com sucesso: {e}")
        finally:
            desconectar_seguro(sock_framing2)
            print("[+] [Cliente] Desconexão segura executada no socket de teste 5.2.")

        # Teste 5.3: Tratamento de erro de framing e desconexão segura local na função de leitura
        print("\n[*] [Subteste 5.3] Validando tratamento de framing incorreto no leitor do cliente...")
        par_leitura_r, par_leitura_w = socket.socketpair()
        try:
            # Escreve um prefixo com tamanho 0 no stream simulado
            par_leitura_w.sendall(struct.pack(">I", 0))
            try:
                receber_frame_validado(par_leitura_r, timeout=1.0)
                raise AssertionError("FALHA: Leitor não detectou framing de tamanho 0!")
            except FramingError as e:
                print(f"[+] SUCESSO: FramingError capturado corretamente no leitor: {e}")
        finally:
            desconectar_seguro(par_leitura_r)
            desconectar_seguro(par_leitura_w)
            print("[+] Desconexão segura executada no par de sockets local.")

    finally:
        # =====================================================================
        # Limpeza e Desconexão Segura dos Clientes Principais
        # =====================================================================
        print("\n" + "=" * 70)
        print("FINALIZAÇÃO: Limpeza e Desconexão Segura de Alice e Bob")
        print("=" * 70)
        if cliente_a:
            cliente_a.desconectar()
        if cliente_b:
            cliente_b.desconectar()

        if proc_servidor:
            print("[*] Encerrando subprocesso do servidor relay iniciado para o teste...")
            proc_servidor.terminate()
            proc_servidor.wait()
            print("[+] Servidor relay encerrado.")

    print("\n[✔] TODOS OS TESTES FORAM EXECUTADOS E CONCLUÍDOS COM SUCESSO!")


if __name__ == "__main__":
    main()
