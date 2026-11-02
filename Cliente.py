import uuid
import hashlib
import asyncio
from Comunicacao import write_frame, read_frame
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat


HOST = "127.0.0.1"
PORT = 8888


def gerarClientID() -> bytes:
    return uuid.uuid4().bytes

def gerarParEfemero():
    sk = X25519PrivateKey.generate()
    pk_bytes = sk.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)

    return sk, pk_bytes


async def iniciar_handshake(host: str, port: int):
    cliente_id = gerarClientID()
    sk_cliente, pk_cliente = gerarParEfemero()

    reader, writer = await asyncio.open_connection(host, port)
    registro = cliente_id + pk_cliente

    if len(registro) != 48:
       return print("frame nao tem 48 bytes")
        
    await write_frame(writer, registro)
    print(f"[cliente] conectado; id={cliente_id.hex()} "
          f"fp_pk={hashlib.sha256(pk_cliente).hexdigest()[:16]}")

    return reader, writer, cliente_id, sk_cliente, pk_cliente




##asyncio.run(iniciar_handshake(HOST, PORT))