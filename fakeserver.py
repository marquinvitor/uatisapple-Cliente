import asyncio
from Comunicacao import read_frame

async def handle(reader, writer):
    dados = await read_frame(reader)
    print(f"recebi {len(dados)} bytes")
    print("client_id:", dados[:16].hex())
    print("pk_C (32B):", dados[16:].hex())
    assert len(dados) == 48
    writer.close()

async def main():
    server = await asyncio.start_server(handle, "127.0.0.1", 8888)
    async with server:
        await server.serve_forever()

asyncio.run(main())