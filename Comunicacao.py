import struct

MAX_FRAME = 64 * 1024  


class FramingError(Exception):
    pass


async def write_frame(writer, data: bytes) -> None:
    if len(data) > MAX_FRAME:
        raise FramingError("frame grande demais")
    writer.write(struct.pack(">I", len(data)) + data)
    await writer.drain()

async def read_frame(reader) -> bytes:
    header = await reader.readexactly(4)
    (n,) = struct.unpack(">I", header)
    if n == 0 or n > MAX_FRAME:
        raise FramingError(f"tamanho de frame inválido: {n}")
    return await reader.readexactly(n)