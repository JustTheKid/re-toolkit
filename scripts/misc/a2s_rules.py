"""Query A2S_RULES and A2S_PLAYER (what game clients ask before joining) and print the replies."""
import socket
import struct
import sys

host, port = sys.argv[1], int(sys.argv[2])
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(5)


def ask(kind):
    s.sendto(b"\xFF\xFF\xFF\xFF" + kind + b"\xFF\xFF\xFF\xFF", (host, port))
    data, _ = s.recvfrom(65535)
    if data[4] == 0x41:  # challenge: repeat with it
        s.sendto(b"\xFF\xFF\xFF\xFF" + kind + data[5:9], (host, port))
        data, _ = s.recvfrom(65535)
    return data


for kind, label in ((b"V", "RULES"), (b"U", "PLAYER")):
    try:
        data = ask(kind)
    except Exception as e:
        print(f"{label}: no reply ({e})")
        continue
    if data[:4] == b"\xFE\xFF\xFF\xFF":
        print(f"{label}: multi-packet reply (split), first packet {len(data)} bytes")
        continue
    print(f"{label}: reply type {chr(data[4])!r}, {len(data)} bytes")
    if data[4] == ord("E"):
        n = struct.unpack_from("<H", data, 5)[0]
        pos = 7
        for _ in range(n):
            k_end = data.index(b"\0", pos); key = data[pos:k_end].decode(errors="replace"); pos = k_end + 1
            v_end = data.index(b"\0", pos); val = data[pos:v_end].decode(errors="replace"); pos = v_end + 1
            print(f"   {key} = {val}")
