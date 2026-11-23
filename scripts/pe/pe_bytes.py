"""Print the PE fingerprint of an executable and the raw bytes at one or more virtual addresses.

The hook DLL refuses to patch a binary whose TimeDateStamp/SizeOfImage differ from the ones it was
built for; this prints those values. Bytes at a VA show whether a function is long enough to hook
(MinHook needs at least 5 bytes before the first branch target or return).

Usage: python -I _tools/pe_bytes.py <exe> [va ...] [--count N]
  va  hex virtual address (image base 0x140000000), e.g. 140327870
"""
import argparse
import struct


def sections(data):
    pe = struct.unpack_from("<I", data, 0x3C)[0]
    count = struct.unpack_from("<H", data, pe + 6)[0]
    opt_size = struct.unpack_from("<H", data, pe + 20)[0]
    table = pe + 24 + opt_size
    for i in range(count):
        name, vsize, va, rsize, raw = struct.unpack_from("<8sIIII", data, table + 40 * i)
        yield name.rstrip(b"\0").decode(), va, max(vsize, rsize), raw


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("exe")
    ap.add_argument("va", nargs="*")
    ap.add_argument("--count", type=int, default=32)
    args = ap.parse_args()
    data = open(args.exe, "rb").read()
    pe = struct.unpack_from("<I", data, 0x3C)[0]
    stamp = struct.unpack_from("<I", data, pe + 8)[0]
    base = struct.unpack_from("<Q", data, pe + 24 + 24)[0]
    size = struct.unpack_from("<I", data, pe + 24 + 56)[0]
    dll_chars = struct.unpack_from("<H", data, pe + 24 + 70)[0]
    print(f"TimeDateStamp=0x{stamp:08x} SizeOfImage=0x{size:08x} ImageBase=0x{base:x} "
          f"DynamicBase={'yes' if dll_chars & 0x40 else 'no'}")
    secs = list(sections(data))
    for text in args.va:
        rva = int(text, 16) - base
        for name, va, vsize, raw in secs:
            if va <= rva < va + vsize:
                off = raw + rva - va
                print(f"{text} [{name}+0x{rva - va:x}]: {data[off:off + args.count].hex(' ')}")
                break
        else:
            print(f"{text}: not inside any section")


if __name__ == "__main__":
    main()
