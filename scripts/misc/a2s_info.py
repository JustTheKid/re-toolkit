import socket, struct, sys
host, port = sys.argv[1], int(sys.argv[2])
req = b'\xFF\xFF\xFF\xFFTSource Engine Query\x00'
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(5)
s.sendto(req, (host, port)); data, _ = s.recvfrom(4096)
if data[4] == 0x41:  # challenge
    s.sendto(req + data[5:9], (host, port)); data, _ = s.recvfrom(4096)
assert data[4] == 0x49, f'unexpected reply type {data[4]:#x}'
pos = 6
def cstr():
    global pos
    end = data.index(b'\0', pos); v = data[pos:end].decode('utf-8', 'replace'); pos = end + 1; return v
name, mapname, folder, game = cstr(), cstr(), cstr(), cstr()
appid, players, maxp, bots = struct.unpack_from('<HBBB', data, pos); pos += 5
stype, env, vis, vac = chr(data[pos]), chr(data[pos+1]), data[pos+2], data[pos+3]; pos += 4
version = cstr()
print(f'name={name!r} map={mapname!r} folder={folder!r} game={game!r}')
print(f'players={players}/{maxp} bots={bots} type={stype} os={env} password={bool(vis)} vac={bool(vac)} version={version!r}')
# Extra Data Flag fields; GameID's low 24 bits are the Steam App ID a client launches to join.
extra = {'short_appid': appid}
if pos < len(data):
    edf = data[pos]; pos += 1
    if edf & 0x80: extra['game_port'] = struct.unpack_from('<H', data, pos)[0]; pos += 2
    if edf & 0x10: extra['steam_id'] = struct.unpack_from('<Q', data, pos)[0]; pos += 8
    if edf & 0x40: pos += 2; cstr()
    if edf & 0x20: extra['keywords'] = cstr()
    if edf & 0x01: extra['app_id'] = struct.unpack_from('<Q', data, pos)[0] & 0xFFFFFF
print('extra:', extra)
