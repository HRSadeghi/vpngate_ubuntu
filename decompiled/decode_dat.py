import struct, zlib, sys, json

def rc4(key, data):
    S = list(range(256)); j = 0
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) & 255
        S[i], S[j] = S[j], S[i]
    i = j = 0; out = bytearray()
    for b in data:
        i = (i + 1) & 255; j = (j + S[i]) & 255
        S[i], S[j] = S[j], S[i]
        out.append(b ^ S[(S[i] + S[j]) & 255])
    return bytes(out)

# SoftEther Pack value types
INT, DATA, STR, UNISTR, INT64 = 0, 1, 2, 3, 4

def parse_pack(buf):
    p = 0
    def u32():
        nonlocal p
        v = struct.unpack_from('>I', buf, p)[0]; p += 4; return v
    n = u32(); out = {}
    for _ in range(n):
        ln = u32(); name = buf[p:p+ln-1].decode('latin1'); p += ln - 1
        typ = u32(); cnt = u32(); vals = []
        for _ in range(cnt):
            if typ == INT: vals.append(u32())
            elif typ == INT64: vals.append(struct.unpack_from('>Q', buf, p)[0]); p += 8
            elif typ == DATA:
                l = u32(); vals.append(buf[p:p+l]); p += l
            elif typ == STR:
                l = u32(); vals.append(buf[p:p+l].decode('utf8', 'replace')); p += l
            elif typ == UNISTR:
                l = u32(); vals.append(buf[p:p+l].decode('utf8', 'replace')); p += l
            else: raise ValueError(typ)
        out[name] = (typ, vals)
    return out

raw = open(sys.argv[1], 'rb').read()
hdr, key, body = raw[:0xF0], raw[0xF0:0x104], raw[0x104:]
print('header:', hdr.rstrip(b'\0').decode())
print('key   :', key.hex(), ' body:', len(body))
import hashlib
rk = hashlib.sha1(key).digest()
dec = rc4(rk, body); open(sys.argv[2]+".outer.bin","wb").write(dec)
outer = parse_pack(dec)
for k, (t, v) in outer.items():
    print(' outer', k, t, [x if not isinstance(x, bytes) else f'<{len(x)} bytes {x[:8].hex()}>' for x in v])
data = outer['data'][1][0] if 'data' in outer else None
print({k: v[1][0] if isinstance(v[1][0], (int, str)) else '<bin %d>' % len(v[1][0]) for k, v in outer.items()})
d = outer['data'][1][0]
if outer.get('compressed', (0, [0]))[1][0]:
    size = outer['data_size'][1][0]
    d = zlib.decompress(d[4:]) if len(d) >= 4 and struct.unpack('>I', d[:4])[0] == size else zlib.decompress(d)
open(sys.argv[2] + '.inner.bin', 'wb').write(d)
inner = parse_pack(d)
print('inner keys:', {k: (v[0], len(v[1])) for k, v in inner.items()})
import csv, datetime
n = inner['NumHosts'][1][0]
cols = ['IP', 'Fqdn', 'HostName', 'CountryShort', 'Score', 'PingToJapan', 'SpeedToJapan', 'NumClients', 'Uptime', 'SslPorts', 'UdpPort', 'OpenVpnUdpPorts', 'L2TP', 'Os', 'Soft', 'Build']
with open(sys.argv[2] + '_hosts.csv', 'w', newline='') as f:
    w = csv.writer(f); w.writerow(cols)
    for i in range(n):
        w.writerow([inner[c][1][i] for c in cols])
print('hosts:', n, 'timestamp:', datetime.datetime.fromtimestamp(struct.unpack('>Q', outer['timestamp'][1][0])[0] / 1000, datetime.UTC))
print('DatId', inner['DatId'][1], 'DynList bytes', len(inner['DynList'][1][0]))
