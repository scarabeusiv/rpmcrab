#!/usr/bin/env python3
import os, subprocess, sys, shutil, hashlib, struct, json

BASE = '/Users/fluff/work/eval779/slice'
GNUPG = os.path.join(BASE, 'gnupg')
OUT = os.path.join(BASE, 'pkgs')
KEYS = os.path.join(BASE, 'keys')
for d in (GNUPG, OUT, KEYS):
    shutil.rmtree(d, ignore_errors=True)
for d in (BASE, GNUPG, OUT, KEYS):
    os.makedirs(d, exist_ok=True)
os.chmod(GNUPG, 0o700)
ENV = dict(os.environ, GNUPGHOME=GNUPG)
LOG = open(os.path.join(BASE, 'build.log'), 'w')
def log(*a):
    print(*a, file=LOG, flush=True)
    print(*a, flush=True)
def run(cmd, inp=None, env=ENV, ok_rc=(0,)):
    r = subprocess.run(cmd, input=inp, capture_output=True, env=env)
    if r.returncode not in ok_rc:
        log('FAIL', cmd, r.returncode, r.stderr.decode(errors='replace')[:400])
    return r

# ---------- 1. base unsigned RPM via rpmbuild ----------
spec = os.path.join(BASE, 'evalsig.spec')
open(spec, 'w').write("""Name: evalsig
Version: 1.0
Release: 1
Summary: signature evaluation vehicle
License: MIT
BuildArch: noarch
%description
Signature evaluation vehicle.
%install
mkdir -p %{buildroot}/usr/share/evalsig
echo "hello signature evaluation" > %{buildroot}/usr/share/evalsig/hello.txt
%files
/usr/share/evalsig/hello.txt
""")
os.makedirs(os.path.join(BASE, 'tmp'), exist_ok=True)
r = run(['rpmbuild', '-bb', '--define', f'_topdir {BASE}/rpmbuild', '--define', f'_tmppath {BASE}/tmp', spec])
rpms = []
for dp, dn, fn in os.walk(os.path.join(BASE, 'rpmbuild')):
    for f in fn:
        if f.endswith('.rpm'):
            rpms.append(os.path.join(dp, f))
assert rpms, 'rpmbuild produced nothing'
base_rpm = rpms[0]
data = open(base_rpm, 'rb').read()
log('base rpm:', base_rpm, len(data), 'bytes')

def parse_header(buf, start):
    assert buf[start:start+3] == b'\x8e\xad\xe8', 'bad header magic'
    nindex, hsize = struct.unpack('>II', buf[start+8:start+16])
    entries = []
    for i in range(nindex):
        off = start + 16 + i*16
        entries.append(struct.unpack('>IIII', buf[off:off+16]))
    store_start = start + 16 + nindex*16
    return entries, buf[store_start:store_start+hsize], store_start + hsize

sig_entries, sig_store, sig_end = parse_header(data, 96)
main_start = 96 + ((sig_end - 96 + 7) // 8) * 8
main_entries, main_store, main_end = parse_header(data, main_start)
HDR = data[main_start:main_end]
HDRPAY = data[main_start:]
log('sig entries:', sig_entries)
log('main header bytes:', len(HDR), 'header+payload:', len(HDRPAY))

def assemble(sig_blobs, outname):
    """sig_blobs: list of (tag, blob). Reuse base sig store, append blobs."""
    store = bytearray(sig_store)
    entries = list(sig_entries)
    for tag, blob in sig_blobs:
        entries.append((tag, 7, len(store), len(blob)))
        store += blob
    hdr = bytearray()
    hdr += b'\x8e\xad\xe8\x01' + b'\x00'*4 + struct.pack('>II', len(entries), len(store))
    for e in entries:
        hdr += struct.pack('>IIII', *e)
    hdr += store
    total = 96 + len(hdr)
    pad = (8 - total % 8) % 8
    out = data[:96] + bytes(hdr) + b'\x00'*pad + data[main_start:]
    path = os.path.join(OUT, outname)
    open(path, 'wb').write(out)
    return path

# ---------- 2. keys ----------
def genkey(name, params, extra_env=None):
    env = dict(ENV)
    if extra_env: env.update(extra_env)
    r = run(['gpg', '--batch', '--gen-key'], inp=params.encode(), env=env)
    lst = run(['gpg', '--batch', '--with-colons', '-k', name], env=env)
    fpr = None
    for line in lst.stdout.decode().splitlines():
        parts = line.split(':')
        if parts[0] == 'fpr':
            fpr = parts[9]; break
    log('key', name, fpr)
    exp = run(['gpg', '--batch', '--export', fpr], env=env)
    kf = os.path.join(KEYS, name + '.asc')
    open(kf, 'wb').write(exp.stdout)
    return fpr, kf

KEYDEFS = {}
KEYDEFS['rsa4096'] = genkey('rsa4096', "Key-Type: RSA\nKey-Length: 4096\nKey-Usage: sign\nName-Real: rsa4096\n%no-protection\n%commit\n")
KEYDEFS['rsa1024'] = genkey('rsa1024', "Key-Type: RSA\nKey-Length: 1024\nKey-Usage: sign\nName-Real: rsa1024\n%no-protection\n%commit\n")
KEYDEFS['dsa1024'] = genkey('dsa1024', "Key-Type: DSA\nKey-Length: 1024\nKey-Usage: sign\nName-Real: dsa1024\n%no-protection\n%commit\n")
KEYDEFS['ecdsa256'] = genkey('ecdsa256', "Key-Type: ECDSA\nKey-Curve: nistp256\nKey-Usage: sign\nName-Real: ecdsa256\n%no-protection\n%commit\n")
KEYDEFS['eddsa'] = genkey('eddsa', "Key-Type: eddsa\nKey-Curve: ed25519\nKey-Usage: sign\nName-Real: eddsa\n%no-protection\n%commit\n")
KEYDEFS['expired'] = genkey('expired', "Key-Type: RSA\nKey-Length: 2048\nKey-Usage: sign\nName-Real: expired\nCreation-Date: 20200101T000000\nExpire-Date: 20210101T000000\n%no-protection\n%commit\n")
KEYDEFS['revoked'] = genkey('revoked', "Key-Type: RSA\nKey-Length: 2048\nKey-Usage: sign\nName-Real: revoked\n%no-protection\n%commit\n")
KEYDEFS['subkey'] = genkey('subkey', "Key-Type: RSA\nKey-Length: 2048\nKey-Usage: cert\nSubkey-Type: RSA\nSubkey-Length: 2048\nSubkey-Usage: sign\nName-Real: subkey\n%no-protection\n%commit\n")

def sign(fpr, databytes, digest=None, extra=None):
    cmd = ['gpg', '--batch', '--yes', '--pinentry-mode', 'loopback', '--passphrase', '',
           '--detach-sign', '--local-user', fpr]
    if digest: cmd += ['--digest-algo', digest]
    if extra: cmd += extra
    r = run(cmd, inp=databytes)
    return r.stdout if r.returncode == 0 else None

manifest = []
def emit(case, blobs, keyfiles, note=''):
    fn = case + '.rpm'
    assemble(blobs, fn)
    manifest.append({'case': case, 'file': fn, 'keyfiles': keyfiles, 'note': note})
    log('case', case, 'ok')

def both(case, keyname, digest=None, extra=None, note=''):
    fpr, kf = KEYDEFS[keyname]
    sh = sign(fpr, HDR, digest, extra)
    sp = sign(fpr, HDRPAY, digest, extra)
    if not sh or not sp:
        manifest.append({'case': case, 'file': None, 'keyfiles': [kf], 'note': 'SIGN FAILED ' + note})
        log('case', case, 'SIGN FAILED')
        return None
    emit(case, [(268, sh), (1002, sp)], [kf], note)
    return (sh, sp)

base_pair = both('rsa4096-sha256', 'rsa4096', 'SHA256', note='modern baseline')
both('rsa4096-sha512', 'rsa4096', 'SHA512')
both('rsa4096-sha384', 'rsa4096', 'SHA384')
both('rsa4096-sha224', 'rsa4096', 'SHA224')
both('rsa4096-sha1', 'rsa4096', 'SHA1', note='weak digest, strong key')
both('rsa4096-md5', 'rsa4096', 'MD5', note='weakest digest; gpg may refuse')
both('rsa1024-sha1', 'rsa1024', 'SHA1', note='weak key + weak digest')
both('rsa1024-sha256', 'rsa1024', 'SHA256', note='weak key, good digest')
both('dsa1024-sha1', 'dsa1024', 'SHA1', note='legacy DSA')
both('ecdsa256-sha256', 'ecdsa256', 'SHA256')
both('eddsa-sha512', 'eddsa', 'SHA512', note='Ed25519')
both('expired-rsa2048', 'expired', 'SHA256', extra=['--faked-system-time', '20200601T000000'], note='signed 2020-06 while key valid; key expired 2021-01-01')
both('revoked-rsa2048', 'revoked', 'SHA256', note='signed before revocation')
both('subkey-rsa2048', 'subkey', 'SHA256', note='signing subkey; primary cert-only')

# revoke the 'revoked' key AFTER signing; keep both cert versions
fpr_rev, kf_rev = KEYDEFS['revoked']
shutil.copy(kf_rev, os.path.join(KEYS, 'revoked-before.asc'))
r = run(['gpg', '--batch', '--yes', '--pinentry-mode', 'loopback', '--passphrase', '',
         '--quick-revoke-key', fpr_rev, '1', 'evaluation revocation'])
exp = run(['gpg', '--batch', '--export', fpr_rev])
open(os.path.join(KEYS, 'revoked-after.asc'), 'wb').write(exp.stdout)
log('revocation rc:', r.returncode)

# header-only / payload-only / mixed
fpr1, kf1 = KEYDEFS['rsa4096']
fpr7, kf7 = KEYDEFS['rsa1024']
sh1 = sign(fpr1, HDR, 'SHA256'); sp1 = sign(fpr1, HDRPAY, 'SHA256')
sp7 = sign(fpr7, HDRPAY, 'SHA256')
emit('header-only', [(268, sh1)], [kf1], 'no payload signature')
emit('payload-only', [(1002, sp1)], [kf1], 'no header signature')
emit('mixed-keys', [(268, sh1), (1002, sp7)], [kf1, kf7], 'header key in mixeddb, payload key not')

# ---------- 3. mutations of the baseline blobs ----------
sh, sp = base_pair
def split_packet(blob):
    """Return (body, fmt) where fmt describes the header for re-heading."""
    b0 = blob[0]
    assert b0 & 0x80
    if b0 & 0x40:  # new format
        c = blob[1]
        if c < 192: return blob[2:], ('new', 1)
        if c < 224: return blob[3:], ('new', 2)
        if c == 255: return blob[6:], ('new', 5)
        raise ValueError('partial body length')
    lt = b0 & 0x3
    if lt == 0: return blob[2:], ('old', 1)
    if lt == 1: return blob[3:], ('old', 2)
    if lt == 2: return blob[5:], ('old', 4)
    return blob[1:], ('old', 3)

def rehead(body, fmt):
    kind, n = fmt
    if kind == 'new':
        if n == 1: return bytes([0xC2, len(body)]) + body
        if n == 2:
            v = len(body) - 192
            return bytes([0xC2, 192 + (v >> 8), v & 0xFF]) + body
        return bytes([0xC2, 255]) + struct.pack('>I', len(body)) + body
    if n == 1: return bytes([0x80 | (2 << 2) | 0, len(body)]) + body
    if n == 2: return bytes([0x80 | (2 << 2) | 1]) + struct.pack('>H', len(body)) + body
    if n == 4: return bytes([0x80 | (2 << 2) | 2]) + struct.pack('>I', len(body)) + body
    return bytes([0x80 | (2 << 2) | 3]) + body

def unhashed_span_in_body(body):
    hlen = struct.unpack('>H', body[4:6])[0]
    uoff = 6 + hlen
    ulen = struct.unpack('>H', body[uoff:uoff+2])[0]
    return uoff + 2, ulen

def mut(case, blobs, fn):
    emit(case, blobs, [kf1], fn)

# badmpi: flip a byte 6 before end of header-sig blob (inside RSA MPI)
b = bytearray(sh); b[-6] ^= 0x01
mut('badmpi', [(268, bytes(b)), (1002, sp)], 'RSA MPI byte flipped; parse ok, crypto bad')
# badpayload: keep blobs, flip payload byte in the FILE instead -> custom assemble
def assemble_custom(sig_blobs, outname, filemut=None):
    store = bytearray(sig_store)
    entries = list(sig_entries)
    for tag, blob in sig_blobs:
        entries.append((tag, 7, len(store), len(blob)))
        store += blob
    hdr = bytearray()
    hdr += b'\x8e\xad\xe8\x01' + b'\x00'*4 + struct.pack('>II', len(entries), len(store))
    for e in entries: hdr += struct.pack('>IIII', *e)
    hdr += store
    total = 96 + len(hdr); pad = (8 - total % 8) % 8
    out = bytearray(data[:96] + bytes(hdr) + b'\x00'*pad + data[main_start:])
    if filemut: filemut(out)
    open(os.path.join(OUT, outname), 'wb').write(bytes(out))
def flip_payload(out):
    out[-3] ^= 0x01
assemble_custom([(268, sh), (1002, sp)], 'badpayload.rpm', flip_payload)
manifest.append({'case': 'badpayload', 'file': 'badpayload.rpm', 'keyfiles': [kf1], 'note': 'payload byte flipped; header sig ok, payload sig bad'})
# truncsig: header blob truncated to 40%
mut('truncsig', [(268, sh[:int(len(sh)*0.4)]), (1002, sp)], 'header sig blob truncated')
# critissuer: issuer subpacket type in unhashed area |= 0x80
body_sh, fmt_sh = split_packet(sh)
uoff, ulen = unhashed_span_in_body(body_sh)
b = bytearray(body_sh)
pos = uoff
while pos < uoff + ulen:
    lb = b[pos]
    if lb < 192: slen = lb; adv = 1
    elif lb < 224: slen = ((lb-192)<<8) + b[pos+1] + 192; adv = 2
    else: slen = struct.unpack('>I', b[pos+1:pos+5])[0]; adv = 5
    if b[pos+adv] == 16:
        b[pos+adv] = 16 | 0x80
        break
    pos += adv + slen
mut('critissuer', [(268, rehead(bytes(b), fmt_sh)), (1002, sp)], 'issuer subpacket critical bit set (unhashed area; crypto unaffected)')
# zerompi: rebuild header-sig packet with first MPI zeroed and MPI bytes dropped
body_sh2, fmt_sh2 = split_packet(sh)
hlen2 = struct.unpack('>H', body_sh2[4:6])[0]
uoff2 = 6 + hlen2
ulen2 = struct.unpack('>H', body_sh2[uoff2:uoff2+2])[0]
left_end = uoff2 + 2 + ulen2 + 2   # through left-16 bits
zb_body = body_sh2[:left_end] + b'\x00\x00'
mut('zerompi', [(268, rehead(zb_body, fmt_sh2)), (1002, sp)], 'first MPI replaced by zero-bit MPI')
# v5label: version byte 4 -> 5
bb, ff = split_packet(sh)
bb = bytearray(bb); bb[0] = 5
bb2, ff2 = split_packet(sp)
bb2 = bytearray(bb2); bb2[0] = 5
mut('v5label', [(268, rehead(bytes(bb), ff)), (1002, rehead(bytes(bb2), ff2))], 'version byte relabelled 4->5 (parse-level probe)')
# newfmt: re-head blobs with new-format packet headers
def newfmt(blob):
    body, _ = split_packet(blob)
    if len(body) < 192:
        return bytes([0xC2, len(body)]) + body
    v = len(body) - 192
    return bytes([0xC2, 192 + (v >> 8), v & 0xFF]) + body
mut('newfmt', [(268, newfmt(sh)), (1002, newfmt(sp))], 'new-format packet headers (gpg emits old-format natively)')
def indet(blob):
    body, _ = split_packet(blob)
    return bytes([0x80 | (2 << 2) | 3]) + body
mut('oldfmt-indet', [(268, indet(sh)), (1002, indet(sp))], 'old-format indeterminate lengths')
# unsigned: the base build itself
shutil.copy(base_rpm, os.path.join(OUT, 'unsigned.rpm'))
manifest.append({'case': 'unsigned', 'file': 'unsigned.rpm', 'keyfiles': [], 'note': 'no signature entries'})

json.dump(manifest, open(os.path.join(BASE, 'manifest.json'), 'w'), indent=1)
log('manifest cases:', len(manifest))
