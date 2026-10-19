import re, collections
rows = []
for line in open('/home/fluff/eval779/pass1.tsv'):
    parts = line.rstrip('\n').split('\t')
    if len(parts) == 3:
        rows.append(parts)
print('total rpms:', len(rows))
sigpat = re.compile(r'(Header(?: and Payload)?|Payload)?\s*(V[346])?\s*(RSA|DSA|ECDSA|EdDSA|EC)\s*/\s*(SHA1|SHA224|SHA256|SHA384|SHA512|MD5)\s+Signature, key ID ([0-9a-f]+): (\w+)')
classes = collections.Counter()
keys = collections.Counter()
nosig = 0
weird = []
for rel, sig, rc in rows:
    if not sig:
        nosig += 1
        classes['UNSIGNED'] += 1
        continue
    ms = sigpat.findall(sig)
    if not ms:
        weird.append((rel, sig))
        classes['UNPARSED'] += 1
        continue
    for hdr, ver, algo, hash_, kid, verdict in ms:
        scope = 'HDR+PAY' if 'and Payload' in (hdr or '') else ('HDR' if hdr else 'PAY?')
        classes[f'{ver or "?"}/{algo}/{hash_}/{scope}'] += 1
        keys[kid] += 1
    if len(ms) > 1:
        classes['MULTI-SIG pkgs (counted once here)'] += 0
multipk = sum(1 for rel, sig, rc in rows if len(sigpat.findall(sig)) > 1)
print('packages with >1 signature:', multipk)
print('unsigned:', nosig)
print('distinct key IDs:', len(keys))
for k, v in keys.most_common(30):
    print('  key', k, v)
print('--- classes ---')
for k, v in classes.most_common(40):
    print(' ', k, v)
print('--- unparsed samples ---')
for rel, sig in weird[:15]:
    print(' ', rel, '=>', sig[:160])
npk_with_sig = sum(1 for rel, sig, rc in rows if sig)
print('packages with >=1 sig line:', npk_with_sig)
