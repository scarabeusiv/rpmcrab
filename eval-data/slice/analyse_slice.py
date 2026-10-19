#!/usr/bin/env python3
import json, re, collections
W = '/Users/fluff/work/eval779/'
S = W + 'slice/'
manifest = {e['case']: e for e in json.load(open(S+'manifest.json'))}
kv = {}
for line in open(W+'kv-slice.tsv', encoding='utf-8', errors='replace'):
    parts = line.rstrip('\n').split('\t')
    if len(parts) >= 4:
        kv[(parts[0], parts[1])] = (parts[2], parts[3])
def kv_verdict(text):
    vs = [m.group(1) for m in re.finditer(r'signature, key (?:ID|fingerprint):?\s*[0-9a-f]+: (\w+)', text, re.I)]
    vs += [m.group(1) for m in re.finditer(r'signature: (BAD|NOTTRUSTED|NOKEY|OK)\b', text)]
    if not vs: return 'NOSIG'
    if 'BAD' in vs: return 'BAD'
    if 'NOKEY' in vs: return 'NOKEY'
    if 'NOTTRUSTED' in vs: return 'NOTTRUSTED'
    return 'OK'
harness = {}
for line in open(W+'harness-slice.jsonl'):
    d = json.loads(line)
    harness[d['path']] = d
def verdict_730(kv_v, sigs):
    if not sigs: return 'silent'
    corrupt = any(str(b.get('hand','')).startswith('error') or b.get('hand') == 'none' for b in sigs)
    if kv_v == 'OK': return 'silent'
    if kv_v == 'NOTTRUSTED': return 'silent'
    if kv_v == 'NOKEY': return 'invalid-signature' if corrupt else 'unknown-key'
    if kv_v == 'BAD': return 'invalid-signature' if corrupt else 'silent'
    if kv_v == 'NOSIG': return 'silent(nosig)'
    return 'kv:'+kv_v
def verdict_seq(sigs, field):
    if not sigs: return 'silent'
    res = [b.get(field) for b in sigs]
    corrupt = any(b.get('parse') != 'ok' or r == 'malformed' for b, r in zip(sigs, res))
    if all(r == 'good' for r in res): crypto = 'OK'
    elif any(r == 'bad' for r in res): crypto = 'BAD'
    elif any(r == 'missing' for r in res): crypto = 'NOKEY'
    else: crypto = 'OTHER:' + ','.join(str(r) for r in res)
    if crypto == 'OK': return 'silent'
    if crypto == 'NOKEY': return 'invalid-signature' if corrupt else 'unknown-key'
    if field == 'verify' and any(b.get('key') == 'missing' for b in sigs) and not any(r == 'bad' for r in res):
        return 'invalid-signature' if corrupt else 'unknown-key'
    if crypto == 'BAD': return 'invalid-signature' if corrupt else 'silent'
    return crypto
print(f"{'case':24} {'kvEmpty':7} {'kvCtx':6} {'v730':16} {'seqLow':16} {'seqNull':16} std")
for case, e in manifest.items():
    fn = e['file']
    ctx = 'slice'
    suffix = ''
    if case == 'mixed-keys': ctx, suffix = 'mixed', '#onekey'
    h = harness.get(S+'pkgs/'+fn+suffix) or harness.get(S+'pkgs/'+fn)
    sigs = h['sigs'] if h else []
    kve = kv_verdict(kv.get((fn,'empty'), ('',''))[0])
    kvc = kv_verdict(kv.get((fn,ctx), ('',''))[0])
    v730 = verdict_730(kvc, sigs)
    vlow = verdict_seq(sigs, 'verify')
    vnull = verdict_seq(sigs, 'builder_null')
    std = ','.join(str(b.get('builder_std'))[:26] for b in sigs) or '-'
    flag = ''
    base = {'silent','unknown-key','invalid-signature'}
    if v730 in base and vlow in base and v730 != vlow: flag += ' LOW!=730'
    if v730 in base and vnull in base and v730 != vnull: flag += ' NULL!=730'
    print(f"{case:24} {kve:7} {kvc:6} {v730:16} {vlow:16} {vnull:16} {std}{flag}")
    if case == 'revoked-rsa2048':
        h2 = harness.get(S+'pkgs/'+fn+'#revoked-after')
        s2 = h2['sigs'] if h2 else []
        kvr = kv_verdict(kv.get((fn,'revoked-after'), ('',''))[0])
        print(f"{'  + revoked-after cert':24} {'':7} {kvr:6} {verdict_730(kvr, s2):16} {verdict_seq(s2,'verify'):16} {verdict_seq(s2,'builder_null'):16} {','.join(str(b.get('builder_std'))[:26] for b in s2)}")
# SLE11 row (not in manifest)
h = harness.get(W+'sle11/timezone-11.4.rpm#sle11')
if h:
    sigs = h['sigs']
    print(f"{'SLE11 timezone (own line)':24} {'NOKEY':7} {'n/a':6} {'unknown-key*':16} {verdict_seq(sigs,'verify'):16} {verdict_seq(sigs,'builder_null'):16} {','.join(str(b.get('builder_std'))[:26] for b in sigs)}")
    print('  SLE11 blobs:', [(b.get('ver'), b.get('pk_algo'), b.get('hash_algo'), b.get('hand'), b.get('issuer'), b.get('verify'), b.get('builder_null')) for b in sigs])
