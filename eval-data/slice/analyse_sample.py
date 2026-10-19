#!/usr/bin/env python3
import json, re, sys, collections
W = '/Users/fluff/work/eval779/'
sample = [l.strip() for l in open(W+'sample1200.txt') if l.strip()]

def load_kv(fn):
    d = {}
    for line in open(W+fn, encoding='utf-8', errors='replace'):
        parts = line.rstrip('\n').split('\t')
        if len(parts) >= 3:
            d[parts[0]] = (parts[1], parts[2])
    return d
kv_empty = load_kv('pass1-sample.tsv')
kv_key = load_kv('pass2-sample.tsv')

def kv_verdict(text):
    # signature lines only: "... Signature, key ID xxxx: OK|NOKEY|BAD ..."
    verdicts = []
    for m in re.finditer(r'signature, key (?:ID|fingerprint):?\s*[0-9a-f]+: (\w+)', text, re.I):
        verdicts.append(m.group(1))
    if not verdicts:
        return 'NOSIGLINES'
    if 'BAD' in verdicts: return 'BAD'
    if 'NOKEY' in verdicts: return 'NOKEY'
    return 'OK'

rows = [json.loads(l) for l in open(W+'harness-sample.jsonl')]
by_path = {r['path']: r for r in rows}
print(f'harness rows: {len(rows)}, sample: {len(sample)}, kv_empty: {len(kv_empty)}, kv_key: {len(kv_key)}')

# ---- blob level ----
blob_n = 0
parse_agree = parse_dis = 0
issuer_agree = issuer_dis = 0
dis_list = []
dist = collections.Counter()
for r in rows:
    for s in r['sigs']:
        blob_n += 1
        hand_ok = not str(s.get('hand','')).startswith('error')
        hand_iss = s.get('hand') if hand_ok else None
        seq_ok = s.get('parse') == 'ok'
        if hand_ok == seq_ok: parse_agree += 1
        else:
            parse_dis += 1; dis_list.append((r['path'], s['tag'], 'parse', s.get('hand'), s.get('parse')))
        if hand_ok and seq_ok:
            if hand_iss == s.get('issuer'): issuer_agree += 1
            else:
                issuer_dis += 1; dis_list.append((r['path'], s['tag'], 'issuer', hand_iss, s.get('issuer')))
        dist[(s.get('ver'), s.get('pk_algo'), s.get('hash_algo'), s.get('verify'), s.get('builder_null'), str(s.get('builder_std'))[:28])] += 1
print(f'blobs: {blob_n}, parse agree {parse_agree} / disagree {parse_dis}, issuer agree {issuer_agree} / disagree {issuer_dis}')
for d in dis_list[:10]: print('DIS', d)
print('blob outcome distribution (ver,pk,hash,lowlevel,builder_null,builder_std):')
for k, v in dist.most_common(8): print(' ', k, v)

# ---- package verdicts ----
def verdict_730(kv_v, blobs):
    # signature.rs decision table; librpm outcome from kv verdict
    if not blobs: return 'silent'
    corrupt = any(str(b.get('hand','')).startswith('error') for b in blobs)
    if kv_v == 'OK': return 'silent'
    if kv_v == 'NOKEY':
        return 'invalid-signature' if corrupt else 'unknown-key'
    if kv_v == 'BAD':
        return 'invalid-signature' if corrupt else 'silent'
    return 'kv:'+kv_v

def verdict_seq(blobs, field):
    # same table, crypto outcome composed from per-blob harness results
    if not blobs: return 'silent'
    res = [b.get(field) for b in blobs]
    corrupt = any(b.get('parse') != 'ok' or r == 'malformed' for b, r in zip(blobs, res))
    if any(r == 'malformed' for r in res): corrupt = True
    if all(r == 'good' for r in res): crypto = 'OK'
    elif any(r == 'bad' for r in res): crypto = 'BAD'
    elif any(r in ('missing',) for r in res): crypto = 'NOKEY'
    else: crypto = 'OTHER:' + ','.join(str(r) for r in res)
    if crypto == 'OK': return 'silent'
    if crypto == 'NOKEY': return 'invalid-signature' if corrupt else 'unknown-key'
    if crypto == 'BAD': return 'invalid-signature' if corrupt else 'silent'
    return crypto

stats = collections.Counter()
mismatch = []
for p in sample:
    r = by_path.get(p)
    if r is None:
        stats['missing-harness'] += 1; continue
    sigs = r['sigs']
    for dbname, kvd in (('empty', kv_empty), ('key', kv_key)):
        rel = p.split('/rpms/', 1)[-1]
        kv_v = kv_verdict(kvd.get(rel, ('',''))[0])
        v730 = verdict_730(kv_v, sigs)
        vlow = verdict_seq(sigs, 'verify') if dbname == 'key' else None
        vnull = verdict_seq(sigs, 'builder_null') if dbname == 'key' else None
        stats[(dbname, 'kv', kv_v)] += 1
        stats[(dbname, 'v730', v730)] += 1
        if dbname == 'key':
            # legacy with-key verdict mapped to 730-outcome vocabulary for comparison:
            legacy_outcome = 'silent' if kv_v == 'OK' else ('unknown-key' if kv_v == 'NOKEY' else 'silent-or-invalid')
            if vlow != v730: mismatch.append((p, 'lowlevel-vs-730', kv_v, v730, vlow))
            if vnull != v730: mismatch.append((p, 'null-vs-730', kv_v, v730, vnull))
            stats[('key', 'lowlevel', vlow)] += 1
            stats[('key', 'null', vnull)] += 1
print('verdict tallies:')
for k in sorted(stats, key=str): print(' ', k, stats[k])
print(f'mismatches (with-key leg): {len(mismatch)}')
for m in mismatch[:10]: print('MIS', m)
