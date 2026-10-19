#!/usr/bin/env python3
import json, os, subprocess
W = '/Users/fluff/work/eval779/'
S = W + 'slice/'
HV = '/Users/fluff/work/rpmcrab/eval-779/target/release/examples/sequoia_verify'
manifest = json.load(open(S+'manifest.json'))
out = open(W+'harness-slice.jsonl', 'w')
def hv(pkg, keyfiles, suffix=''):
    cmd = [HV, '--hand', '--builder']
    if keyfiles:
        cmd += ['--keys'] + keyfiles
    cmd += [pkg]
    r = subprocess.run(cmd, capture_output=True, text=True)
    for line in r.stdout.splitlines():
        if suffix:
            d = json.loads(line); d['path'] += suffix
            line = json.dumps(d)
        out.write(line + '\n')
    if r.returncode != 0:
        print('HV FAIL', pkg, r.stderr[:200])
for e in manifest:
    hv(S+'pkgs/'+e['file'], e['keyfiles'])
    if e['case'] == 'revoked-rsa2048':
        hv(S+'pkgs/'+e['file'], [S+'keys/revoked-after.asc'], suffix='#revoked-after')
    if e['case'] == 'mixed-keys':
        hv(S+'pkgs/'+e['file'], [S+'keys/rsa4096.asc'], suffix='#onekey')
hv(W+'sle11/timezone-11.4.rpm', [W+'sle11/opensuse-11.4-buildkey.asc'], suffix='#sle11')
out.close()
print('harness-slice rows:', sum(1 for _ in open(W+'harness-slice.jsonl')))
