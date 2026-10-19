import os, subprocess, sys
from concurrent.futures import ThreadPoolExecutor
ROOT = '/home/fluff/factory-full/rpms'
DB = '/home/fluff/eval779/emptydb'
OUT = '/home/fluff/eval779/pass1.tsv'
files = []
for dp, dn, fn in os.walk(ROOT):
    for f in fn:
        if f.endswith('.rpm') and not f.endswith('.nosrc.rpm'):
            files.append(os.path.join(dp, f))
files.sort()
print(f'{len(files)} rpms', flush=True)
def work(p):
    try:
        r = subprocess.run(['rpm', '--dbpath', DB, '-Kv', p], capture_output=True, text=True, timeout=120)
        sig = [l.strip() for l in (r.stdout + r.stderr).splitlines() if 'ignature' in l]
        return (os.path.relpath(p, ROOT), ' ;; '.join(sig), r.returncode)
    except Exception as e:
        return (os.path.relpath(p, ROOT), f'EXC {e}', -1)
done = 0
with open(OUT, 'w') as out, ThreadPoolExecutor(max_workers=16) as ex:
    for rel, sig, rc in ex.map(work, files, chunksize=64):
        out.write(f'{rel}\t{sig}\t{rc}\n')
        done += 1
        if done % 5000 == 0:
            print(f'{done}/{len(files)}', flush=True)
print('DONE', flush=True)
