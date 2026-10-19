# Synthetic signature slice for the #779 evaluation

`mkslice.py` builds one unsigned base RPM with rpmbuild, detach-signs its
header and header+payload ranges with GnuPG keys generated for the purpose
(RSA-4096/1024, DSA-1024, ECDSA P-256, Ed25519, an expired key signed
in-validity, a revoked key, a signing-subkey key), and transplants the
signature packets into the signature header (`assemble()` in the script).
Mutation cases (corrupted MPI, truncated blob, critical-bit issuer,
zero-bit MPI, v5 re-label, new-format re-heading, indeterminate
old-format lengths) are byte edits of the RSA-4096/SHA256 baseline, plus
`badpaysig.rpm` (MPI byte flipped inside the header+payload blob of the
assembled baseline package). `manifest.json` lists every case with its
signing key; `keys/` holds the public certs (binary exports, `arm-*` are
the armoured exports rpm's `--import` requires).

Legs: `rpm -Kv` against empty/per-case rpmdb keyrings (`kv-slice.tsv`),
the `sequoia_verify` harness with each case's key files
(`harness-slice.jsonl`, produced by `run_harness_slice.py`), and the
#730 release binary with the keyring selected through a HOME-scoped
`.rpmmacros` `%_dbpath`. `analyse_slice.py` renders the three-way
comparison. The corpus-sample outputs (`sample1200.txt`,
`harness-sample.jsonl`, `pass1-sample.tsv`, `pass2-sample.tsv`,
`analyse_sample.py`) are the 1,200-package random sample
(`random.Random(779)` over the sorted usable-RPM list) from the
classification pass in `eval-data/`.
