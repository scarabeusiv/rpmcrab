# SLFO Flavor

**Status:** Implemented. `BuildRootAndDateCheck` (`checks::buildroot`) is the
first flavor-gated check: the `file-contains-date-and-time` and
`file-contains-current-date` findings are warnings under `"opensuse"` and
errors under `"slfo"`.

The `Flavor` config key (DESIGN.md §4.11) controls flavor-specific check
behavior. rpmcrab does not branch; one `"slfo"` value covers the SLFO
branches.

## Config plumbing

In `crates/rpmcrab-core/src/config.rs`:

```rust
/// `Flavor` (default `"opensuse"`); unknown values warn and fall back to
/// `"opensuse"`.
pub flavor: String,
```

Derived in `Config::finalize()` from the merged TOML table: lowercased,
default `"opensuse"`, unknown values print a stderr warning and fall back to
`"opensuse"`.

Helper, next to the existing config predicates:

```rust
impl Config {
    /// True when the `slfo` flavor is selected.
    pub fn is_slfo(&self) -> bool {
        self.flavor == "slfo"
    }
}
```

No trait changes: `Config` (or `&Config`) is already passed to every check's
`check` / `check_binary` entry points.

## Gating pattern

At the decision point, branch on `config.is_slfo()`. For severity flips,
make the level a variable rather than duplicating the emit call:

```rust
// checks/buildroot.rs
let date_level = if config.is_slfo() {
    Level::Error
} else {
    Level::Warning
};
```

## Hardening

`BuildRootAndDateCheck` skips the date findings (not
`file-contains-buildroot`) on paths where dates are legitimate content:

```rust
const DATE_FP_SKIP_PREFIXES: &[&str] = &[
    "/usr/share/doc/",
    "/usr/share/man/",
    "/usr/share/info/",
    "/usr/share/licenses/",
];

fn is_date_fp_prone(path: &str) -> bool {
    DATE_FP_SKIP_PREFIXES.iter().any(|p| path.starts_with(p))
        || path.ends_with(".changes")
        || path.contains("CHANGELOG")
        || path.contains("NEWS")
}
```

This addresses the false positives behind upstream #1317. Tom's decision
keeps the check: matching *today's* date still signals a non-reproducible
build.

## Ledger entries

Each gated divergence gets a `[[divergence]]` entry in
`tests/parity/divergences.toml`, with the flavor recorded so corpus diffs
stay legible:

```toml
[[divergence]]
case = "buildroot"
check = "file-contains-date-and-time"
flavor = "slfo"
kind = "behaviour"
reason = "Severity is Error under Flavor=\"slfo\" (immutable images require reproducible builds); Warning otherwise, matching the frozen 2.10.0 opensuse reference. The check is hardened vs the reference: documentation paths and changelog files are skipped to avoid the false positives noted in upstream #1317."
```

The corpus runner (§6) runs in the default `"opensuse"` flavor, so the
ledger remains the record of intentional departures from the reference.

## Out of scope

- **No `slfo-1.2` vs `slfo-main` distinction.** The check-level divergences
  are identical in both branches; 1.2 is simply older. One `"slfo"` value
  covers both.
- **No auto-detection** (no `/etc/os-release` sniffing). Flavor is a
  property of the lint target, not the host.
