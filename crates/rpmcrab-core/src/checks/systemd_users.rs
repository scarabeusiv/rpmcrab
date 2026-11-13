//! `SystemdUsersCheck` — users and groups referenced by systemd unit
//! files and D-Bus system policy files must exist.
//!
//! A unit's `User=`/`Group=` (and `SupplementaryGroups=`,
//! `SocketUser=`/`SocketGroup=`) names the account the service runs
//! as; a D-Bus `<policy user="...">` / `<policy group="...">` scopes
//! its rules to that account. Either reference dangles when the
//! account is provided by no package: the service fails to start, or
//! the policy matches nobody. A reference is valid when the account
//! is declared by the package's own sysusers.d snippet (the
//! declarative route), required as a `user(<name>)` / `group(<name>)`
//! capability (provided by another package), listed in the
//! distribution's standard tables, or a numeric id (which names no
//! account to declare). Findings: `systemd-unit-unknown-user`,
//! `systemd-unit-unknown-group`, `dbus-policy-unknown-user`,
//! `dbus-policy-unknown-group`.
//!
//! Scope (POC): `.service` and `.socket` units directly under the
//! system and user unit directories; tmpfiles.d `user:group` fields
//! are not judged here (they name file owners, judged by
//! `non-standard-uid` / `non-standard-gid`), and units with
//! `DynamicUser=` set to a true boolean (`1`/`yes`/`true`/`on`,
//! case-insensitive) are skipped whole — their accounts are allocated
//! at runtime, not declared anywhere.

use std::collections::HashSet;

use crate::check::{Check, add_info};
use crate::checks::dbus_policy::{DBusPolicyCheck, policy_subjects};
use crate::checks::files::own_sysusers_declared;
use crate::config::Config;
use crate::filter::Filter;
use crate::level::Level;
use crate::pkg::Pkg;
use crate::pkg::dep::leaf_account_capability;

const UNIT_DIRECTORIES: &[&str] = &[
    "/usr/lib/systemd/system/",
    "/etc/systemd/system/",
    "/usr/lib/systemd/user/",
    "/etc/systemd/user/",
];

/// One user/group reference in a unit file: whether it is a group,
/// the directive that named it, and the account name.
struct UnitRef {
    is_group: bool,
    directive: &'static str,
    name: String,
}

/// Whether `value` is a systemd true boolean: `1`, `yes`, `true` or
/// `on`, case-insensitive (systemd.syntax(7)). Only the first token
/// counts, so a trailing `#`/`;` comment is ignored.
fn is_true_boolean(value: &str) -> bool {
    let Some(first) = value.split_whitespace().next() else {
        return false;
    };
    first == "1"
        || first.eq_ignore_ascii_case("yes")
        || first.eq_ignore_ascii_case("true")
        || first.eq_ignore_ascii_case("on")
}

/// The user/group references in a unit file's content, in file order.
/// Only `[Service]` `User=`/`Group=`/`SupplementaryGroups=` and
/// `[Socket]` `SocketUser=`/`SocketGroup=` name accounts. A value is
/// read as whitespace-separated tokens (a trailing `#`/`;` comment
/// ends the tokens; a token carrying a `%` specifier cannot be
/// resolved statically and is skipped). A file with
/// `DynamicUser=` set to a true boolean (`1`/`yes`/`true`/`on`,
/// case-insensitive, per systemd.syntax(7)) names no static account:
/// its references are dropped whole.
fn unit_refs(content: &str) -> Vec<UnitRef> {
    let mut refs = Vec::new();
    let mut section = "";
    let mut dynamic_user = false;
    for raw in content.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }
        if line.starts_with('[') && line.ends_with(']') {
            section = &line[1..line.len() - 1];
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let key = key.trim();
        let value = value.trim();
        if section == "Service" && key == "DynamicUser" && is_true_boolean(value) {
            dynamic_user = true;
        }
        let (directive, is_group, multi) = match (section, key) {
            ("Service", "User") => ("User", false, false),
            ("Service", "Group") => ("Group", true, false),
            ("Service", "SupplementaryGroups") => ("SupplementaryGroups", true, true),
            ("Socket", "SocketUser") => ("SocketUser", false, false),
            ("Socket", "SocketGroup") => ("SocketGroup", true, false),
            _ => continue,
        };
        for token in value.split_whitespace() {
            if token.starts_with('#') || token.starts_with(';') {
                break;
            }
            if token.contains('%') {
                continue;
            }
            refs.push(UnitRef {
                is_group,
                directive,
                name: token.to_string(),
            });
            if !multi {
                break;
            }
        }
    }
    if dynamic_user {
        return Vec::new();
    }
    refs
}

/// The accounts one reference may resolve to: the package's own
/// sysusers.d declarations, its `user()`/`group()` Requires, and the
/// distribution's standard tables.
struct Accounts {
    users: HashSet<String>,
    groups: HashSet<String>,
}

impl Accounts {
    fn for_pkg(
        pkg: &Pkg,
        standard_users: &HashSet<String>,
        standard_groups: &HashSet<String>,
    ) -> Self {
        let (mut users, mut groups) = own_sysusers_declared(pkg);
        users.extend(standard_users.iter().cloned());
        groups.extend(standard_groups.iter().cloned());
        for dep in pkg.requires.iter().chain(pkg.prereq.iter()) {
            for leaf in dep.leaves() {
                if let Some((group, name)) = leaf_account_capability(&leaf) {
                    if group {
                        groups.insert(name.to_string());
                    } else {
                        users.insert(name.to_string());
                    }
                }
            }
        }
        Self { users, groups }
    }
}

/// Whether `name` names an account that exists: a numeric id names
/// no account to declare, so it always counts as valid.
fn is_valid(name: &str, is_group: bool, accounts: &Accounts) -> bool {
    if !name.is_empty() && name.bytes().all(|b| b.is_ascii_digit()) {
        return true;
    }
    if is_group {
        accounts.groups.contains(name)
    } else {
        accounts.users.contains(name)
    }
}

pub struct SystemdUsersCheck {
    standard_users: HashSet<String>,
    standard_groups: HashSet<String>,
}

impl SystemdUsersCheck {
    pub fn new(config: &Config) -> Self {
        let tbl = &config.configuration;
        let get_strings = |k: &str| {
            tbl.get(k)
                .and_then(toml::Value::as_array)
                .map(|a| {
                    a.iter()
                        .filter_map(|v| v.as_str().map(str::to_string))
                        .collect()
                })
                .unwrap_or_default()
        };
        Self {
            standard_users: get_strings("StandardUsers"),
            standard_groups: get_strings("StandardGroups"),
        }
    }

    /// True when `path` is a unit file this check judges: a
    /// `.service` or `.socket` directly under a unit directory.
    /// Symlinks under `.wants`/`.requires` subdirectories name the
    /// same unit twice and are not units themselves.
    fn is_unit_file(path: &str) -> bool {
        if !(path.ends_with(".service") || path.ends_with(".socket")) {
            return false;
        }
        UNIT_DIRECTORIES
            .iter()
            .any(|d| path.starts_with(d) && !path[d.len()..].contains('/'))
    }
}

impl Check for SystemdUsersCheck {
    fn name(&self) -> &'static str {
        "SystemdUsersCheck"
    }

    fn check_binary(&mut self, pkg: &Pkg, _config: &Config, out: &mut Filter) {
        if pkg.is_source {
            return;
        }
        let accounts = Accounts::for_pkg(pkg, &self.standard_users, &self.standard_groups);
        for file in &pkg.files {
            let fname = file.name.as_str();
            if pkg.ghost_files.contains(fname) {
                continue;
            }
            if Self::is_unit_file(fname) {
                let content = pkg.read_file(fname);
                for r in unit_refs(&content) {
                    if !is_valid(&r.name, r.is_group, &accounts) {
                        let finding = if r.is_group {
                            "systemd-unit-unknown-group"
                        } else {
                            "systemd-unit-unknown-user"
                        };
                        let detail = format!("{}={}", r.directive, r.name);
                        add_info(out, Level::Warning, pkg, finding, &[fname, &detail]);
                    }
                }
            } else if DBusPolicyCheck::is_policy_file(fname) {
                let content = pkg.read_file(fname);
                // A malformed file is skipped: the parse failure is
                // already charged by `DBusPolicyCheck`.
                let Ok(subjects) = policy_subjects(&content) else {
                    continue;
                };
                for s in subjects {
                    if !is_valid(&s.name, s.is_group, &accounts) {
                        let finding = if s.is_group {
                            "dbus-policy-unknown-group"
                        } else {
                            "dbus-policy-unknown-user"
                        };
                        let detail = format!(
                            "{}=\"{}\"",
                            if s.is_group { "group" } else { "user" },
                            s.name
                        );
                        add_info(out, Level::Warning, pkg, finding, &[fname, &detail]);
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::color::Color;
    use crate::pkg::dep::DepInfo;
    use crate::pkg::pkgfile::PkgFile;

    fn test_config() -> Config {
        let defaults: toml::Table = toml::from_str(include_str!("../../data/configdefaults.toml"))
            .expect("parse configdefaults");
        Config {
            configuration: defaults,
            ..Default::default()
        }
    }

    fn refs(content: &str) -> Vec<(bool, &'static str, String)> {
        unit_refs(content)
            .into_iter()
            .map(|r| (r.is_group, r.directive, r.name))
            .collect()
    }

    #[test]
    fn unit_refs_collects_service_and_socket_directives() {
        let content = "[Unit]\nDescription=probe\n\n[Service]\nUser=foosvc\nGroup=foogrp\nSupplementaryGroups=grp1 grp2\nExecStart=/usr/bin/probe\n\n[Socket]\nSocketUser=socku\nSocketGroup=sockg\n";
        assert_eq!(
            refs(content),
            vec![
                (false, "User", "foosvc".to_string()),
                (true, "Group", "foogrp".to_string()),
                (true, "SupplementaryGroups", "grp1".to_string()),
                (true, "SupplementaryGroups", "grp2".to_string()),
                (false, "SocketUser", "socku".to_string()),
                (true, "SocketGroup", "sockg".to_string()),
            ]
        );
    }

    #[test]
    fn unit_refs_ignores_other_sections_and_lines() {
        let content = "[Unit]\nUser=not-a-service-user\n[Install]\nWantedBy=multi-user.target\n[Service]\n# a comment\n; another comment\nExecStart=/usr/bin/probe\nNoEqualsSignHere\n";
        assert!(refs(content).is_empty());
    }

    #[test]
    fn unit_refs_stops_at_trailing_comment_and_skips_specifiers() {
        let content = "[Service]\nUser=foosvc # the daemon account\nGroup=%g\nSupplementaryGroups=grp1 %G grp2\n";
        assert_eq!(
            refs(content),
            vec![
                (false, "User", "foosvc".to_string()),
                (true, "SupplementaryGroups", "grp1".to_string()),
                (true, "SupplementaryGroups", "grp2".to_string()),
            ]
        );
    }

    #[test]
    fn unit_refs_dynamic_user_skips_the_file() {
        // systemd.syntax(7) true booleans, any case: each skips the
        // file whole.
        for spelling in ["yes", "Yes", "YES", "true", "True", "1", "on", "On"] {
            let content = format!("[Service]\nDynamicUser={spelling}\nUser=foosvc\nGroup=foogrp\n");
            assert!(
                refs(&content).is_empty(),
                "DynamicUser={spelling} must skip the file"
            );
        }
    }

    #[test]
    fn unit_refs_dynamic_user_false_spellings_still_judge() {
        // False booleans do not skip: the references are still judged.
        for spelling in ["no", "false", "0", "off"] {
            let content = format!("[Service]\nDynamicUser={spelling}\nUser=foosvc\nGroup=foogrp\n");
            assert_eq!(
                refs(&content),
                vec![
                    (false, "User", "foosvc".to_string()),
                    (true, "Group", "foogrp".to_string()),
                ],
                "DynamicUser={spelling} must not skip the file"
            );
        }
    }

    #[test]
    fn unit_refs_empty_value_names_nothing() {
        assert!(refs("[Service]\nUser=\nGroup=\n").is_empty());
    }

    #[test]
    fn is_valid_accepts_numeric_declared_standard_and_required() {
        let accounts = Accounts {
            users: ["foosvc".to_string(), "root".to_string()]
                .into_iter()
                .collect(),
            groups: ["foogrp".to_string(), "root".to_string()]
                .into_iter()
                .collect(),
        };
        assert!(is_valid("1000", false, &accounts));
        assert!(is_valid("0", true, &accounts));
        assert!(is_valid("foosvc", false, &accounts));
        assert!(is_valid("foogrp", true, &accounts));
        assert!(is_valid("root", false, &accounts));
        assert!(!is_valid("ghost", false, &accounts));
        assert!(!is_valid("ghostgrp", true, &accounts));
        // A user declaration does not credit the group side, and
        // vice versa: `foosvc` is a user only here.
        assert!(!is_valid("foosvc", true, &accounts));
    }

    /// Open the fixture RPM into `dir` and write `files`
    /// (`(installed path, content)`) under the extracted tree, so
    /// `Pkg::read_file` sees them. Returns the package with only
    /// those files listed.
    fn users_pkg(dir: &tempfile::TempDir, files: &[(&str, &str)]) -> Pkg {
        let rpm = format!(
            "{}/../../tests/parity/pkg/inputs/fcprobe-1-1.noarch.rpm",
            env!("CARGO_MANIFEST_DIR")
        );
        let mut pkg =
            Pkg::open(std::path::Path::new(&rpm), dir.path(), true).expect("open fixture pkg");
        pkg.name = "users-test".to_string();
        pkg.files.clear();
        for (name, content) in files {
            let rel = name.trim_start_matches('/');
            let path = pkg.dir_name().join(rel);
            std::fs::create_dir_all(path.parent().unwrap()).expect("mkdirs");
            std::fs::write(&path, content).expect("write file");
            pkg.files.push(PkgFile {
                name: name.to_string(),
                path: path.to_string_lossy().into_owned(),
                mode: 0o100644,
                ..Default::default()
            });
        }
        pkg
    }

    fn findings_for(pkg: &Pkg) -> Vec<(String, String)> {
        let config = test_config();
        let mut out = Filter::new(&config, Color::for_tty(false)).unwrap();
        let mut check = SystemdUsersCheck::new(&config);
        check.check_binary(pkg, &config, &mut out);
        out.results().to_vec()
    }

    fn has(results: &[(String, String)], finding: &str) -> bool {
        results.iter().any(|(n, _)| n == finding)
    }

    #[test]
    fn standard_account_in_unit_is_quiet() {
        let dir = tempfile::TempDir::new().expect("tmpdir");
        let pkg = users_pkg(
            &dir,
            &[(
                "/usr/lib/systemd/system/probe.service",
                "[Service]\nUser=root\nGroup=root\nExecStart=/usr/bin/probe\n",
            )],
        );
        let results = findings_for(&pkg);
        assert!(
            results.is_empty(),
            "standard accounts must stay quiet: {results:?}"
        );
    }

    #[test]
    fn sysusers_declared_account_in_unit_is_quiet() {
        let dir = tempfile::TempDir::new().expect("tmpdir");
        let pkg = users_pkg(
            &dir,
            &[
                (
                    "/usr/lib/sysusers.d/probe.conf",
                    "u foosvc - \"Foo service\" /var/lib/foo /bin/false\n",
                ),
                (
                    "/usr/lib/systemd/system/probe.service",
                    "[Service]\nUser=foosvc\nGroup=foosvc\nExecStart=/usr/bin/probe\n",
                ),
            ],
        );
        let results = findings_for(&pkg);
        assert!(
            results.is_empty(),
            "a sysusers-declared account must stay quiet: {results:?}"
        );
    }

    #[test]
    fn unknown_user_and_group_in_unit_fire() {
        let dir = tempfile::TempDir::new().expect("tmpdir");
        let pkg = users_pkg(
            &dir,
            &[(
                "/usr/lib/systemd/system/probe.service",
                "[Service]\nUser=ghostsvc\nGroup=ghostgrp\nSupplementaryGroups=alsoghost\nExecStart=/usr/bin/probe\n",
            )],
        );
        let results = findings_for(&pkg);
        assert_eq!(
            results
                .iter()
                .filter(|(n, _)| n == "systemd-unit-unknown-user")
                .count(),
            1,
            "unknown user must fire once: {results:?}"
        );
        assert_eq!(
            results
                .iter()
                .filter(|(n, _)| n == "systemd-unit-unknown-group")
                .count(),
            2,
            "both unknown groups must fire: {results:?}"
        );
        assert!(
            results
                .iter()
                .any(|(_, line)| line.contains(" W: ") && line.ends_with("User=ghostsvc")),
            "warning line names the reference: {results:?}"
        );
    }

    #[test]
    fn numeric_user_in_unit_is_quiet() {
        let dir = tempfile::TempDir::new().expect("tmpdir");
        let pkg = users_pkg(
            &dir,
            &[(
                "/usr/lib/systemd/system/probe.service",
                "[Service]\nUser=1000\nGroup=100\nExecStart=/usr/bin/probe\n",
            )],
        );
        assert!(findings_for(&pkg).is_empty());
    }

    #[test]
    fn required_account_in_unit_is_quiet() {
        let dir = tempfile::TempDir::new().expect("tmpdir");
        let mut pkg = users_pkg(
            &dir,
            &[(
                "/usr/lib/systemd/system/probe.service",
                "[Service]\nUser=foosvc\nGroup=foogrp\nExecStart=/usr/bin/probe\n",
            )],
        );
        pkg.requires = vec![
            DepInfo {
                name: "user(foosvc)".to_string(),
                flags: 0,
                epoch: None,
                version: None,
                release: None,
            },
            DepInfo {
                name: "group(foogrp)".to_string(),
                flags: 0,
                epoch: None,
                version: None,
                release: None,
            },
        ];
        assert!(
            findings_for(&pkg).is_empty(),
            "a required account must stay quiet: {:?}",
            findings_for(&pkg)
        );
    }

    #[test]
    fn dbus_policy_subjects_fire_and_stay_quiet() {
        let dir = tempfile::TempDir::new().expect("tmpdir");
        let pkg = users_pkg(
            &dir,
            &[
                (
                    "/usr/lib/sysusers.d/probe.conf",
                    "u dbsvc - \"D-Bus service\" /var/lib/db /bin/false\ng dbgrp\n",
                ),
                (
                    "/usr/share/dbus-1/system.d/probe.conf",
                    "<busconfig>\n<policy user=\"root\"><allow own=\"org.foo.Root\"/></policy>\n<policy user=\"dbsvc\"><allow own=\"org.foo.Svc\"/></policy>\n<policy group=\"dbgrp\"><allow send_interface=\"org.foo.Svc\"/></policy>\n<policy user=\"ghost\"><allow own=\"org.foo.Ghost\"/></policy>\n<policy group=\"ghostgrp\"><allow send_interface=\"org.foo.Ghost\"/></policy>\n</busconfig>\n",
                ),
            ],
        );
        let results = findings_for(&pkg);
        assert_eq!(
            results
                .iter()
                .filter(|(n, _)| n == "dbus-policy-unknown-user")
                .count(),
            1,
            "only the unknown user fires: {results:?}"
        );
        assert_eq!(
            results
                .iter()
                .filter(|(n, _)| n == "dbus-policy-unknown-group")
                .count(),
            1,
            "only the unknown group fires: {results:?}"
        );
        assert!(has(&results, "dbus-policy-unknown-user"));
        assert!(!results.iter().any(|(_, line)| line.contains("dbsvc")));
        assert!(!results.iter().any(|(_, line)| line.contains("dbgrp")));
    }

    #[test]
    fn socket_user_and_group_are_judged() {
        let dir = tempfile::TempDir::new().expect("tmpdir");
        let pkg = users_pkg(
            &dir,
            &[(
                "/usr/lib/systemd/system/probe.socket",
                "[Socket]\nSocketUser=ghostsock\nSocketGroup=root\nListenStream=/run/probe.sock\n",
            )],
        );
        let results = findings_for(&pkg);
        assert_eq!(
            results
                .iter()
                .filter(|(n, _)| n == "systemd-unit-unknown-user")
                .count(),
            1,
            "unknown socket user must fire: {results:?}"
        );
        assert!(
            !has(&results, "systemd-unit-unknown-group"),
            "standard socket group must stay quiet: {results:?}"
        );
    }

    #[test]
    fn dynamic_user_true_spellings_stay_quiet() {
        // End to end: DynamicUser=true/1/on/Yes with unknown accounts
        // fires nothing, whatever the spelling.
        for spelling in ["true", "1", "on", "Yes"] {
            let dir = tempfile::TempDir::new().expect("tmpdir");
            let content = format!(
                "[Service]\nDynamicUser={spelling}\nUser=ghostsvc\nGroup=ghostgrp\nExecStart=/usr/bin/probe\n"
            );
            let pkg = users_pkg(
                &dir,
                &[("/usr/lib/systemd/system/probe.service", content.as_str())],
            );
            let results = findings_for(&pkg);
            assert!(
                results.is_empty(),
                "DynamicUser={spelling} must stay quiet: {results:?}"
            );
        }
    }

    #[test]
    fn unit_symlink_under_wants_is_not_a_unit() {
        let dir = tempfile::TempDir::new().expect("tmpdir");
        let pkg = users_pkg(
            &dir,
            &[(
                "/usr/lib/systemd/system/multi-user.target.wants/probe.service",
                "[Service]\nUser=ghostsvc\nExecStart=/usr/bin/probe\n",
            )],
        );
        assert!(
            findings_for(&pkg).is_empty(),
            "a .wants symlink target must not be judged as a unit"
        );
    }
}
