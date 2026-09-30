//! `BuildRootAndDateCheck`: file-level validation, ported from rpmlint's
//! `BuildRootAndDateCheck.py`.
//!
//! Flags files embedding today's date (a build that was not reproducible:
//! compliant builds never contain the current date) and files embedding the
//! build root path. The date findings skip documentation and changelog paths,
//! where dates are legitimate content, and become errors under the `slfo`
//! flavor instead of warnings.

use fancy_regex::Regex;

use super::is_match;
use crate::check::{Check, add_info};
use crate::config::Config;
use crate::filter::Filter;
use crate::level::Level;
use crate::pkg::Pkg;
use crate::pkg::pkgfile::{self, PkgFile};

/// Paths where a date string is legitimate content rather than a build stamp;
/// the date findings skip these (upstream #1317).
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

/// `time.strftime('%b %e %Y')`: e.g. `Sep 30 2026` (space-padded day).
fn today_string() -> String {
    chrono::Local::now().format("%b %e %Y").to_string()
}

fn time_regex() -> Regex {
    Regex::new(r"(2[0-3]|[01]?[0-9]):([0-5]?[0-9]):([0-5]?[0-9])").expect("static regex")
}

/// The reference builds this from `rpm.expandMacro('%{?buildroot}')`, which
/// rpm 4.20 expands to the empty string, so the fallback below is what runs
/// in practice. The component class is byte-identical to the reference.
fn buildroot_regex() -> Regex {
    let mut pattern = String::from("/%{NAME}-%{VERSION}-build/BUILDROOT/");
    for macro_name in ["name", "version", "release", "NAME", "VERSION", "RELEASE"] {
        pattern = pattern.replace(&format!("%{{{macro_name}}}"), r"[\w\!-\.]{1,20}");
    }
    Regex::new(&pattern).expect("static regex")
}

pub struct BuildRootAndDateCheck {
    istoday: Regex,
    looksliketime: Regex,
    lookslikebuildroot: Regex,
}

impl BuildRootAndDateCheck {
    pub fn new(_config: &Config) -> Self {
        Self {
            istoday: Regex::new(&today_string()).expect("static regex"),
            looksliketime: time_regex(),
            lookslikebuildroot: buildroot_regex(),
        }
    }

    fn check_file(
        &self,
        pkg: &Pkg,
        filename: &str,
        pkgfile: &PkgFile,
        date_level: Level,
        out: &mut Filter,
    ) {
        if filename.starts_with("/usr/lib/debug") || !pkgfile::is_reg(pkgfile.mode) {
            return;
        }
        let data = pkg.read_file(filename);
        for (level, finding) in self.findings_for(filename, &data, date_level) {
            add_info(out, level, pkg, finding, &[filename]);
        }
    }

    /// The findings for one file's content. Pure so the unit tests need no
    /// package scaffolding.
    fn findings_for(
        &self,
        filename: &str,
        data: &str,
        date_level: Level,
    ) -> Vec<(Level, &'static str)> {
        let mut findings = Vec::new();
        // Hardened vs the reference: dates are legitimate content in docs and
        // changelogs. The buildroot finding is never skipped.
        if !is_date_fp_prone(filename) && is_match(&self.istoday, data) {
            findings.push((
                date_level,
                if is_match(&self.looksliketime, data) {
                    "file-contains-date-and-time"
                } else {
                    "file-contains-current-date"
                },
            ));
        }
        if is_match(&self.lookslikebuildroot, data) {
            findings.push((Level::Error, "file-contains-buildroot"));
        }
        findings
    }
}

impl Check for BuildRootAndDateCheck {
    fn name(&self) -> &'static str {
        "BuildRootAndDateCheck"
    }

    fn check_binary(&mut self, pkg: &Pkg, config: &Config, out: &mut Filter) {
        if pkg.is_source {
            return;
        }
        // Immutable SLFO images require reproducible builds, so embedded
        // dates are errors there and warnings elsewhere.
        let date_level = if config.is_slfo() {
            Level::Error
        } else {
            Level::Warning
        };
        for f in &pkg.files {
            self.check_file(pkg, &f.name, f, date_level, out);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn check() -> BuildRootAndDateCheck {
        BuildRootAndDateCheck::new(&Config::default())
    }

    fn slfo_config() -> Config {
        let mut config = Config::default();
        config.configuration.insert(
            "Flavor".to_string(),
            toml::Value::String("slfo".to_string()),
        );
        config.finalize();
        config
    }

    #[test]
    fn date_and_time_in_file_fires_warning() {
        let data = format!("built {} 23:59:58", today_string());
        assert_eq!(
            check().findings_for("/usr/bin/foo", &data, Level::Warning),
            [(Level::Warning, "file-contains-date-and-time")]
        );
    }

    #[test]
    fn date_and_time_fires_error_under_slfo() {
        let config = slfo_config();
        assert!(config.is_slfo());
        let data = format!("built {} 23:59:58", today_string());
        assert_eq!(
            check().findings_for("/usr/bin/foo", &data, Level::Error),
            [(Level::Error, "file-contains-date-and-time")]
        );
    }

    #[test]
    fn date_without_time_fires_current_date() {
        let data = format!("built {}", today_string());
        assert_eq!(
            check().findings_for("/usr/bin/foo", &data, Level::Warning),
            [(Level::Warning, "file-contains-current-date")]
        );
    }

    #[test]
    fn date_in_doc_dir_is_skipped() {
        let data = format!("built {} 23:59:58", today_string());
        assert!(
            check()
                .findings_for("/usr/share/doc/foo/README", &data, Level::Warning)
                .is_empty()
        );
    }

    #[test]
    fn date_in_changelog_is_skipped() {
        let data = format!("built {} 23:59:58", today_string());
        assert!(
            check()
                .findings_for("/usr/src/packages/CHANGELOG", &data, Level::Warning)
                .is_empty()
        );
    }

    #[test]
    fn date_in_changes_file_is_skipped() {
        let data = format!("built {} 23:59:58", today_string());
        assert!(
            check()
                .findings_for("/usr/src/packages/foo.changes", &data, Level::Warning)
                .is_empty()
        );
    }

    #[test]
    fn buildroot_string_fires_error() {
        let data = "prefix /myapp-2.0-build/BUILDROOT/ suffix";
        assert_eq!(
            check().findings_for("/usr/bin/foo", data, Level::Warning),
            [(Level::Error, "file-contains-buildroot")]
        );
    }

    #[test]
    fn buildroot_in_doc_dir_still_fires() {
        // The hardening skip covers the date findings only, never buildroot.
        let data = "prefix /myapp-2.0-build/BUILDROOT/ suffix";
        assert_eq!(
            check().findings_for("/usr/share/doc/foo/README", data, Level::Warning),
            [(Level::Error, "file-contains-buildroot")]
        );
    }

    #[test]
    fn clean_file_has_no_findings() {
        assert!(
            check()
                .findings_for("/usr/bin/foo", "nothing to see here", Level::Warning)
                .is_empty()
        );
    }

    #[test]
    fn is_date_fp_prone_covers_doc_and_changelog_paths() {
        for path in [
            "/usr/share/doc/foo/README",
            "/usr/share/man/man1/foo.1",
            "/usr/share/info/foo.info",
            "/usr/share/licenses/foo/LICENSE",
            "/usr/src/packages/foo.changes",
            "/usr/src/packages/CHANGELOG",
            "/usr/src/packages/NEWS",
        ] {
            assert!(is_date_fp_prone(path), "{path}");
        }
        for path in ["/usr/bin/foo", "/etc/foo.conf", "/usr/lib/libfoo.so"] {
            assert!(!is_date_fp_prone(path), "{path}");
        }
    }

    #[test]
    fn today_string_matches_strftime_format() {
        // `%b %e %Y`: abbreviated month, space-padded day, e.g. `Sep 30 2026`.
        let today = today_string();
        assert_eq!(today.len(), 11, "{today}");
        assert_eq!(&today[3..4], " ");
        assert!(today[7..].parse::<u32>().is_ok(), "{today}");
    }
}
