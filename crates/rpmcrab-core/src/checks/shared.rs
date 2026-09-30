//! Shared check helpers (`docs/DESIGN.md` §7.2).
//!
//! Path/mode predicates, tag readers, and regexes that two or more checks
//! would otherwise each write. A new check reuses these; new shared logic
//! goes here, not in the check.

use fancy_regex::Regex;

use crate::pkg::Pkg;

/// `AbstractCheck.macro_regex`: `%+[{(]?[a-zA-Z_]\w{2,}[)}]?`.
pub fn macro_regex() -> Regex {
    Regex::new(r"%+[{(]?[a-zA-Z_]\w{2,}[)}]?").expect("static regex")
}

/// `FilesCheck.devel_regex`: `(.*)-(debug(info|source)?|devel|headers|source|static|prof)$`.
pub fn devel_regex() -> Regex {
    Regex::new(r"(.*)-(debug(info|source)?|devel|headers|source|static|prof)$")
        .expect("static regex")
}

/// `lib_package_regex`: `(?:^(?:compat-)?lib.*?(\.so.*)?|libs?[\d-]*)$`, case-insensitive.
pub fn lib_package_regex() -> Regex {
    Regex::new(r"(?i)(?:^(?:compat-)?lib.*?(\.so.*)?|libs?[\d-]*)$").expect("static regex")
}

/// The reference's `pkg[tag] or pkg.scriptprog(prog)`: the scriptlet body
/// wins whenever it is non-empty; an empty body falls back to the `-p`
/// interpreter string. This is the one place that choice is made -- every
/// check that needs a scriptlet goes through this helper instead of
/// open-coding the choice (see the `scriptlet_choice` test).
pub(crate) fn script_body_or_prog(pkg: &Pkg, tag: librpm::Tag, prog: librpm::Tag) -> String {
    let body = pkg.tag_str(tag).unwrap_or_default();
    if body.is_empty() {
        pkg.scriptprog(prog)
    } else {
        body
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::check::Check;
    use crate::checks::files::FilesCheck;
    use crate::color::Color;
    use crate::config::Config;
    use crate::filter::Filter;

    #[test]
    fn macro_regex_matches_unexpanded_macro() {
        // Regression: files.rs had \\w (double-escaped) which matched a
        // literal backslash-w instead of word characters. This fails if the
        // broken form is restored.
        let re = macro_regex();
        assert!(re.is_match("%{foo}").unwrap_or(false));
        assert!(re.is_match("%foo").unwrap_or(false));
        assert!(!re.is_match("plain").unwrap_or(true));
    }

    #[test]
    fn lib_package_regex_matches_lib_names() {
        let re = lib_package_regex();
        assert!(re.is_match("libfoo").unwrap_or(false));
        assert!(re.is_match("lib64").unwrap_or(false));
        assert!(!re.is_match("foo").unwrap_or(true));
    }

    #[test]
    fn shared_regexes_have_no_double_escaping() {
        // Regression: files.rs had \\.so, [\\d-], and \\w (double-escaped
        // in raw strings). The Debug format escapes backslashes, so a correct
        // single-backslash pattern appears as \\ in debug output, while a
        // double-backslash (broken) pattern appears as \\\\. This fails
        // if the broken forms are restored.
        let macro_dbg = format!("{:?}", macro_regex());
        let lib_dbg = format!("{:?}", lib_package_regex());
        assert!(
            !macro_dbg.contains("\\\\"),
            "macro_regex double-escaped: {macro_dbg}"
        );
        assert!(
            !lib_dbg.contains("\\\\"),
            "lib_package_regex double-escaped: {lib_dbg}"
        );
    }

    fn test_config() -> Config {
        // Load the bundled defaults so the check sees the same configuration
        // as the real binary (empty Config::default would leave regexes like
        // MetaPackageRegexp empty, matching everything).
        let defaults: toml::Table = toml::from_str(include_str!("../../data/configdefaults.toml"))
            .expect("parse configdefaults");
        Config {
            configuration: defaults,
            ..Default::default()
        }
    }

    #[test]
    fn ldconfig_p_interpreter_satisfies_check() {
        // #1602: %post -p /sbin/ldconfig with a body that does not call
        // ldconfig must NOT emit postin-without-ldconfig. The fixture RPM has
        // a .so file and scriptlets whose -p interpreter is /sbin/ldconfig.
        // Reverting to the stub scriptprog (or the reference body-only search)
        // makes this fail.
        let rpm = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../tests/parity/pkg/inputs/ldconfig-test-1.0-1.noarch.rpm"
        );
        let dir = std::env::temp_dir().join("rpmcrab-ldconfig-test");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("tmpdir");
        let pkg = Pkg::open(std::path::Path::new(rpm), &dir).expect("open fixture");
        assert_eq!(pkg.scriptprog(librpm::Tag::POSTINPROG), "/sbin/ldconfig");

        let config = test_config();
        let mut out = Filter::new(&config, Color::for_tty(false)).unwrap();
        let mut check = FilesCheck::new(&config);
        check.check(&pkg, &config, &mut out);
        let names: Vec<&str> = out.results().iter().map(|(n, _)| n.as_str()).collect();
        assert!(
            !names.contains(&"postin-without-ldconfig"),
            "unexpected postin-without-ldconfig: {names:?}"
        );
        assert!(
            !names.contains(&"postun-without-ldconfig"),
            "unexpected postun-without-ldconfig: {names:?}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
