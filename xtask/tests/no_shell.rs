//! A grep with teeth: production code must never spawn a shell.
//!
//! `docs/THREAT-MODEL.md` T4 says there is no `sh -c` anywhere in this project
//! and that the privileged backend runs external programs through exactly one
//! resolver. Those are the kind of claims that quietly stop being true, so they
//! are asserted here rather than only written down.
//!
//! Test code is exempt and says so: the suite legitimately writes a shell script
//! to stand in for `resolvconf`, and legitimately spawns `sh` to prove what an
//! empty environment does to program resolution. The exemption is drawn at the
//! `#[cfg(test)]` boundary, which in this codebase is always the last item in a
//! file.

use std::path::{Path, PathBuf};

/// Program names that mean "a shell is about to interpret a string".
const SHELLS: &[&str] = &[
    "sh",
    "bash",
    "zsh",
    "dash",
    "/bin/sh",
    "/bin/bash",
    "/usr/bin/sh",
];

#[test]
fn production_code_never_spawns_a_shell() {
    let mut offences = Vec::new();
    for file in production_sources() {
        let text = production_part(&file);
        for shell in SHELLS {
            let pattern = format!("Command::new(\"{shell}\")");
            if text.contains(&pattern) {
                offences.push(format!("{}: {pattern}", file.display()));
            }
        }
        if text.contains("sh -c") {
            offences.push(format!("{}: the literal `sh -c`", file.display()));
        }
    }
    assert!(
        offences.is_empty(),
        "production code must not reach a shell:\n{}",
        offences.join("\n")
    );
}

#[test]
fn the_privileged_backend_runs_programs_through_one_resolver() {
    // Everything `xraytui-linux-net` executes must go through `program::command`,
    // which clears the environment, sets a fixed PATH, and refuses a program
    // name that is not an absolute path or a bare name on a fixed search path.
    let mut offences = Vec::new();
    for file in sources_under(&repo_root().join("crates/linux-net/src")) {
        if file.file_name().is_some_and(|name| name == "program.rs") {
            continue;
        }
        let text = production_part(&file);
        if text.contains("Command::new(") {
            offences.push(file.display().to_string());
        }
    }
    assert!(
        offences.is_empty(),
        "these files build a Command directly instead of using `program::command`:\n{}",
        offences.join("\n")
    );
}

#[test]
fn the_privileged_binary_forbids_unsafe_code() {
    let main = repo_root().join("bins/xraytui-netd/src/main.rs");
    let text = std::fs::read_to_string(&main).expect("read the helper's entry point");
    assert!(
        text.contains("#![forbid(unsafe_code)]"),
        "the only privileged binary must forbid unsafe code"
    );
}

#[test]
fn unsafe_code_lives_in_exactly_one_module() {
    // `linux-net` needs three ioctls that have no safe wrapper. Everything else
    // in the workspace must stay free of unsafe, and the exemption must stay
    // where it is rather than spreading.
    let mut allowing = Vec::new();
    for file in production_sources() {
        let text = std::fs::read_to_string(&file).unwrap_or_default();
        // Both spellings: the attribute is written across lines where it
        // carries a `reason`.
        if text.contains("allow(\n    unsafe_code") || text.contains("allow(unsafe_code") {
            allowing.push(file);
        }
    }
    assert_eq!(
        allowing.len(),
        1,
        "expected exactly one module to allow unsafe, found {allowing:?}"
    );
    assert!(
        allowing[0].ends_with("crates/linux-net/src/tun.rs"),
        "unsafe moved to {:?}; if that is intended, this test and DECISIONS.md D-012 \
         both need updating",
        allowing[0]
    );
}

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("xtask has a parent directory")
        .to_path_buf()
}

fn production_sources() -> Vec<PathBuf> {
    let root = repo_root();
    let mut files = Vec::new();
    for directory in ["crates", "bins", "xtask"] {
        files.extend(sources_under(&root.join(directory)));
    }
    // Integration tests live outside `src`, and a crate whose unit tests are big
    // enough to warrant their own file puts them in `src/tests.rs` or
    // `src/tests/`. Both are test code and exempt by construction.
    files.retain(|file| {
        file.components().any(|part| part.as_os_str() == "src")
            && !file.components().any(|part| part.as_os_str() == "tests")
            && file.file_name().is_none_or(|name| name != "tests.rs")
    });
    files
}

fn sources_under(directory: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let Ok(entries) = std::fs::read_dir(directory) else {
        return out;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            if path.file_name().is_some_and(|name| name == "target") {
                continue;
            }
            out.extend(sources_under(&path));
        } else if path.extension().is_some_and(|extension| extension == "rs") {
            out.push(path);
        }
    }
    out
}

/// A file's contents up to its test module.
///
/// The cut is made at the **last** `#[cfg(test)]`, not the first: a file may
/// carry a `#[cfg(test)] use` for an import only the tests need, and cutting
/// there would hide most of the file from the checks above.
fn production_part(file: &Path) -> String {
    let text = std::fs::read_to_string(file).unwrap_or_default();
    match test_module_offset(&text) {
        Some(offset) => text[..offset].to_owned(),
        None => text,
    }
}

/// Where the trailing run of test modules begins, if there is one.
///
/// A file may carry several — `mod tests` and `mod prop_tests`, say — and may
/// carry a `#[cfg(test)] use` for an import only the tests need. What matters is
/// the offset of the *first* test module that is followed by nothing but more
/// test modules, because everything before it is code that ships.
fn test_module_offset(text: &str) -> Option<usize> {
    let mut candidate = None;
    let mut search = 0usize;
    let mut offsets = Vec::new();
    while let Some(found) = text[search..].find("#[cfg(test)]") {
        offsets.push(search + found);
        search += found + 1;
    }
    for offset in offsets.into_iter().rev() {
        let tail = text[offset..]
            .trim_start_matches("#[cfg(test)]")
            .trim_start();
        if tail.starts_with("mod ") && tail.contains("test") {
            candidate = Some(offset);
        } else {
            break;
        }
    }
    candidate
}

#[test]
fn the_exemption_boundary_is_where_it_is_believed_to_be() {
    // If a crate ever put shipping code after its test module, the checks above
    // would silently stop looking at it. This asserts the convention that makes
    // the cut safe: everything from the first `#[cfg(test)]` onwards is the test
    // module and nothing else.
    for file in production_sources() {
        let text = std::fs::read_to_string(&file).unwrap_or_default();
        if !text.contains("#[cfg(test)]") {
            continue;
        }
        let Some(offset) = test_module_offset(&text) else {
            panic!(
                "{}: has #[cfg(test)] but no trailing `mod tests`; the checks above \
                 would not know where the shipping code ends",
                file.display()
            );
        };
        let tail = text[offset..].trim_end();
        assert!(
            tail.ends_with('}') || tail.ends_with(';'),
            "{}: the trailing test modules do not close the file; cutting at \
             #[cfg(test)] would leave shipping code unchecked",
            file.display()
        );
    }
}
