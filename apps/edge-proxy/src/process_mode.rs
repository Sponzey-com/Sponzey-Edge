use edge_domain::{AppError, ErrorCode};
use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackupCreateOptions {
    pub data_dir: PathBuf,
    pub output: PathBuf,
    pub passphrase_file: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackupVerifyOptions {
    pub input: PathBuf,
    pub passphrase_file: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RestoreOptions {
    pub input: PathBuf,
    pub target_data_dir: PathBuf,
    pub passphrase_file: PathBuf,
    pub replace: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RestoreRecoverOptions {
    pub target_data_dir: PathBuf,
    pub operation_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditVerifyOptions {
    pub data_dir: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProcessMode {
    Serve,
    BackupCreate(BackupCreateOptions),
    BackupVerify(BackupVerifyOptions),
    Restore(RestoreOptions),
    RestoreRecover(RestoreRecoverOptions),
    AuditVerify(AuditVerifyOptions),
}

pub fn parse_process_mode(args: &[String]) -> Result<ProcessMode, AppError> {
    match args {
        [] => Ok(ProcessMode::Serve),
        [command] if command == "serve" => Ok(ProcessMode::Serve),
        [backup, operation, options @ ..] if backup == "backup" => {
            parse_backup_mode(operation, options)
        }
        [audit, operation, options @ ..] if audit == "audit" && operation == "verify" => {
            let parsed = parse_options(options, &["--data-dir"], &[])?;
            Ok(ProcessMode::AuditVerify(AuditVerifyOptions {
                data_dir: required_path(&parsed.values, "--data-dir")?,
            }))
        }
        _ => Err(invalid_command()),
    }
}

fn parse_backup_mode(operation: &str, tokens: &[String]) -> Result<ProcessMode, AppError> {
    match operation {
        "create" => {
            let parsed = parse_options(
                tokens,
                &["--data-dir", "--output", "--passphrase-file"],
                &[],
            )?;
            Ok(ProcessMode::BackupCreate(BackupCreateOptions {
                data_dir: required_path(&parsed.values, "--data-dir")?,
                output: required_path(&parsed.values, "--output")?,
                passphrase_file: required_path(&parsed.values, "--passphrase-file")?,
            }))
        }
        "verify" => {
            let parsed = parse_options(tokens, &["--input", "--passphrase-file"], &[])?;
            Ok(ProcessMode::BackupVerify(BackupVerifyOptions {
                input: required_path(&parsed.values, "--input")?,
                passphrase_file: required_path(&parsed.values, "--passphrase-file")?,
            }))
        }
        "restore" => {
            let parsed = parse_options(
                tokens,
                &["--input", "--target-data-dir", "--passphrase-file"],
                &["--replace"],
            )?;
            Ok(ProcessMode::Restore(RestoreOptions {
                input: required_path(&parsed.values, "--input")?,
                target_data_dir: required_path(&parsed.values, "--target-data-dir")?,
                passphrase_file: required_path(&parsed.values, "--passphrase-file")?,
                replace: parsed.flags.contains("--replace"),
            }))
        }
        "restore-recover" => {
            let parsed = parse_options(tokens, &["--target-data-dir", "--operation-id"], &[])?;
            Ok(ProcessMode::RestoreRecover(RestoreRecoverOptions {
                target_data_dir: required_path(&parsed.values, "--target-data-dir")?,
                operation_id: required_value(&parsed.values, "--operation-id")?.to_string(),
            }))
        }
        _ => Err(invalid_command()),
    }
}

struct ParsedOptions {
    values: BTreeMap<String, String>,
    flags: BTreeSet<String>,
}

fn parse_options(
    tokens: &[String],
    value_names: &[&str],
    flag_names: &[&str],
) -> Result<ParsedOptions, AppError> {
    let mut values = BTreeMap::new();
    let mut flags = BTreeSet::new();
    let mut index = 0;
    while index < tokens.len() {
        let name = tokens[index].as_str();
        if flag_names.contains(&name) {
            if !flags.insert(name.to_string()) {
                return Err(invalid_command());
            }
            index += 1;
            continue;
        }
        if !value_names.contains(&name) || index + 1 >= tokens.len() {
            return Err(invalid_command());
        }
        let value = &tokens[index + 1];
        if value.is_empty() || value.starts_with("--") {
            return Err(invalid_command());
        }
        if values.insert(name.to_string(), value.clone()).is_some() {
            return Err(invalid_command());
        }
        index += 2;
    }
    Ok(ParsedOptions { values, flags })
}

fn required_path(values: &BTreeMap<String, String>, name: &str) -> Result<PathBuf, AppError> {
    Ok(PathBuf::from(required_value(values, name)?))
}

fn required_value<'a>(
    values: &'a BTreeMap<String, String>,
    name: &str,
) -> Result<&'a str, AppError> {
    values
        .get(name)
        .map(String::as_str)
        .ok_or_else(invalid_command)
}

fn invalid_command() -> AppError {
    AppError::new(
        ErrorCode::ProcessCommandInvalid,
        "process command does not match the supported contract",
    )
}

#[cfg(test)]
mod tests {
    use super::{
        parse_process_mode, AuditVerifyOptions, BackupCreateOptions, BackupVerifyOptions,
        ProcessMode, RestoreOptions, RestoreRecoverOptions,
    };
    use edge_domain::ErrorCode;
    use std::path::PathBuf;

    fn args(values: &[&str]) -> Vec<String> {
        values.iter().map(|value| (*value).to_string()).collect()
    }

    #[test]
    fn no_args_and_explicit_serve_select_serve_mode() {
        assert_eq!(parse_process_mode(&[]).unwrap(), ProcessMode::Serve);
        assert_eq!(
            parse_process_mode(&args(&["serve"])).unwrap(),
            ProcessMode::Serve
        );
    }

    #[test]
    fn backup_create_and_restore_options_are_typed() {
        assert_eq!(
            parse_process_mode(&args(&[
                "backup",
                "create",
                "--data-dir",
                "/data",
                "--output",
                "/backup/edge.age",
                "--passphrase-file",
                "/run/secret"
            ]))
            .unwrap(),
            ProcessMode::BackupCreate(BackupCreateOptions {
                data_dir: PathBuf::from("/data"),
                output: PathBuf::from("/backup/edge.age"),
                passphrase_file: PathBuf::from("/run/secret"),
            })
        );
        assert_eq!(
            parse_process_mode(&args(&[
                "backup",
                "restore",
                "--input",
                "/backup/edge.age",
                "--target-data-dir",
                "/restored",
                "--passphrase-file",
                "/run/secret",
                "--replace"
            ]))
            .unwrap(),
            ProcessMode::Restore(RestoreOptions {
                input: PathBuf::from("/backup/edge.age"),
                target_data_dir: PathBuf::from("/restored"),
                passphrase_file: PathBuf::from("/run/secret"),
                replace: true,
            })
        );
    }

    #[test]
    fn unknown_command_and_missing_option_fail_without_serve_fallback() {
        let unknown = parse_process_mode(&args(&["unknown"])).unwrap_err();
        assert_eq!(unknown.code, ErrorCode::ProcessCommandInvalid);

        let incomplete =
            parse_process_mode(&args(&["backup", "create", "--data-dir", "/data"])).unwrap_err();
        assert_eq!(incomplete.code, ErrorCode::ProcessCommandInvalid);
    }

    #[test]
    fn audit_verify_requires_an_explicit_data_directory() {
        assert_eq!(
            parse_process_mode(&args(&["audit", "verify", "--data-dir", "/data"])).unwrap(),
            ProcessMode::AuditVerify(AuditVerifyOptions {
                data_dir: PathBuf::from("/data"),
            })
        );
        assert_eq!(
            parse_process_mode(&args(&["audit", "verify"]))
                .unwrap_err()
                .code,
            ErrorCode::ProcessCommandInvalid
        );
    }

    #[test]
    fn backup_verify_and_recover_options_are_typed_without_hidden_defaults() {
        assert_eq!(
            parse_process_mode(&args(&[
                "backup",
                "verify",
                "--input",
                "/backup/edge.age",
                "--passphrase-file",
                "/run/secret"
            ]))
            .unwrap(),
            ProcessMode::BackupVerify(BackupVerifyOptions {
                input: PathBuf::from("/backup/edge.age"),
                passphrase_file: PathBuf::from("/run/secret"),
            })
        );
        assert_eq!(
            parse_process_mode(&args(&[
                "backup",
                "restore-recover",
                "--target-data-dir",
                "/restored",
                "--operation-id",
                "restore-001"
            ]))
            .unwrap(),
            ProcessMode::RestoreRecover(RestoreRecoverOptions {
                target_data_dir: PathBuf::from("/restored"),
                operation_id: "restore-001".to_string(),
            })
        );
    }
}
