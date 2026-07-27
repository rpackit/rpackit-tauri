//! Windows private launch-session acceptance tests.

#![cfg(windows)]

use std::fs;

use rpackit_windows_launcher::{LaunchError, PrivateSession};
use tempfile::tempdir;

#[test]
fn session_files_are_private_exact_and_explicitly_cleaned() -> Result<(), Box<dyn std::error::Error>>
{
    let temporary = tempdir()?;
    let parent = temporary.path().join("parent with spaces");
    fs::create_dir(&parent)?;
    let token = "Abcd_efgh-ijkl.mn~opqrstu012345";
    let session = PrivateSession::create(&parent)?;

    assert!(!session.token_path().exists());
    assert!(!session.control_path().exists());
    session.verify_security()?;
    session.write_token_file(token)?;
    assert_eq!(
        fs::read_to_string(session.token_path())?,
        format!("{token}\n")
    );
    session.verify_security()?;
    assert!(matches!(
        session.write_token_file(token),
        Err(LaunchError::PrivateFileAlreadyExists("token"))
    ));

    session.create_control_file()?;
    assert_eq!(fs::metadata(session.control_path())?.len(), 0);
    session.verify_security()?;
    assert!(matches!(
        session.create_control_file(),
        Err(LaunchError::PrivateFileAlreadyExists("control"))
    ));
    fs::remove_file(session.token_path())?;
    session.verify_security()?;

    let directory = session.directory().to_path_buf();
    session.cleanup()?;
    assert!(!directory.exists());
    assert!(parent.read_dir()?.next().is_none());
    Ok(())
}

#[test]
fn cleanup_never_recursively_removes_an_unexpected_entry() -> Result<(), Box<dyn std::error::Error>>
{
    let temporary = tempdir()?;
    let session = PrivateSession::create(temporary.path())?;
    session.write_token_file("Abcdefghijklmnop")?;
    let unexpected = session.directory().join("unexpected-audit-entry");
    fs::write(&unexpected, b"retain")?;

    assert!(session.cleanup().is_err());
    assert_eq!(fs::read(&unexpected)?, b"retain");
    fs::remove_file(unexpected)?;
    session.cleanup()?;
    Ok(())
}

#[test]
fn invalid_inputs_create_no_session_entries() -> Result<(), Box<dyn std::error::Error>> {
    let temporary = tempdir()?;
    let session = PrivateSession::create(temporary.path())?;
    for token in ["too-short", "contains/slash___", "contains-newline\n"] {
        assert!(matches!(
            session.write_token_file(token),
            Err(LaunchError::InvalidToken)
        ));
    }
    assert!(!session.token_path().exists());
    session.cleanup()?;
    assert!(temporary.path().read_dir()?.next().is_none());
    assert!(matches!(
        PrivateSession::create("relative-parent"),
        Err(LaunchError::InvalidSessionParent)
    ));
    Ok(())
}
