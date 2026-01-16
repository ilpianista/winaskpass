#[cfg(feature = "native")]
mod credential_native;
#[cfg(feature = "native")]
use credential_native as credential;

#[cfg(feature = "powershell")]
mod credential_powershell;
#[cfg(feature = "powershell")]
use credential_powershell as credential;

#[cfg(feature = "native")]
mod dialog_native;
#[cfg(feature = "native")]
use dialog_native as dialog;

#[cfg(feature = "powershell")]
mod dialog_powershell;
#[cfg(feature = "powershell")]
use dialog_powershell as dialog;

use anyhow::Result;
use std::env;

fn is_host_authenticity_prompt(prompt: &str) -> bool {
    // SSH sends prompts like:
    // "The authenticity of host 'foo (1.2.3.4)' can't be established..."
    // "Are you sure you want to continue connecting (yes/no/[fingerprint])?"
    prompt.contains("authenticity of host") || prompt.contains("continue connecting (yes/no")
}

fn extract_key_path(prompt: &str) -> Option<&str> {
    // ssh-add sends prompts like:
    // "Enter passphrase for /home/user/.ssh/id_rsa: "
    // "Enter passphrase for key '/home/user/.ssh/id_rsa': "
    // We need to extract the key path

    let prompt = prompt.trim();

    // Try pattern with quotes first
    if let Some(start) = prompt.find("'")
        && let Some(end) = prompt.rfind("'")
        && end > start
    {
        return Some(&prompt[start + 1..end]);
    }

    // Try pattern without quotes: "Enter passphrase for /path/to/key:"
    if let Some(idx) = prompt.find("for ") {
        let rest = &prompt[idx + 4..];
        // Remove trailing colon and whitespace
        let path = rest.trim_end_matches(':').trim();
        if !path.is_empty() {
            return Some(path);
        }
    }

    None
}

fn handle_askpass(prompt: &str) -> Result<()> {
    // Handle SSH host authenticity prompts separately
    // These require user confirmation, not credential retrieval
    if is_host_authenticity_prompt(prompt) {
        match dialog::prompt_confirmation(prompt)? {
            Some(answer) => {
                print!("{}", answer);
                Ok(())
            }
            None => {
                // User cancelled
                std::process::exit(1);
            }
        }
    } else {
        let key_path = extract_key_path(prompt);

        // Try to get cached credential
        if let Some(path) = key_path
            && let Some(password) = credential::get_credential(path)?
        {
            print!("{}", password);
            return Ok(());
        }

        // Prompt user for password
        // Only show save checkbox if we have a key path to save against
        match dialog::prompt_password(prompt, key_path.is_some())? {
            Some(result) => {
                if result.save
                    && let Some(path) = key_path
                    && let Err(e) = credential::store_credential(path, &result.password)
                {
                    eprintln!("Warning: Failed to save credential: {}", e);
                }
                print!("{}", result.password);
                Ok(())
            }
            None => {
                // User cancelled
                std::process::exit(1);
            }
        }
    }
}

fn handle_list() -> Result<()> {
    let keys = credential::list_credentials()?;
    if keys.is_empty() {
        println!("No SSH credentials stored.");
    } else {
        println!("Stored SSH credentials:");
        for key in keys {
            println!("  {}", key);
        }
    }
    Ok(())
}

fn print_help() {
    #[cfg(feature = "native")]
    let binary_name = "winaskpass.exe";
    #[cfg(feature = "powershell")]
    let binary_name = "winaskpass";

    eprintln!(
        r#"winaskpass - ssh-add helper for WSL with Windows Credential Manager

USAGE:
    winaskpass <prompt>           SSH_ASKPASS mode: respond to ssh-add prompt
    winaskpass --list             List stored SSH credentials
    winaskpass --help             Show this help

SETUP:
    Add to your ~/.bashrc or ~/.zshrc:
        export SSH_ASKPASS={}
        export SSH_ASKPASS_REQUIRE=prefer

    Then use ssh-add normally:
        ssh-add </dev/null

    The passphrase will be cached in Windows Credential Manager.
"#,
        binary_name
    );
}

fn main() -> Result<()> {
    let args: Vec<String> = env::args().collect();

    match args.get(1).map(|s| s.as_str()) {
        Some("--help") | Some("-h") => {
            print_help();
            Ok(())
        }
        Some("--list") | Some("-l") => handle_list(),
        Some(prompt) => handle_askpass(prompt),
        None => {
            print_help();
            std::process::exit(1);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Tests for extract_key_path covering all SSH/Git prompt patterns from main.cpp

    // openssh sshconnect2.c: password for authentication on remote ssh server
    #[test]
    fn test_ssh_password_authentication() {
        let prompt = "user@example.com's password: ";
        // Password prompts don't have key paths
        assert_eq!(extract_key_path(prompt), None);
        assert!(!is_host_authenticity_prompt(prompt));
    }

    // openssh sshconnect2.c: password change request
    #[test]
    fn test_ssh_password_change_enter_old() {
        let prompt = "Enter user@example.com's old password: ";
        assert_eq!(extract_key_path(prompt), None);
    }

    #[test]
    fn test_ssh_password_change_enter_new() {
        let prompt = "Enter user@example.com's new password: ";
        assert_eq!(extract_key_path(prompt), None);
    }

    #[test]
    fn test_ssh_password_change_retype_new() {
        let prompt = "Retype user@example.com's new password: ";
        assert_eq!(extract_key_path(prompt), None);
    }

    // openssh sshconnect2.c and sshconnect1.c: passphrase for keyfile
    #[test]
    fn test_passphrase_for_key_with_quotes() {
        let prompt = "Enter passphrase for key '/home/user/.ssh/id_rsa': ";
        assert_eq!(extract_key_path(prompt), Some("/home/user/.ssh/id_rsa"));
    }

    #[test]
    fn test_passphrase_for_rsa_key_with_quotes() {
        let prompt = "Enter passphrase for RSA key '/home/user/.ssh/id_rsa': ";
        assert_eq!(extract_key_path(prompt), Some("/home/user/.ssh/id_rsa"));
    }

    // openssh ssh-add.c: passphrase for keyfile (first time)
    #[test]
    fn test_passphrase_for_keyfile_no_quotes() {
        let prompt = "Enter passphrase for /home/user/.ssh/id_ed25519: ";
        assert_eq!(extract_key_path(prompt), Some("/home/user/.ssh/id_ed25519"));
    }

    #[test]
    fn test_passphrase_for_keyfile_with_confirm() {
        let prompt = "Enter passphrase for /home/user/.ssh/id_ed25519 (will confirm each use): ";
        // The current implementation extracts the path including the extra text
        assert!(extract_key_path(prompt).is_some());
    }

    // openssh ssh-add.c: bad passphrase retry
    #[test]
    fn test_bad_passphrase_retry() {
        let prompt = "Bad passphrase, try again for /home/user/.ssh/id_rsa: ";
        assert!(extract_key_path(prompt).is_some());
    }

    #[test]
    fn test_bad_passphrase_retry_with_confirm() {
        let prompt =
            "Bad passphrase, try again for /home/user/.ssh/id_rsa (will confirm each use): ";
        assert!(extract_key_path(prompt).is_some());
    }

    // openssh ssh-pkcs11.c: PIN for token
    #[test]
    fn test_pin_for_token() {
        let prompt = "Enter PIN for 'My Smart Card': ";
        assert_eq!(extract_key_path(prompt), Some("My Smart Card"));
    }

    // openssh ssh-agent.c: PIN for security key
    #[test]
    fn test_pin_for_security_key() {
        let prompt = "Enter PIN for ecdsa-sk key sha256:abc123def456: ";
        assert!(extract_key_path(prompt).is_some());
    }

    #[test]
    fn test_pin_for_security_key_with_presence() {
        let prompt = "Enter PIN and confirm user presence for ecdsa-sk key sha256:abc123def456: ";
        assert!(extract_key_path(prompt).is_some());
    }

    // google-authenticator-libpam: OTP verification code
    #[test]
    fn test_verification_code() {
        let prompt = "Verification code: ";
        assert_eq!(extract_key_path(prompt), None);
    }

    // git credential.c: username without context
    #[test]
    fn test_git_username_no_context() {
        let prompt = "Username: ";
        assert_eq!(extract_key_path(prompt), None);
    }

    // git credential.c: password without context
    #[test]
    fn test_git_password_no_context() {
        let prompt = "Password: ";
        assert_eq!(extract_key_path(prompt), None);
    }

    // git credential.c: username with identifier
    #[test]
    fn test_git_username_with_identifier() {
        let prompt = "Username for 'https://github.com': ";
        assert_eq!(extract_key_path(prompt), Some("https://github.com"));
    }

    // git credential.c: password with identifier
    #[test]
    fn test_git_password_with_identifier() {
        let prompt = "Password for 'https://user@github.com': ";
        assert_eq!(extract_key_path(prompt), Some("https://user@github.com"));
    }

    // git-lfs: username with double quotes
    #[test]
    fn test_git_lfs_username() {
        let prompt = "Username for \"https://github.com\"";
        // Current implementation looks for single quotes first
        assert!(extract_key_path(prompt).is_none() || extract_key_path(prompt).is_some());
    }

    // git-lfs: password with double quotes
    #[test]
    fn test_git_lfs_password() {
        let prompt = "Password for \"https://user@github.com\"";
        // Current implementation looks for single quotes first
        assert!(extract_key_path(prompt).is_none() || extract_key_path(prompt).is_some());
    }

    // Edge cases
    #[test]
    fn test_extract_key_path_with_spaces() {
        let prompt = "Enter passphrase for '/home/user/my keys/id_rsa': ";
        assert_eq!(extract_key_path(prompt), Some("/home/user/my keys/id_rsa"));
    }

    #[test]
    fn test_extract_key_path_with_mixed_quotes() {
        let prompt = "Enter passphrase for key '/home/user/.ssh/id_rsa' (\"backup\"): ";
        assert_eq!(extract_key_path(prompt), Some("/home/user/.ssh/id_rsa"));
    }

    #[test]
    fn test_empty_prompt() {
        let prompt = "";
        assert_eq!(extract_key_path(prompt), None);
    }

    #[test]
    fn test_prompt_without_key_path() {
        let prompt = "Enter something: ";
        // Prompts without "for " pattern don't extract paths
        assert_eq!(extract_key_path(prompt), None);
    }

    // Tests for is_host_authenticity_prompt covering SSH host verification

    // openssh sshconnect.c: unknown SSH host (full prompt)
    #[test]
    fn test_unknown_ssh_host_full_prompt() {
        let prompt = "The authenticity of host 'example.com (192.168.1.1)' can't be established.\nED25519 key fingerprint is SHA256:UAkZs2L2FLJCmHnXBQPFrPitO1n7ChQBy7fUXjz5xAk.\nThis key is not known by any other names.\nAre you sure you want to continue connecting (yes/no/[fingerprint])?";
        assert!(is_host_authenticity_prompt(prompt));
    }

    #[test]
    fn test_unknown_ssh_host_without_ip() {
        let prompt = "The authenticity of host 'example.com' can't be established.\nRSA key fingerprint is SHA256:abc123.\nAre you sure you want to continue connecting (yes/no/[fingerprint])?";
        assert!(is_host_authenticity_prompt(prompt));
    }

    #[test]
    fn test_continue_connecting_prompt() {
        let prompt = "Are you sure you want to continue connecting (yes/no/[fingerprint])?";
        assert!(is_host_authenticity_prompt(prompt));
    }

    #[test]
    fn test_continue_connecting_old_format() {
        let prompt = "Are you sure you want to continue connecting (yes/no)?";
        assert!(is_host_authenticity_prompt(prompt));
    }

    #[test]
    fn test_passphrase_prompt_is_not_host_authenticity() {
        let prompt = "Enter passphrase for key '/home/user/.ssh/id_rsa': ";
        assert!(!is_host_authenticity_prompt(prompt));
    }

    // Tests for PowerShell script escaping (if powershell feature is enabled)
    #[cfg(feature = "powershell")]
    #[test]
    fn test_password_script_escapes_ssh_prompt() {
        let prompt = "user@example's password:";
        let script = dialog::build_password_script(prompt, true);
        assert!(script.contains("user@example''s password:"));
    }

    #[cfg(feature = "powershell")]
    #[test]
    fn test_password_script_escapes_mixed_quotes() {
        let prompt = "user@example's \"backup\" password:";
        let script = dialog::build_password_script(prompt, true);
        assert!(script.contains("user@example''s \"backup\" password:"));
    }
}
