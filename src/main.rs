mod credential;
mod dialog;

use anyhow::Result;
use std::env;

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
    let key_path = extract_key_path(prompt);

    // Try to get cached credential
    if let Some(path) = key_path
        && let Some(password) = credential::get_credential(path)? {
            print!("{}", password);
            return Ok(());
        }

    // Prompt user for password
    // Only show save checkbox if we have a key path to save against
    match dialog::prompt_password(prompt, key_path.is_some())? {
        Some(result) => {
            if result.save
                && let Some(path) = key_path
                    && let Err(e) = credential::store_credential(path, &result.password) {
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
    eprintln!(
        r#"winaskpass - ssh-add helper for WSL with Windows Credential Manager

USAGE:
    winaskpass <prompt>           SSH_ASKPASS mode: respond to ssh-add prompt
    winaskpass --list             List stored SSH credentials
    winaskpass --help             Show this help

SETUP:
    Add to your ~/.bashrc or ~/.zshrc:
        export SSH_ASKPASS=winaskpass
        export SSH_ASKPASS_REQUIRE=prefer

    Then use ssh-add normally:
        ssh-add </dev/null

    The passphrase will be cached in Windows Credential Manager.
"#
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

    #[test]
    fn test_extract_key_path_with_quotes() {
        let prompt = "Enter passphrase for key '/home/user/.ssh/id_rsa': ";
        assert_eq!(extract_key_path(prompt), Some("/home/user/.ssh/id_rsa"));
    }

    #[test]
    fn test_extract_key_path_without_quotes() {
        let prompt = "Enter passphrase for /home/user/.ssh/id_ed25519: ";
        assert_eq!(extract_key_path(prompt), Some("/home/user/.ssh/id_ed25519"));
    }

    #[test]
    fn test_extract_key_path_with_spaces() {
        let prompt = "Enter passphrase for '/home/user/my keys/id_rsa': ";
        assert_eq!(extract_key_path(prompt), Some("/home/user/my keys/id_rsa"));
    }
}
