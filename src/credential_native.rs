use anyhow::Result;
use std::ptr;
use windows::core::PWSTR;
use windows::Win32::Security::Credentials::{
    CredEnumerateW, CredFree, CredReadW, CredWriteW, CREDENTIALW, CRED_FLAGS,
    CRED_PERSIST_LOCAL_MACHINE, CRED_TYPE_GENERIC,
};

const CREDENTIAL_PREFIX: &str = "winaskpass:";

const ERROR_NOT_FOUND: u32 = 0x80070490;

fn target_name(key_path: &str) -> String {
    format!("{}{}", CREDENTIAL_PREFIX, key_path)
}

pub fn get_credential(key_path: &str) -> Result<Option<String>> {
    let target = target_name(key_path);
    let target_wide: Vec<u16> = target.encode_utf16().chain(std::iter::once(0)).collect();

    unsafe {
        let mut credential_ptr: *mut CREDENTIALW = ptr::null_mut();
        let result = CredReadW(
            PWSTR(target_wide.as_ptr() as *mut u16),
            CRED_TYPE_GENERIC,
            Some(0),
            &mut credential_ptr,
        );

        match result {
            Ok(_) => {
                if credential_ptr.is_null() {
                    return Ok(None);
                }

                let credential = &*credential_ptr;
                let password = if credential.CredentialBlob.is_null()
                    || credential.CredentialBlobSize == 0
                {
                    None
                } else {
                    // Password is stored as Unicode (UTF-16)
                    let slice = std::slice::from_raw_parts(
                        credential.CredentialBlob as *const u16,
                        credential.CredentialBlobSize as usize / 2,
                    );
                    Some(String::from_utf16_lossy(slice))
                };

                CredFree(credential_ptr as *const _);
                Ok(password)
            }
            Err(e) => {
                if e.code().0 as u32 == ERROR_NOT_FOUND {
                    Ok(None)
                } else {
                    Err(anyhow::anyhow!("Failed to read credential: {}", e))
                }
            }
        }
    }
}

pub fn store_credential(key_path: &str, passphrase: &str) -> Result<()> {
    let target = target_name(key_path);
    let target_wide: Vec<u16> = target.encode_utf16().chain(std::iter::once(0)).collect();
    let username_wide: Vec<u16> = vec![0]; // Empty username
    let password_bytes: Vec<u16> = passphrase.encode_utf16().collect();

    unsafe {
        let mut credential = CREDENTIALW {
            Flags: CRED_FLAGS(0),
            Type: CRED_TYPE_GENERIC,
            TargetName: PWSTR(target_wide.as_ptr() as *mut u16),
            Comment: PWSTR::null(),
            LastWritten: Default::default(),
            CredentialBlobSize: (password_bytes.len() * 2) as u32,
            CredentialBlob: password_bytes.as_ptr() as *mut u8,
            Persist: CRED_PERSIST_LOCAL_MACHINE,
            AttributeCount: 0,
            Attributes: ptr::null_mut(),
            TargetAlias: PWSTR::null(),
            UserName: PWSTR(username_wide.as_ptr() as *mut u16),
        };

        CredWriteW(&mut credential, 0)?;
    }

    Ok(())
}

pub fn list_credentials() -> Result<Vec<String>> {
    let filter: Vec<u16> = format!("{}*", CREDENTIAL_PREFIX)
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();

    unsafe {
        let mut count: u32 = 0;
        let mut credentials_ptr: *mut *mut CREDENTIALW = ptr::null_mut();

        let result = CredEnumerateW(
            PWSTR(filter.as_ptr() as *mut u16),
            None,
            &mut count,
            &mut credentials_ptr,
        );

        match result {
            Ok(_) => {
                let mut results = Vec::new();

                if !credentials_ptr.is_null() {
                    let credentials_slice =
                        std::slice::from_raw_parts(credentials_ptr, count as usize);

                    for &cred_ptr in credentials_slice {
                        if !cred_ptr.is_null() {
                            let cred = &*cred_ptr;
                            if !cred.TargetName.is_null() {
                                let target_name = cred.TargetName.to_string()?;
                                if let Some(key_path) = target_name.strip_prefix(CREDENTIAL_PREFIX)
                                {
                                    results.push(key_path.to_string());
                                }
                            }
                        }
                    }

                    CredFree(credentials_ptr as *const _);
                }

                Ok(results)
            }
            Err(e) => {
                if e.code().0 as u32 == ERROR_NOT_FOUND {
                    Ok(Vec::new())
                } else {
                    Err(anyhow::anyhow!("Failed to enumerate credentials: {}", e))
                }
            }
        }
    }
}
