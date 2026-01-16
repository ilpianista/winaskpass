use anyhow::Result;
use std::ptr;
use windows::Win32::Foundation::{ERROR_CANCELLED, HWND};
use windows::Win32::Security::Credentials::{
    CRED_PACK_FLAGS, CREDUI_INFOW, CREDUIWIN_CHECKBOX, CREDUIWIN_FLAGS, CREDUIWIN_GENERIC,
    CREDUIWIN_IN_CRED_ONLY, CredPackAuthenticationBufferW, CredUIPromptForWindowsCredentialsW,
    CredUnPackAuthenticationBufferW,
};
use windows::Win32::System::Com::CoTaskMemFree;
use windows::Win32::UI::WindowsAndMessaging::{
    IDCANCEL, IDNO, IDYES, MB_ICONWARNING, MB_YESNOCANCEL, MESSAGEBOX_STYLE, MessageBoxW,
};
use windows::core::{PCWSTR, PWSTR};

pub struct PromptResult {
    pub password: String,
    pub save: bool,
}

/// Shows a confirmation dialog with Yes/No/Cancel buttons.
/// Returns Some("yes"), Some("no"), or None if cancelled.
pub fn prompt_confirmation(prompt: &str) -> Result<Option<String>> {
    let prompt_wide: Vec<u16> = prompt.encode_utf16().chain(std::iter::once(0)).collect();
    let title_wide: Vec<u16> = "SSH Host Verification"
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();

    unsafe {
        let result = MessageBoxW(
            None,
            PCWSTR(prompt_wide.as_ptr()),
            PCWSTR(title_wide.as_ptr()),
            MESSAGEBOX_STYLE(MB_YESNOCANCEL.0 | MB_ICONWARNING.0),
        );

        match result {
            IDYES => Ok(Some("yes".to_string())),
            IDNO => Ok(Some("no".to_string())),
            IDCANCEL => Ok(None),
            _ => Ok(None),
        }
    }
}

pub fn prompt_password(prompt: &str, show_save_checkbox: bool) -> Result<Option<PromptResult>> {
    let caption = "SSH Key Passphrase";
    let caption_wide: Vec<u16> = caption.encode_utf16().chain(std::iter::once(0)).collect();
    let prompt_wide: Vec<u16> = prompt.encode_utf16().chain(std::iter::once(0)).collect();

    unsafe {
        let ui_info = CREDUI_INFOW {
            cbSize: std::mem::size_of::<CREDUI_INFOW>() as u32,
            hwndParent: HWND::default(),
            pszMessageText: PCWSTR(prompt_wide.as_ptr()),
            pszCaptionText: PCWSTR(caption_wide.as_ptr()),
            hbmBanner: Default::default(),
        };

        // Pack initial credentials (empty username and password)
        let username_wide: Vec<u16> = vec![0];
        let password_wide: Vec<u16> = vec![0];

        let mut in_buffer_size: u32 = 0;
        let _ = CredPackAuthenticationBufferW(
            CRED_PACK_FLAGS(0),
            PWSTR(username_wide.as_ptr() as *mut u16),
            PWSTR(password_wide.as_ptr() as *mut u16),
            None,
            &mut in_buffer_size,
        );

        let mut in_buffer = vec![0u8; in_buffer_size as usize];
        let pack_result = CredPackAuthenticationBufferW(
            CRED_PACK_FLAGS(0),
            PWSTR(username_wide.as_ptr() as *mut u16),
            PWSTR(password_wide.as_ptr() as *mut u16),
            Some(in_buffer.as_mut_ptr()),
            &mut in_buffer_size,
        );

        if pack_result.is_err() {
            return Err(anyhow::anyhow!("Failed to pack authentication buffer"));
        }

        let mut auth_package: u32 = 0;
        let mut out_buffer: *mut std::ffi::c_void = ptr::null_mut();
        let mut out_buffer_size: u32 = 0;
        let mut save = false.into();

        let mut flags = CREDUIWIN_GENERIC.0 | CREDUIWIN_IN_CRED_ONLY.0;
        if show_save_checkbox {
            flags |= CREDUIWIN_CHECKBOX.0;
        }

        let result = CredUIPromptForWindowsCredentialsW(
            Some(&ui_info),
            0,
            &mut auth_package,
            Some(in_buffer.as_ptr() as *const std::ffi::c_void),
            in_buffer_size,
            &mut out_buffer,
            &mut out_buffer_size,
            Some(&mut save),
            CREDUIWIN_FLAGS(flags),
        );

        if result != 0 {
            if result == ERROR_CANCELLED.0 {
                return Ok(None);
            }
            return Err(anyhow::anyhow!(
                "CredUIPromptForWindowsCredentialsW failed with error code: {}",
                result
            ));
        }

        // Unpack the result
        let mut user_buf = vec![0u16; 256];
        let mut user_len: u32 = user_buf.len() as u32;
        let mut domain_buf = vec![0u16; 256];
        let mut domain_len: u32 = domain_buf.len() as u32;
        let mut pass_buf = vec![0u16; 256];
        let mut pass_len: u32 = pass_buf.len() as u32;

        let unpack_result = CredUnPackAuthenticationBufferW(
            CRED_PACK_FLAGS(0),
            out_buffer as *const _,
            out_buffer_size,
            Some(PWSTR(user_buf.as_mut_ptr())),
            &mut user_len,
            Some(PWSTR(domain_buf.as_mut_ptr())),
            Some(&mut domain_len),
            Some(PWSTR(pass_buf.as_mut_ptr())),
            &mut pass_len,
        );

        CoTaskMemFree(Some(out_buffer as *const _));

        if unpack_result.is_err() {
            return Err(anyhow::anyhow!("Failed to unpack authentication buffer"));
        }

        // Extract password from buffer
        let password = String::from_utf16_lossy(&pass_buf[..pass_len.saturating_sub(1) as usize]);

        Ok(Some(PromptResult {
            password,
            save: save.as_bool(),
        }))
    }
}
