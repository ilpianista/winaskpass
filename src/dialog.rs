use anyhow::{Context, Result};
use std::process::Command;

pub struct PromptResult {
    pub password: String,
    pub save: bool,
}

pub fn prompt_password(key_path: &str) -> Result<Option<PromptResult>> {
    // Use Windows CredUIPromptForWindowsCredentialsW via PowerShell
    // This newer API supports both save checkbox and pre-filled username
    let script = format!(
        r#"
Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
using System.Text;

public class CredUI {{
    [DllImport("credui.dll", CharSet = CharSet.Unicode)]
    public static extern int CredUIPromptForWindowsCredentialsW(
        ref CREDUI_INFO pUiInfo,
        int dwAuthError,
        ref uint pulAuthPackage,
        IntPtr pvInAuthBuffer,
        uint ulInAuthBufferSize,
        out IntPtr ppvOutAuthBuffer,
        out uint pulOutAuthBufferSize,
        ref bool pfSave,
        int dwFlags
    );

    [DllImport("credui.dll", CharSet = CharSet.Unicode)]
    public static extern bool CredPackAuthenticationBufferW(
        int dwFlags,
        string pszUserName,
        string pszPassword,
        IntPtr pPackedCredentials,
        ref int pcbPackedCredentials
    );

    [DllImport("credui.dll", CharSet = CharSet.Unicode)]
    public static extern bool CredUnPackAuthenticationBufferW(
        int dwFlags,
        IntPtr pAuthBuffer,
        uint cbAuthBuffer,
        StringBuilder pszUserName,
        ref int pcchMaxUserName,
        StringBuilder pszDomainName,
        ref int pcchMaxDomainName,
        StringBuilder pszPassword,
        ref int pcchMaxPassword
    );

    [DllImport("ole32.dll")]
    public static extern void CoTaskMemFree(IntPtr pv);

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct CREDUI_INFO {{
        public int cbSize;
        public IntPtr hwndParent;
        public string pszMessageText;
        public string pszCaptionText;
        public IntPtr hbmBanner;
    }}

    public const int CREDUIWIN_GENERIC = 0x1;
    public const int CREDUIWIN_CHECKBOX = 0x2;
    public const int CREDUIWIN_IN_CRED_ONLY = 0x20;
    public const int ERROR_CANCELLED = 1223;

    public static string Prompt(string caption, string message, string username, ref bool save) {{
        CREDUI_INFO info = new CREDUI_INFO();
        info.cbSize = Marshal.SizeOf(info);
        info.pszCaptionText = caption;
        info.pszMessageText = message;

        // Pack initial credentials (username only, empty password)
        int inBufferSize = 0;
        CredPackAuthenticationBufferW(0, username, "", IntPtr.Zero, ref inBufferSize);
        IntPtr inBuffer = Marshal.AllocHGlobal(inBufferSize);
        try {{
            if (!CredPackAuthenticationBufferW(0, username, "", inBuffer, ref inBufferSize)) {{
                throw new Exception("CredPackAuthenticationBufferW failed: " + Marshal.GetLastWin32Error());
            }}

            uint authPackage = 0;
            IntPtr outBuffer;
            uint outBufferSize;

            int flags = CREDUIWIN_GENERIC | CREDUIWIN_CHECKBOX | CREDUIWIN_IN_CRED_ONLY;

            int result = CredUIPromptForWindowsCredentialsW(
                ref info,
                0,
                ref authPackage,
                inBuffer,
                (uint)inBufferSize,
                out outBuffer,
                out outBufferSize,
                ref save,
                flags
            );

            if (result == ERROR_CANCELLED) {{
                return null;
            }} else if (result != 0) {{
                throw new Exception("CredUIPromptForWindowsCredentialsW error: " + result);
            }}

            try {{
                // Unpack the result
                StringBuilder user = new StringBuilder(256);
                StringBuilder domain = new StringBuilder(256);
                StringBuilder pass = new StringBuilder(256);
                int userLen = 256, domainLen = 256, passLen = 256;

                if (!CredUnPackAuthenticationBufferW(0, outBuffer, outBufferSize,
                    user, ref userLen, domain, ref domainLen, pass, ref passLen)) {{
                    throw new Exception("CredUnPackAuthenticationBufferW failed: " + Marshal.GetLastWin32Error());
                }}

                return pass.ToString();
            }} finally {{
                CoTaskMemFree(outBuffer);
            }}
        }} finally {{
            Marshal.FreeHGlobal(inBuffer);
        }}
    }}
}}
"@

$save = $false
$password = [CredUI]::Prompt("SSH Key Passphrase", "Enter passphrase for:`n{key_path}", "{username}", [ref]$save)
if ($password -ne $null) {{
    # Output format: SAVE|password or NOSAVE|password
    if ($save) {{
        "SAVE|" + $password
    }} else {{
        "NOSAVE|" + $password
    }}
}}
"#,
        key_path = key_path.replace("`", "``").replace("'", "''"),
        username = ""
    );

    let output = Command::new("powershell.exe")
        .args(["-NoProfile", "-Command", &script])
        .output()
        .context("Failed to execute PowerShell")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        // Check if user cancelled
        if stderr.contains("1223") || output.stdout.is_empty() {
            return Ok(None);
        }
        anyhow::bail!("PowerShell error: {}", stderr);
    }

    let result = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if result.is_empty() {
        return Ok(None);
    }

    if let Some(password) = result.strip_prefix("SAVE|") {
        Ok(Some(PromptResult {
            password: password.to_string(),
            save: true,
        }))
    } else if let Some(password) = result.strip_prefix("NOSAVE|") {
        Ok(Some(PromptResult {
            password: password.to_string(),
            save: false,
        }))
    } else {
        // Fallback: assume no save
        Ok(Some(PromptResult {
            password: result,
            save: false,
        }))
    }
}
