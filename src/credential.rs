use anyhow::{Context, Result};
use std::process::Command;

const CREDENTIAL_PREFIX: &str = "winaskpass:";

fn powershell(script: &str) -> Result<String> {
    let output = Command::new("powershell.exe")
        .args(["-NoProfile", "-NonInteractive", "-Command", script])
        .output()
        .context("Failed to execute PowerShell")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!("PowerShell error: {}", stderr);
    }

    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

fn target_name(key_path: &str) -> String {
    format!("{}{}", CREDENTIAL_PREFIX, key_path)
}

pub fn get_credential(key_path: &str) -> Result<Option<String>> {
    let target = target_name(key_path);
    let script = format!(
        r#"
        $cred = Get-StoredCredential -Target '{target}' -ErrorAction SilentlyContinue
        if ($cred) {{
            $cred.GetNetworkCredential().Password
        }}
        "#,
        target = target.replace("'", "''")
    );

    // Try with CredentialManager module first
    match powershell(&script) {
        Ok(password) if !password.is_empty() => return Ok(Some(password)),
        _ => {}
    }

    // Fallback: use cmdkey and direct API via .NET
    let script = format!(
        r#"
        Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
using System.Text;

public class CredentialManager {{
    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    public static extern bool CredReadW(string target, int type, int flags, out IntPtr credential);

    [DllImport("advapi32.dll")]
    public static extern void CredFree(IntPtr credential);

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct CREDENTIAL {{
        public int Flags;
        public int Type;
        public string TargetName;
        public string Comment;
        public System.Runtime.InteropServices.ComTypes.FILETIME LastWritten;
        public int CredentialBlobSize;
        public IntPtr CredentialBlob;
        public int Persist;
        public int AttributeCount;
        public IntPtr Attributes;
        public string TargetAlias;
        public string UserName;
    }}

    public static string GetPassword(string target) {{
        IntPtr credPtr;
        if (CredReadW(target, 1, 0, out credPtr)) {{
            try {{
                var cred = (CREDENTIAL)Marshal.PtrToStructure(credPtr, typeof(CREDENTIAL));
                if (cred.CredentialBlob != IntPtr.Zero && cred.CredentialBlobSize > 0) {{
                    return Marshal.PtrToStringUni(cred.CredentialBlob, cred.CredentialBlobSize / 2);
                }}
            }} finally {{
                CredFree(credPtr);
            }}
        }}
        return null;
    }}
}}
"@

$result = [CredentialManager]::GetPassword('{target}')
if ($result) {{ $result }}
"#,
        target = target.replace("'", "''")
    );

    let password = powershell(&script)?;
    if password.is_empty() {
        Ok(None)
    } else {
        Ok(Some(password))
    }
}

pub fn store_credential(key_path: &str, passphrase: &str) -> Result<()> {
    let target = target_name(key_path);
    let username = "";
    let script = format!(
        r#"
        Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
using System.Text;

public class CredentialWriter {{
    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    public static extern bool CredWriteW(ref CREDENTIAL credential, int flags);

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct CREDENTIAL {{
        public int Flags;
        public int Type;
        public string TargetName;
        public string Comment;
        public long LastWritten;
        public int CredentialBlobSize;
        public IntPtr CredentialBlob;
        public int Persist;
        public int AttributeCount;
        public IntPtr Attributes;
        public string TargetAlias;
        public string UserName;
    }}

    public static void Write(string target, string password, string username) {{
        byte[] byteArray = Encoding.Unicode.GetBytes(password);
        CREDENTIAL cred = new CREDENTIAL();
        cred.Type = 1; // CRED_TYPE_GENERIC
        cred.TargetName = target;
        cred.CredentialBlobSize = byteArray.Length;
        cred.CredentialBlob = Marshal.AllocHGlobal(byteArray.Length);
        Marshal.Copy(byteArray, 0, cred.CredentialBlob, byteArray.Length);
        cred.Persist = 2; // CRED_PERSIST_LOCAL_MACHINE
        cred.UserName = username;

        try {{
            if (!CredWriteW(ref cred, 0)) {{
                throw new Exception("CredWriteW failed: " + Marshal.GetLastWin32Error());
            }}
        }} finally {{
            Marshal.FreeHGlobal(cred.CredentialBlob);
        }}
    }}
}}
"@

[CredentialWriter]::Write('{target}', '{passphrase}', '{username}')
"#,
        target = target.replace("'", "''"),
        passphrase = passphrase.replace("'", "''"),
        username = username.replace("'", "''")
    );

    powershell(&script)?;
    Ok(())
}

pub fn list_credentials() -> Result<Vec<String>> {
    let script = format!(
        r#"
        Add-Type -TypeDefinition @"
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;

public class CredentialLister {{
    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    public static extern bool CredEnumerateW(string filter, int flags, out int count, out IntPtr credentials);

    [DllImport("advapi32.dll")]
    public static extern void CredFree(IntPtr credential);

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct CREDENTIAL {{
        public int Flags;
        public int Type;
        public string TargetName;
        public string Comment;
        public long LastWritten;
        public int CredentialBlobSize;
        public IntPtr CredentialBlob;
        public int Persist;
        public int AttributeCount;
        public IntPtr Attributes;
        public string TargetAlias;
        public string UserName;
    }}

    public static string[] List(string prefix) {{
        var results = new List<string>();
        int count;
        IntPtr credentials;

        if (CredEnumerateW(prefix + "*", 0, out count, out credentials)) {{
            try {{
                for (int i = 0; i < count; i++) {{
                    IntPtr credPtr = Marshal.ReadIntPtr(credentials, i * IntPtr.Size);
                    var cred = (CREDENTIAL)Marshal.PtrToStructure(credPtr, typeof(CREDENTIAL));
                    if (cred.TargetName != null && cred.TargetName.StartsWith(prefix)) {{
                        results.Add(cred.TargetName.Substring(prefix.Length));
                    }}
                }}
            }} finally {{
                CredFree(credentials);
            }}
        }}
        return results.ToArray();
    }}
}}
"@

$results = [CredentialLister]::List('{prefix}')
$results -join "`n"
"#,
        prefix = CREDENTIAL_PREFIX.replace("'", "''")
    );

    let output = powershell(&script)?;
    if output.is_empty() {
        Ok(Vec::new())
    } else {
        Ok(output.lines().map(|s| s.to_string()).collect())
    }
}
