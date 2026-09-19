use anyhow::{Context, Result};
use std::path::Path;

/// File-format marker for Windows DPAPI protected JSON.
#[cfg(windows)]
const DPAPI_FORMAT: &str = "wx-cli-dpapi-v1";

/// Read the key document.
///
/// On Windows, files written by this fork are a small JSON envelope whose
/// payload is protected with current-user DPAPI. Legacy plaintext JSON is
/// accepted for migration compatibility.
pub fn read_json(path: &Path) -> Result<serde_json::Value> {
    let content = std::fs::read_to_string(path)
        .with_context(|| format!("读取密钥文件失败: {}", path.display()))?;

    #[cfg(windows)]
    {
        if let Ok(envelope) = serde_json::from_str::<serde_json::Value>(&content) {
            if envelope
                .get("_format")
                .and_then(|v| v.as_str())
                == Some(DPAPI_FORMAT)
            {
                use base64::Engine as _;

                let encoded = envelope
                    .get("blob")
                    .and_then(|v| v.as_str())
                    .context("DPAPI 密钥文件缺少 blob")?;
                let ciphertext = base64::engine::general_purpose::STANDARD
                    .decode(encoded)
                    .context("DPAPI blob base64 解码失败")?;
                let mut plaintext = dpapi_unprotect_current_user(&ciphertext)?;
                let parsed = serde_json::from_slice(&plaintext)
                    .context("DPAPI 解密后的密钥 JSON 格式错误");
                plaintext.fill(0);
                return parsed;
            }
        }
    }

    // Legacy plaintext input is accepted for compatibility. On Windows
    // Safe Readonly immediately migrates it in place to current-user DPAPI,
    // so a successful read never leaves known plaintext keys at rest.
    let parsed: serde_json::Value =
        serde_json::from_str(&content).context("密钥 JSON 格式错误")?;

    #[cfg(windows)]
    {
        write_json(path, &parsed).context("将旧版明文密钥迁移到 DPAPI 失败")?;
    }

    Ok(parsed)
}

/// Write a key document.
///
/// Windows: current-user DPAPI + base64 JSON envelope.
/// Unix: plaintext JSON with mode 0600 (existing upstream behavior is retained).
pub fn write_json(path: &Path, value: &serde_json::Value) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("创建密钥目录失败: {}", parent.display()))?;
    }

    let mut plaintext = serde_json::to_vec_pretty(value)?;

    #[cfg(windows)]
    {
        use base64::Engine as _;

        let ciphertext = dpapi_protect_current_user(&plaintext)?;
        plaintext.fill(0);

        let envelope = serde_json::json!({
            "_format": DPAPI_FORMAT,
            "scope": "current-user",
            "blob": base64::engine::general_purpose::STANDARD.encode(ciphertext),
        });
        std::fs::write(path, serde_json::to_vec_pretty(&envelope)?)
            .with_context(|| format!("写入 DPAPI 密钥文件失败: {}", path.display()))?;
        return Ok(());
    }

    #[cfg(not(windows))]
    {
        std::fs::write(path, &plaintext)
            .with_context(|| format!("写入密钥文件失败: {}", path.display()))?;
        plaintext.fill(0);

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
                .with_context(|| format!("设置密钥文件权限失败: {}", path.display()))?;
        }
        Ok(())
    }
}

#[cfg(windows)]
fn dpapi_protect_current_user(plaintext: &[u8]) -> Result<Vec<u8>> {
    use windows::core::PCWSTR;
    use windows::Win32::Foundation::{HLOCAL, LocalFree};
    use windows::Win32::Security::Cryptography::{
        CryptProtectData, CRYPT_INTEGER_BLOB, CRYPTPROTECT_UI_FORBIDDEN,
    };

    let input = CRYPT_INTEGER_BLOB {
        cbData: plaintext.len().try_into().context("密钥数据过大")?,
        pbData: plaintext.as_ptr() as *mut u8,
    };
    let mut output = CRYPT_INTEGER_BLOB::default();

    unsafe {
        CryptProtectData(
            &input,
            PCWSTR::null(),
            None,
            None,
            None,
            CRYPTPROTECT_UI_FORBIDDEN,
            &mut output,
        )
        .context("CryptProtectData 失败")?;
    }

    let result = if output.pbData.is_null() {
        Vec::new()
    } else {
        unsafe { std::slice::from_raw_parts(output.pbData, output.cbData as usize).to_vec() }
    };

    if !output.pbData.is_null() {
        unsafe {
            let _ = LocalFree(Some(HLOCAL(output.pbData as *mut core::ffi::c_void)));
        }
    }
    Ok(result)
}

#[cfg(windows)]
fn dpapi_unprotect_current_user(ciphertext: &[u8]) -> Result<Vec<u8>> {
    use windows::Win32::Foundation::{HLOCAL, LocalFree};
    use windows::Win32::Security::Cryptography::{
        CryptUnprotectData, CRYPT_INTEGER_BLOB, CRYPTPROTECT_UI_FORBIDDEN,
    };

    let input = CRYPT_INTEGER_BLOB {
        cbData: ciphertext.len().try_into().context("DPAPI blob 过大")?,
        pbData: ciphertext.as_ptr() as *mut u8,
    };
    let mut output = CRYPT_INTEGER_BLOB::default();

    unsafe {
        CryptUnprotectData(
            &input,
            None,
            None,
            None,
            None,
            CRYPTPROTECT_UI_FORBIDDEN,
            &mut output,
        )
        .context("CryptUnprotectData 失败；该密钥文件可能属于另一 Windows 用户或另一台电脑")?;
    }

    let mut result = if output.pbData.is_null() {
        Vec::new()
    } else {
        unsafe { std::slice::from_raw_parts(output.pbData, output.cbData as usize).to_vec() }
    };

    // Wipe the DPAPI-owned plaintext buffer before LocalFree.
    if !output.pbData.is_null() {
        unsafe {
            std::ptr::write_bytes(output.pbData, 0, output.cbData as usize);
            let _ = LocalFree(Some(HLOCAL(output.pbData as *mut core::ffi::c_void)));
        }
    }
    Ok(std::mem::take(&mut result))
}

#[cfg(all(test, windows))]
mod tests {
    use super::*;

    #[test]
    fn dpapi_round_trip_for_current_user() {
        let input = br#"{"session/session.db":{"enc_key":"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"}}"#;
        let ciphertext = dpapi_protect_current_user(input).expect("protect");
        assert_ne!(ciphertext.as_slice(), input);
        let plaintext = dpapi_unprotect_current_user(&ciphertext).expect("unprotect");
        assert_eq!(plaintext.as_slice(), input);
    }
}
