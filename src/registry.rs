//! Windows Explorer integration: a right-click "Encrypt with AegisCrypt" on
//! any file/folder, and association of the `.aegis` extension so double-click
//! (or a right-click "Decrypt with AegisCrypt") opens it back in this app.
//!
//! Everything is written under `HKEY_CURRENT_USER\Software\Classes`, which
//! Explorer treats exactly like `HKEY_CLASSES_ROOT` but which any signed-in
//! user can write without elevation - no admin prompt, and nothing gets
//! copied into `C:\Windows`. Uninstalling removes exactly the keys we added.

use std::path::Path;
use winreg::enums::*;
use winreg::RegKey;

const VAULT_PROGID: &str = "AegisCrypt.Vault";
const ENCRYPT_VERB: &str = "AegisCrypt.Encrypt";
pub const EXTENSION: &str = "aegis";

fn quoted(exe: &Path) -> String {
    format!("\"{}\"", exe.display())
}

pub fn install(exe_path: &Path) -> std::io::Result<()> {
    let classes = RegKey::predef(HKEY_CURRENT_USER).open_subkey_with_flags("Software\\Classes", KEY_ALL_ACCESS)
        .or_else(|_| RegKey::predef(HKEY_CURRENT_USER).create_subkey("Software\\Classes").map(|(k, _)| k))?;

    let exe = quoted(exe_path);

    // Right-click "Encrypt with AegisCrypt" on any file.
    let (key, _) = classes.create_subkey(format!("*\\shell\\{ENCRYPT_VERB}"))?;
    key.set_value("MUIVerb", &"Encrypt with AegisCrypt")?;
    key.set_value("Icon", &format!("{exe},0"))?;
    let (cmd, _) = classes.create_subkey(format!("*\\shell\\{ENCRYPT_VERB}\\command"))?;
    cmd.set_value("", &format!("{exe} \"%1\""))?;

    // Right-click "Encrypt with AegisCrypt" on any folder.
    let (key, _) = classes.create_subkey(format!("Directory\\shell\\{ENCRYPT_VERB}"))?;
    key.set_value("MUIVerb", &"Encrypt with AegisCrypt")?;
    key.set_value("Icon", &format!("{exe},0"))?;
    let (cmd, _) = classes.create_subkey(format!("Directory\\shell\\{ENCRYPT_VERB}\\command"))?;
    cmd.set_value("", &format!("{exe} \"%1\""))?;

    // .aegis extension -> AegisCrypt.Vault ProgID.
    let (ext_key, _) = classes.create_subkey(format!(".{EXTENSION}"))?;
    ext_key.set_value("", &VAULT_PROGID)?;

    let (progid, _) = classes.create_subkey(VAULT_PROGID)?;
    progid.set_value("", &"AegisCrypt encrypted vault")?;
    let (icon, _) = classes.create_subkey(format!("{VAULT_PROGID}\\DefaultIcon"))?;
    icon.set_value("", &format!("{exe},0"))?;

    // Double-click -> decrypt (the app auto-detects the mode from the .aegis extension).
    let (open_cmd, _) = classes.create_subkey(format!("{VAULT_PROGID}\\shell\\open\\command"))?;
    open_cmd.set_value("", &format!("{exe} \"%1\""))?;

    // Explicit right-click "Decrypt with AegisCrypt" (mirrors the encrypt verb).
    let (decrypt_key, _) = classes.create_subkey(format!("{VAULT_PROGID}\\shell\\decrypt"))?;
    decrypt_key.set_value("MUIVerb", &"Decrypt with AegisCrypt")?;
    let (decrypt_cmd, _) = classes.create_subkey(format!("{VAULT_PROGID}\\shell\\decrypt\\command"))?;
    decrypt_cmd.set_value("", &format!("{exe} \"%1\""))?;

    notify_shell();
    Ok(())
}

pub fn uninstall() -> std::io::Result<()> {
    let classes = RegKey::predef(HKEY_CURRENT_USER).open_subkey_with_flags("Software\\Classes", KEY_ALL_ACCESS)?;

    let _ = classes.open_subkey_with_flags("*\\shell", KEY_ALL_ACCESS)
        .and_then(|k| k.delete_subkey_all(ENCRYPT_VERB));
    let _ = classes.open_subkey_with_flags("Directory\\shell", KEY_ALL_ACCESS)
        .and_then(|k| k.delete_subkey_all(ENCRYPT_VERB));
    let _ = classes.delete_subkey_all(format!(".{EXTENSION}"));
    let _ = classes.delete_subkey_all(VAULT_PROGID);

    notify_shell();
    Ok(())
}

pub fn is_installed() -> bool {
    RegKey::predef(HKEY_CURRENT_USER)
        .open_subkey(format!("Software\\Classes\\.{EXTENSION}"))
        .is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn install_then_uninstall_round_trips() {
        let exe = std::env::current_exe().unwrap();
        install(&exe).expect("install should succeed without admin rights");
        assert!(is_installed());

        let classes = RegKey::predef(HKEY_CURRENT_USER).open_subkey("Software\\Classes").unwrap();
        let cmd: String = classes
            .open_subkey(format!("{VAULT_PROGID}\\shell\\open\\command"))
            .unwrap()
            .get_value("")
            .unwrap();
        assert!(cmd.contains(&exe.display().to_string()));

        uninstall().expect("uninstall should succeed");
        assert!(!is_installed());
    }
}

fn notify_shell() {
    #[link(name = "shell32")]
    extern "system" {
        fn SHChangeNotify(event_id: u32, flags: u32, item1: *const std::ffi::c_void, item2: *const std::ffi::c_void);
    }
    const SHCNE_ASSOCCHANGED: u32 = 0x0800_0000;
    const SHCNF_IDLIST: u32 = 0x0000;
    unsafe {
        SHChangeNotify(SHCNE_ASSOCCHANGED, SHCNF_IDLIST, std::ptr::null(), std::ptr::null());
    }
}
