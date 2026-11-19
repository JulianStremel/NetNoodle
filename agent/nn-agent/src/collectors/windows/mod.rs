//! Read-only Windows inventory. Pure helpers are also compiled by Linux tests.

mod interfaces;
mod os;
mod programs;
#[cfg(windows)]
mod registry {
    // Minimal read-only registry access with owned handles.
    use super::api::{error, wide};
    use std::ptr::{null, null_mut};
    use windows_sys::Win32::Foundation::{
        ERROR_FILE_NOT_FOUND, ERROR_MORE_DATA, ERROR_NO_MORE_ITEMS, ERROR_SUCCESS,
    };
    use windows_sys::Win32::System::Registry::*;

    pub struct Key(HKEY);
    impl Drop for Key {
        fn drop(&mut self) {
            // SAFETY: this handle was opened by RegOpenKeyExW and is owned here.
            unsafe {
                RegCloseKey(self.0);
            }
        }
    }
    impl Key {
        pub fn open(path: &str) -> Result<Self, String> {
            Self::open_at(HKEY_LOCAL_MACHINE, path)?
                .ok_or_else(|| format!("registry key missing: HKLM\\{path}"))
        }
        pub fn optional(path: &str) -> Result<Option<Self>, String> {
            Self::open_at(HKEY_LOCAL_MACHINE, path)
        }
        pub fn subkey(&self, name: &str) -> Result<Option<Self>, String> {
            Self::open_at(self.0, name)
        }
        pub fn has(&self, name: &str) -> Result<bool, String> {
            let name = wide(name);
            let mut size = 0;
            // SAFETY: valid key and terminated name; null data asks only for the value size.
            let status = unsafe {
                RegQueryValueExW(
                    self.0,
                    name.as_ptr(),
                    null(),
                    null_mut(),
                    null_mut(),
                    &mut size,
                )
            };
            match status {
                ERROR_SUCCESS | ERROR_MORE_DATA => Ok(true),
                ERROR_FILE_NOT_FOUND => Ok(false),
                e => Err(error("RegQueryValueExW", e)),
            }
        }
        fn open_at(parent: HKEY, path: &str) -> Result<Option<Self>, String> {
            let path = wide(path);
            let mut key = null_mut();
            // SAFETY: parent is valid, path terminated, output points to writable storage.
            let status = unsafe {
                RegOpenKeyExW(
                    parent,
                    path.as_ptr(),
                    0,
                    KEY_READ | KEY_WOW64_64KEY,
                    &mut key,
                )
            };
            match status {
                ERROR_SUCCESS => Ok(Some(Self(key))),
                ERROR_FILE_NOT_FOUND => Ok(None),
                e => Err(error("RegOpenKeyExW", e)),
            }
        }
        fn value(&self, name: &str) -> Result<(u32, Vec<u8>), String> {
            let name = wide(name);
            let mut data = Vec::new();
            for _ in 0..8 {
                let mut size = data.len() as u32;
                let mut ty = 0;
                // SAFETY: the handle and terminated name are valid; size matches the buffer.
                let status = unsafe {
                    RegQueryValueExW(
                        self.0,
                        name.as_ptr(),
                        null(),
                        &mut ty,
                        if data.is_empty() {
                            null_mut()
                        } else {
                            data.as_mut_ptr()
                        },
                        &mut size,
                    )
                };
                match status {
                    ERROR_FILE_NOT_FOUND => return Ok((0, Vec::new())),
                    ERROR_SUCCESS if size as usize <= data.len() => {
                        data.truncate(size as usize);
                        return Ok((ty, data));
                    }
                    ERROR_SUCCESS | ERROR_MORE_DATA => {
                        data.resize((size as usize).max(data.len() + 2), 0)
                    }
                    e => return Err(error("RegQueryValueExW", e)),
                }
            }
            Err("registry value kept changing size".into())
        }
        pub fn string(&self, name: &str) -> Result<String, String> {
            let (ty, bytes) = self.value(name)?;
            if ty == 0 {
                return Ok(String::new());
            }
            if !matches!(ty, REG_SZ | REG_EXPAND_SZ) || bytes.len() % 2 != 0 {
                return Err(format!("registry {name}: expected UTF-16 string"));
            }
            let words: Vec<_> = bytes
                .as_chunks::<2>()
                .0
                .iter()
                .map(|b| u16::from_le_bytes([b[0], b[1]]))
                .take_while(|w| *w != 0)
                .collect();
            Ok(String::from_utf16_lossy(&words))
        }
        pub fn dword(&self, name: &str) -> Result<u32, String> {
            let (ty, bytes) = self.value(name)?;
            if ty == 0 {
                return Ok(0);
            }
            match bytes.try_into() {
                Ok(b) if ty == REG_DWORD => Ok(u32::from_le_bytes(b)),
                _ => Err(format!("registry {name}: expected DWORD")),
            }
        }
        pub fn names(&self) -> Result<Vec<String>, String> {
            let mut out = Vec::new();
            for index in 0..u32::MAX {
                let mut buf = vec![0u16; 256];
                loop {
                    let mut size = buf.len() as u32;
                    // SAFETY: handle is valid, buffer has size UTF-16 elements; optional outputs are null.
                    let status = unsafe {
                        RegEnumKeyExW(
                            self.0,
                            index,
                            buf.as_mut_ptr(),
                            &mut size,
                            null(),
                            null_mut(),
                            null_mut(),
                            null_mut(),
                        )
                    };
                    match status {
                        ERROR_SUCCESS => {
                            out.push(String::from_utf16_lossy(&buf[..size as usize]));
                            break;
                        }
                        ERROR_NO_MORE_ITEMS => return Ok(out),
                        ERROR_MORE_DATA if buf.len() < 32768 => buf.resize(buf.len() * 2, 0),
                        e => return Err(error("RegEnumKeyExW", e)),
                    }
                }
            }
            Err("registry subkey count overflow".into())
        }
    }
}
mod sockets;

#[cfg(windows)]
pub fn all() -> Vec<Box<dyn crate::collector::Collector>> {
    vec![
        Box::new(os::Os),
        Box::new(programs::Programs),
        Box::new(sockets::Sockets),
        Box::new(interfaces::Interfaces),
    ]
}

fn enc(s: &str) -> String {
    let mut out = String::new();
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_' | b'~') {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

fn purl(namespace: &str, name: &str, version: &str, qualifiers: &[(&str, &str)]) -> String {
    let mut out = String::from("pkg:generic/");
    if !namespace.is_empty() {
        out.push_str(&enc(namespace));
        out.push('/');
    }
    out.push_str(&enc(name));
    if !version.is_empty() {
        out.push('@');
        out.push_str(&enc(version));
    }
    let mut qualifiers: Vec<_> = qualifiers.iter().filter(|(_, v)| !v.is_empty()).collect();
    qualifiers.sort();
    for (i, (key, value)) in qualifiers.into_iter().enumerate() {
        out.push(if i == 0 { '?' } else { '&' });
        out.push_str(key);
        out.push('=');
        out.push_str(&enc(value));
    }
    out
}

#[cfg(windows)]
pub(super) mod api {
    use std::ffi::c_void;

    pub fn wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(Some(0)).collect()
    }

    /// Read a NUL-terminated string owned by a successful Windows API result.
    ///
    /// # Safety
    /// `p` must be null or point to a readable, terminated UTF-16 string.
    pub unsafe fn string(p: *const u16) -> String {
        if p.is_null() {
            return String::new();
        }
        let mut len = 0;
        // SAFETY: the caller guarantees a readable NUL-terminated string.
        unsafe {
            while *p.add(len) != 0 {
                len += 1;
            }
            String::from_utf16_lossy(std::slice::from_raw_parts(p, len))
        }
    }

    /// Aligned storage for API structures and their trailing data.
    pub struct Buffer(Vec<u64>);
    impl Buffer {
        pub fn new(bytes: u32) -> Self {
            Self(vec![0; (bytes as usize).div_ceil(8).max(1)])
        }
        pub fn ptr(&mut self) -> *mut c_void {
            self.0.as_mut_ptr().cast()
        }
        pub fn len(&self) -> u32 {
            (self.0.len() * 8) as u32
        }
    }

    pub fn error(api: &str, code: u32) -> String {
        format!("{api}: {}", std::io::Error::from_raw_os_error(code as i32))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn encoded_purl() {
        assert_eq!(enc("a /é&@"), "a%20%2F%C3%A9%26%40");
        assert_eq!(
            purl(
                "",
                "A+B",
                "1:2",
                &[("publisher", "A & B"), ("arch", "x64"), ("empty", "")]
            ),
            "pkg:generic/A%2BB@1%3A2?arch=x64&publisher=A%20%26%20B"
        );
        assert_eq!(purl("", "Unknown", "", &[]), "pkg:generic/Unknown");
    }
}
