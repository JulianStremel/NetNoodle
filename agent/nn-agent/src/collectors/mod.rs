//! Built-in collectors. To add one: write a type that implements
//! [`Collector`] in a new module and add it to [`all`].

mod apk;
mod dpkg;
mod interfaces;
mod os;
mod rpm;
pub mod sockets;
pub mod sockowner;
mod util;
#[cfg(windows)]
mod windows;
// Exercise the pure helpers on non-Windows test builds as well.
#[cfg(all(test, not(windows)))]
#[path = "windows/mod.rs"]
mod windows_tests;

use crate::collector::Collector;

/// All compiled-in collectors. The config selects which of them run.
pub fn all() -> Vec<Box<dyn Collector>> {
    #[cfg(windows)]
    {
        windows::all()
    }
    #[cfg(not(windows))]
    linux()
}

/// Linux collectors, also used by the platform-independent fixture tests.
pub fn linux() -> Vec<Box<dyn Collector>> {
    vec![
        Box::new(os::Os),
        Box::new(interfaces::Interfaces),
        Box::new(dpkg::Dpkg),
        Box::new(rpm::Rpm),
        Box::new(apk::Apk),
        Box::new(sockets::Sockets),
    ]
}

#[cfg(test)]
pub(crate) fn testctx(name: &str) -> crate::collector::Ctx {
    crate::collector::Ctx::new(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("testdata")
            .join(name),
    )
}
