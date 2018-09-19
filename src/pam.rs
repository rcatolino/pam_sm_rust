// Copyright (c) 2017 raphael.catolino@gmail.com

use libc::{size_t};
use pam_raw::{PamFlag, PamHandle, PamItemType, PamError, PamResult, get_user, get_item, get_authtok, set_item};
use std::os::raw::{c_char, c_void};
use std::ffi::{CStr, CString};
use std::str::Utf8Error;

/// Opaque PAM handle
pub struct Pam(PamHandle);

impl Pam {

    /// Get the username. If the PAM_USER item is not set, this function
    /// prompts for a username (like get_authtok).
    pub fn get_user(&self, prompt: Option<&str>) -> PamResult<Option<&CStr>> {
        let cprompt = prompt.map(|p| CString::new(p).expect("Error, the prompt cannot contain any null bytes"));
        let pointer = get_user(self.0, cprompt.as_ref().map(|p| p.as_ptr()))?;
        unsafe {
            Ok(pointer.map(|p| CStr::from_ptr(p)))
        }
    }

    /// Get the username, i.e. the PAM_USER item. If it's not set return None.
    pub fn get_cached_user(&self) -> PamResult<Option<&CStr>> {
        let pointer = get_item(self.0, PamItemType::USER)?;
        unsafe {
            Ok(pointer.map(|p| CStr::from_ptr(p as *const c_char)))
        }
    }

    /// Get the cached authentication token.
    pub fn get_cached_authtok(&self) -> PamResult<Option<&CStr>> {
        // pam should keep the underlying token allocated for as long as the module is loaded
        // which make this safe
        unsafe {
            let pointer = get_item(self.0, PamItemType::AUTHTOK)?;
            Ok(pointer.map(|p| CStr::from_ptr(p as *const c_char)))
        }
    }

    /// Get the cached authentication token or prompt the user for one if there isn't any
    pub fn get_authtok(&self, prompt: Option<&str>) -> PamResult<Option<&CStr>> {
        let cprompt = prompt.map(|p| CString::new(p).expect("Error, the prompt cannot contain any null bytes"));
        let result = get_authtok(self.0, PamItemType::AUTHTOK, cprompt.as_ref().map(|p| p.as_ptr()))?;
        // If result is Ok we're guaranteed that p is a valid pointer
        unsafe {
            Ok(result.map(|p| CStr::from_ptr(p)))
        }
    }

    pub fn set_authtok(&self, authtok: &CString) -> PamResult<()> {
        set_item(self.0, PamItemType::AUTHTOK, authtok.as_ptr() as *const c_void)
    }

    /// Get the remote hostname.
    pub fn get_rhost(&self) -> PamResult<Option<&CStr>> {
        let pointer = get_item(self.0, PamItemType::RHOST)?;
        unsafe {
            Ok(pointer.map(|p| CStr::from_ptr(p as *const c_char)))
        }
    }

    /// Get the remote username.
    pub fn get_ruser(&self) -> PamResult<Option<& CStr>> {
        let pointer = get_item(self.0, PamItemType::RUSER)?;
        unsafe {
            Ok(pointer.map(|p| CStr::from_ptr(p as *const c_char)))
        }
    }
}

/// Default service module implementation.
/// All default functions return SERVICE_ERR.
/// You can override functions depending on what kind of module you implement.
/// See the respective pam_sm_* man pages for documentation.
pub trait PamServiceModule {
    fn open_session(_: Pam, _: PamFlag, _: Vec<String>) -> PamError {
        PamError::SERVICE_ERR
    }

    fn close_session(_: Pam, _: PamFlag, _: Vec<String>) -> PamError {
        PamError::SERVICE_ERR
    }

    fn authenticate(_: Pam, _: PamFlag, _: Vec<String>) -> PamError {
        PamError::SERVICE_ERR
    }

    fn setcred(_: Pam, _: PamFlag, _: Vec<String>) -> PamError {
        PamError::SERVICE_ERR
    }

    fn acct_mgmt(_: Pam, _: PamFlag, _: Vec<String>) -> PamError {
        PamError::SERVICE_ERR
    }

    fn chauthtok(_: Pam, _: PamFlag, _: Vec<String>) -> PamError {
        PamError::SERVICE_ERR
    }
}

#[doc(hidden)]
pub unsafe fn extract_args(argc: size_t, argv: *const *const u8) -> Result<Vec<String>, Utf8Error> {
    let mut args = Vec::<String>::with_capacity(argc);
    for count in 0..(argc as isize) {
        args.push(CStr::from_ptr(*argv.offset(count) as *const c_char).to_str()?.to_owned())
    }
    Ok(args)
}

#[macro_export]
macro_rules! pam_callback {
    ($pamsm_ty:ty, $pam_cb:ident, $rust_cb:ident) => {
        #[no_mangle]
        #[doc(hidden)]
        pub extern "C" fn $pam_cb(pamh: pamsm::Pam, flags: pamsm::pam_raw::PamFlag,
                                  argc: usize, argv: *const *const u8) -> pamsm::pam_raw::PamError {
            match unsafe { pamsm::extract_args(argc, argv) } {
                Ok(args) => <$pamsm_ty>::$rust_cb(pamh, flags, args),
                Err(_) => pamsm::pam_raw::PamError::SERVICE_ERR,
            }
        }
    }
}

/// Define entrypoints for the PAM module.
///
/// This macro must be called exactly once in a PAM module.
/// It then exports all the pam_sm_* symbols.
///
/// The argument to the macro is a type implementing the
/// `PamServiceModule` trait.
///
/// # Example
///
/// ```ignore
/// // lib.rs
/// #[macro_use] extern crate pamsm;
///
/// pam_module!(MyPamService);
/// ```
#[macro_export]
macro_rules! pam_module {
    ($pamsm_ty:ty) => {
        // Check trait bound on input type.
        fn _check_pamsm_trait<T: pamsm::PamServiceModule>() { }
        fn _t() { _check_pamsm_trait::<$pamsm_ty>() }

        pam_callback!($pamsm_ty, pam_sm_open_session, open_session);
        pam_callback!($pamsm_ty, pam_sm_close_session, close_session);
        pam_callback!($pamsm_ty, pam_sm_authenticate, authenticate);
        pam_callback!($pamsm_ty, pam_sm_setcred, setcred);
        pam_callback!($pamsm_ty, pam_sm_acct_mgmt, acct_mgmt);
        pam_callback!($pamsm_ty, pam_sm_chauthtok, chauthtok);
    }
}
