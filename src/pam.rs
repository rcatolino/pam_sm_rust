// Copyright (c) 2017 raphael.catolino@gmail.com

use libc::{size_t};
use pam_raw::{PamFlag, PamHandle, PamItemType, PamError, PamResult, get_item, get_authtok, set_item};
use std::os::raw::{c_char, c_void};
use std::ffi::{CStr, CString};
use std::str::Utf8Error;

/// Opaque PAM handle
pub struct Pam(PamHandle);

impl Pam {
    /// Get the cached authentication token.
    pub fn get_cached_authtok(&self) -> PamResult<Option<&CStr>> {
        // pam should keep the underlying token allocated for as long as the module is loaded
        // which make this safe
        unsafe {
            let pointer = try!(get_item(self.0, PamItemType::AUTHTOK));
            Ok(pointer.map(|p| CStr::from_ptr(p as *const c_char)))
        }
    }

    /// Get the cached authentication token or prompt the user for one if there isn't any
    pub fn get_authtok(&self, prompt: Option<&str>) -> PamResult<Option<&CStr>> {
        let cprompt = prompt.map(|p| CString::new(p).expect("Error, the prompt cannot contain any null bytes"));
        let result = try!(get_authtok(self.0, PamItemType::AUTHTOK, cprompt.as_ref().map(|p| p.as_ptr())));
        // If result is Ok we're guaranteed that p is a valid pointer
        unsafe {
            Ok(result.map(|p| CStr::from_ptr(p)))
        }
    }

    pub fn set_authtok(&self, authtok: &CString) -> PamResult<()> {
        set_item(self.0, PamItemType::AUTHTOK, authtok.as_ptr() as *const c_void)
    }

}

/// Default service module implementation.
/// All default functions return SERVICE_ERR.
/// You can override functions depending on what kind of module you implement.
/// See the respective pam_sm_* man pages for documentation.
pub trait PamServiceModule {
    fn open_session(self: &Self, _: Pam, _: PamFlag, _: Vec<String>) -> PamError {
        PamError::SERVICE_ERR
    }

    fn close_session(self: &Self, _: Pam, _: PamFlag, _: Vec<String>) -> PamError {
        PamError::SERVICE_ERR
    }

    fn authenticate(self: &Self, _: Pam, _: PamFlag, _: Vec<String>) -> PamError {
        PamError::SERVICE_ERR
    }

    fn setcred(self: &Self, _: Pam, _: PamFlag, _: Vec<String>) -> PamError {
        PamError::SERVICE_ERR
    }

    fn acct_mgmt(self: &Self, _: Pam, _: PamFlag, _: Vec<String>) -> PamError {
        PamError::SERVICE_ERR
    }

    fn chauthtok(self: &Self, _: Pam, _: PamFlag, _: Vec<String>) -> PamError {
        PamError::SERVICE_ERR
    }
}

/// You must implement a get_pam_sm function that returns a Box<PamServiceModule>
/// This PamServiceModule implementation should override the functions you need in your module
#[allow(improper_ctypes)]
extern {
    #[no_mangle]
    fn get_pam_sm() -> Box<PamServiceModule>;
}

thread_local! {
    static PAMSM: Box<PamServiceModule> = unsafe { get_pam_sm() };
}

unsafe fn extract_args(argc: size_t, argv: *const *const u8) -> Result<Vec<String>, Utf8Error> {
    let mut args = Vec::<String>::with_capacity(argc);
    for count in 0..(argc as isize) {
        args.push(try!(CStr::from_ptr(*argv.offset(count) as *const c_char).to_str()).to_owned())
    }
    Ok(args)
}

macro_rules! pam_callback {
    ($pam_cb:ident, $rust_cb:ident) => {
        #[no_mangle]
        #[doc(hidden)]
        pub extern "C" fn $pam_cb(pamh: Pam, flags: PamFlag,
                                   argc: size_t, argv: *const *const u8) -> PamError {
            match unsafe { extract_args(argc, argv) } {
                Ok(args) => PAMSM.with(|sm| sm.$rust_cb(pamh, flags, args)),
                Err(_) => PamError::SERVICE_ERR,
            }
        }
    }
}

// Pam Callbacks
pam_callback!(pam_sm_open_session, open_session);
pam_callback!(pam_sm_close_session, close_session);
pam_callback!(pam_sm_authenticate, authenticate);
pam_callback!(pam_sm_setcred, setcred);
pam_callback!(pam_sm_acct_mgmt, acct_mgmt);
pam_callback!(pam_sm_chauthtok, chauthtok);

