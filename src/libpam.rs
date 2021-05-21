#![allow(dead_code)]
#![allow(non_camel_case_types)]

use pam::{Pam, PamError, PamFlag};
use pam_types::{PamConv, PamHandle, PamItemType, PamMessage, PamMsgStyle, PamResponse};
use std::ffi::{CStr, CString, NulError};
use std::option::Option;
use std::os::raw::{c_char, c_int, c_void};
use std::ptr;
use std::rc::Rc;

pub type PamResult<T> = Result<T, PamError>;

pub trait PamData: Sync {
    fn cleanup(&self, _pam: Pam, _flags: i32, _status: PamError) {}
}

impl PamError {
    fn to_result<T>(self, ok: T) -> PamResult<T> {
        if self == PamError::SUCCESS {
            Ok(ok)
        } else {
            Err(self)
        }
    }
}

/// This contains a private marker trait, used to seal private traits.
mod private {
    pub trait Sealed {}
    impl Sealed for super::Pam {}
}

impl Pam {
    // End users should call the item specific methods
    fn get_cstr_item(&self, item_type: PamItemType) -> PamResult<Option<&CStr>> {
        match item_type {
            PamItemType::CONV | PamItemType::FAIL_DELAY | PamItemType::XAUTHDATA => {
                panic!("Error, get_cstr_item can only be used with pam item returning c-strings")
            }
            _ => (),
        }
        let mut raw_item: *const c_void = ptr::null();
        let r = unsafe { PamError::new(pam_get_item(self.0, item_type as c_int, &mut raw_item)) };
        if raw_item.is_null() {
            r.to_result(None)
        } else {
            // pam should keep the underlying token allocated during the lifetime of the module
            r.to_result(Some(unsafe { CStr::from_ptr(raw_item as *const c_char) }))
        }
    }
}

/// Extension trait over `Pam`, usually provided by the `libpam` shared library.
pub trait PamLibExt: private::Sealed {
    /// Get the username. If the PAM_USER item is not set, this function
    /// prompts for a username (like get_authtok).
    /// Returns PamError::SERVICE_ERR if the prompt contains any null byte
    fn get_user(&self, prompt: Option<&str>) -> PamResult<Option<&CStr>>;

    /// Get the username, i.e. the PAM_USER item. If it's not set return None.
    fn get_cached_user(&self) -> PamResult<Option<&CStr>>;

    /// Get the cached authentication token.
    fn get_cached_authtok(&self) -> PamResult<Option<&CStr>>;

    /// Get the cached old authentication token.
    fn get_cached_oldauthtok(&self) -> PamResult<Option<&CStr>>;

    /// Get the cached authentication token or prompt the user for one if there isn't any.
    /// Returns PamError::SERVICE_ERR if the prompt contains any null byte
    fn get_authtok(&self, prompt: Option<&str>) -> PamResult<Option<&CStr>>;

    fn set_authtok(&self, authtok: &CString) -> PamResult<()>;

    /// Get the remote hostname.
    fn get_rhost(&self) -> PamResult<Option<&CStr>>;

    /// Get the remote username.
    fn get_ruser(&self) -> PamResult<Option<&CStr>>;

    /// Prompt the user for custom input.
    /// Returns PamError::SERVICE_ERR if the prompt contains any null byte
    fn conv(&self, prompt: Option<&str>, style: PamMsgStyle) -> PamResult<Option<&CStr>>;

    /// Get a variable from the pam environment list.
    fn getenv(&self, name: &str) -> PamResult<Option<&CStr>>;

    /// Put a variable in the pam environment list.
    /// `name_value` takes for form documented in pam_putent(3) :
    ///
    /// - `NAME=value` will set variable `NAME` to value `value`
    /// - `NAME=` will set variable `NAME` to an empty value
    /// - `NAME` will unset the variable `NAME`
    fn putenv(&self, name_value: &str) -> PamResult<()>;

    unsafe fn get_data<T: PamData>(&self, module_name: &str) -> PamResult<Rc<T>>;
    fn set_data<T: PamData>(&self, module_name: &str, data: Rc<T>) -> PamResult<()>;
}

impl From<NulError> for PamError {
    fn from(_: NulError) -> PamError {
        PamError::SERVICE_ERR
    }
}

impl PamLibExt for Pam {
    fn get_user(&self, prompt: Option<&str>) -> PamResult<Option<&CStr>> {
        let cprompt = match prompt {
            None => None,
            Some(p) => Some(CString::new(p)?),
        };
        let mut raw_user: *const c_char = ptr::null();
        let r = unsafe {
            PamError::new(pam_get_user(
                self.0,
                &mut raw_user,
                cprompt.as_ref().map_or(ptr::null(), |p| p.as_ptr()),
            ))
        };

        if raw_user.is_null() {
            r.to_result(None)
        } else {
            r.to_result(Some(unsafe { CStr::from_ptr(raw_user) }))
        }
    }

    fn get_cached_user(&self) -> PamResult<Option<&CStr>> {
        self.get_cstr_item(PamItemType::USER)
    }

    fn get_cached_authtok(&self) -> PamResult<Option<&CStr>> {
        self.get_cstr_item(PamItemType::AUTHTOK)
    }

    fn get_cached_oldauthtok(&self) -> PamResult<Option<&CStr>> {
        self.get_cstr_item(PamItemType::OLDAUTHTOK)
    }

    fn get_authtok(&self, prompt: Option<&str>) -> PamResult<Option<&CStr>> {
        let cprompt = match prompt {
            None => None,
            Some(p) => Some(CString::new(p)?),
        };
        let mut raw_at: *const c_char = ptr::null();
        let r = unsafe {
            PamError::new(pam_get_authtok(
                self.0,
                PamItemType::AUTHTOK as i32,
                &mut raw_at,
                cprompt.as_ref().map_or(ptr::null(), |p| p.as_ptr()),
            ))
        };

        if raw_at.is_null() {
            r.to_result(None)
        } else {
            r.to_result(unsafe { Some(CStr::from_ptr(raw_at)) })
        }
    }

    fn set_authtok(&self, authtok: &CString) -> PamResult<()> {
        unsafe {
            set_item(
                self.0,
                PamItemType::AUTHTOK,
                authtok.as_ptr() as *const c_void,
            )
        }
    }

    fn get_rhost(&self) -> PamResult<Option<&CStr>> {
        self.get_cstr_item(PamItemType::RHOST)
    }

    fn get_ruser(&self) -> PamResult<Option<&CStr>> {
        self.get_cstr_item(PamItemType::RUSER)
    }

    fn conv(&self, prompt: Option<&str>, style: PamMsgStyle) -> PamResult<Option<&CStr>> {
        let mut conv_pointer: *const c_void = ptr::null();
        let r = unsafe {
            PamError::new(pam_get_item(
                self.0,
                PamItemType::CONV as c_int,
                &mut conv_pointer,
            ))
        };

        if r != PamError::SUCCESS {
            return Err(r);
        }

        if conv_pointer.is_null() {
            return Ok(None);
        }

        let conv = unsafe { &*(conv_pointer as *const PamConv) };
        let mut resp_ptr: *mut PamResponse = ptr::null_mut();
        let msg_cstr = CString::new(prompt.unwrap_or(""))?;
        let msg = PamMessage {
            msg_style: style,
            msg: msg_cstr.as_ptr(),
        };

        match conv.cb.map(|cb| {
            PamError::new(cb(
                1,
                &mut (&msg as *const PamMessage),
                &mut resp_ptr,
                conv.appdata_ptr,
            ))
        }) {
            Some(PamError::SUCCESS) => {
                Ok(unsafe { (*resp_ptr).resp }.map(|r| unsafe { CStr::from_ptr(r.as_ptr()) }))
            }
            Some(ret) => Err(ret),
            None => Ok(None),
        }
    }

    fn getenv(&self, name: &str) -> PamResult<Option<&CStr>> {
        let cname = CString::new(name)?;
        let cenv = unsafe { pam_getenv(self.0, cname.as_ptr()) };

        if cenv.is_null() {
            Ok(None)
        } else {
            unsafe { Ok(Some(CStr::from_ptr(cenv))) }
        }
    }

    fn putenv(&self, name_value: &str) -> PamResult<()> {
        let cenv = CString::new(name_value)?;
        unsafe { PamError::new(pam_putenv(self.0, cenv.as_ptr())).to_result(()) }
    }

    unsafe fn get_data<T: PamData>(&self, module_name: &str) -> PamResult<Rc<T>> {
        let mut data_ptr : *const c_void = ptr::null();
        PamError::new(pam_get_data(
            self.0,
            CString::new(module_name)?.as_ptr(),
            &mut data_ptr,
        )).to_result(data_ptr as *const T).map(|ptr| Rc::from_raw(ptr))
    }

    // T has to be boxed because it will outlive the call stack
    fn set_data<T: PamData>(&self, module_name: &str, data: Rc<T>) -> PamResult<()> {
        // This needs unsafe because pam_data_cleanup is unsafe if T is different than what
        // was used in pam_set_data.
        PamError::new(unsafe {
            pam_set_data(
                self.0,
                CString::new(module_name)?.as_ptr(),
                Rc::into_raw(data) as *mut c_void,
                Some(pam_data_cleanup::<T>),
            )
        })
        .to_result(())
    }
}

unsafe extern "C" fn pam_data_cleanup<T: PamData>(
    handle: PamHandle,
    data: *mut c_void,
    error_status: c_int,
) {
    let mut flags = 0i32;
    flags |= error_status & PamFlag::PAM_DATA_REPLACE as i32;
    flags |= error_status & PamFlag::PAM_SILENT as i32;
    Rc::from_raw(data as *const T).cleanup(Pam(handle), flags, PamError::new(error_status & 0xff));
}

unsafe fn set_item(pamh: PamHandle, item_type: PamItemType, item: *const c_void) -> PamResult<()> {
    PamError::new(pam_set_item(pamh, item_type as c_int, item)).to_result(())
}

// Raw functions
#[link(name = "pam")]
extern "C" {
    pub fn pam_set_item(pamh: PamHandle, item_type: c_int, item: *const c_void) -> c_int;
    pub fn pam_get_item(pamh: PamHandle, item_type: c_int, item: *mut *const c_void) -> c_int;
    pub fn pam_strerror(pamh: PamHandle, errnum: c_int) -> *const c_char;
    pub fn pam_putenv(pamh: PamHandle, name_value: *const c_char) -> c_int;
    pub fn pam_getenv(pamh: PamHandle, name: *const c_char) -> *const c_char;
    pub fn pam_getenvlist(pamh: PamHandle) -> *mut *mut c_char;

    pub fn pam_set_data(
        pamh: PamHandle,
        module_data_name: *const c_char,
        data: *mut c_void,
        cleanup: Option<unsafe extern "C" fn(_: PamHandle, _: *mut c_void, _: c_int)>,
    ) -> c_int;
    pub fn pam_get_data(
        pamh: PamHandle,
        module_data_name: *const c_char,
        data: *mut *const c_void,
    ) -> c_int;
    pub fn pam_get_user(pamh: PamHandle, user: *mut *const c_char, prompt: *const c_char) -> c_int;
    pub fn pam_get_authtok(
        pamh: PamHandle,
        item: c_int,
        authok_ptr: *mut *const c_char,
        prompt: *const c_char,
    ) -> c_int;
}
