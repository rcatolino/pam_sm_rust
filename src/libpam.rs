#![allow(dead_code)]
#![allow(non_camel_case_types)]

use pam::{Pam, PamError, PamResult};
use pam_types::{PamConv, PamHandle, PamItemType, PamMessage, PamMsgStyle, PamResponse};
use std::ffi::{CStr, CString};
use std::option::Option;
use std::os::raw::{c_char, c_int, c_void};
use std::ptr;

#[cfg(feature = "libpam")]
const ERR_CSTR_NULL: &str = "Error, the prompt cannot contain any null bytes";

/// This contains a private marker trait, used to seal private traits.
mod private {
    pub trait Sealed {}
    impl Sealed for super::Pam {}
}

/// Extension trait over `Pam`, usually provided by the `libpam` shared library.
pub trait PamLibExt: private::Sealed {
    /// Get the username. If the PAM_USER item is not set, this function
    /// prompts for a username (like get_authtok).
    fn get_user(&self, prompt: Option<&str>) -> PamResult<Option<&CStr>>;

    /// Get the username, i.e. the PAM_USER item. If it's not set return None.
    fn get_cached_user(&self) -> PamResult<Option<&CStr>>;

    /// Get the cached authentication token.
    fn get_cached_authtok(&self) -> PamResult<Option<&CStr>>;

    /// Get the cached authentication token or prompt the user for one if there isn't any.
    fn get_authtok(&self, prompt: Option<&str>) -> PamResult<Option<&CStr>>;

    fn set_authtok(&self, authtok: &CString) -> PamResult<()>;

    /// Get the remote hostname.
    fn get_rhost(&self) -> PamResult<Option<&CStr>>;

    /// Get the remote username.
    fn get_ruser(&self) -> PamResult<Option<&CStr>>;

    /// Prompt the user for custom input.
    fn conv(&self, prompt: Option<&str>, style: PamMsgStyle) -> PamResult<Option<&CStr>>;
}

#[cfg(feature = "libpam")]
impl PamLibExt for Pam {
    fn get_user(&self, prompt: Option<&str>) -> PamResult<Option<&CStr>> {
        let cprompt = prompt.map(|p| CString::new(p).expect(ERR_CSTR_NULL));
        let mut raw_user: *const c_char = ptr::null();
        let r = unsafe {
            PamError::new(pam_get_user(
                self.0,
                &mut raw_user,
                cprompt.map(|p| p.as_ptr()).unwrap_or(ptr::null())
            ))
        };

        if raw_user.is_null() {
            r.to_result(None)
        } else {
            r.to_result(Some(unsafe { CStr::from_ptr(raw_user) }))
        }
    }

    fn get_cached_user(&self) -> PamResult<Option<&CStr>> {
        let pointer = get_item(self.0, PamItemType::USER)?;
        unsafe { Ok(pointer.map(|p| CStr::from_ptr(p as *const c_char))) }
    }

    fn get_cached_authtok(&self) -> PamResult<Option<&CStr>> {
        // pam should keep the underlying token allocated for as long as the module is loaded
        // which make this safe
        unsafe {
            let pointer = get_item(self.0, PamItemType::AUTHTOK)?;
            Ok(pointer.map(|p| CStr::from_ptr(p as *const c_char)))
        }
    }

    fn get_authtok(&self, prompt: Option<&str>) -> PamResult<Option<&CStr>> {
        let cprompt = prompt.map(|p| CString::new(p).expect(ERR_CSTR_NULL));
        let mut raw_at: *const c_char = ptr::null();
        let r = unsafe {
            PamError::new(pam_get_authtok(
                self.0,
                PamItemType::AUTHTOK as i32,
                &mut raw_at,
                cprompt.map(|p| p.as_ptr()).unwrap_or(ptr::null()),
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
        let pointer = get_item(self.0, PamItemType::RHOST)?;
        unsafe { Ok(pointer.map(|p| CStr::from_ptr(p as *const c_char))) }
    }

    fn get_ruser(&self) -> PamResult<Option<&CStr>> {
        let pointer = get_item(self.0, PamItemType::RUSER)?;
        unsafe { Ok(pointer.map(|p| CStr::from_ptr(p as *const c_char))) }
    }

    fn conv(&self, prompt: Option<&str>, style: PamMsgStyle) -> PamResult<Option<&CStr>> {
        let pointer = match get_item(self.0, PamItemType::CONV)? {
            Some(p) => p,
            None => return Ok(None),
        };
        let conv = unsafe { &*(pointer as *const PamConv) };

        let mut resp_ptr: *mut PamResponse = ptr::null_mut();
        let msg_cstr = CString::new(prompt.unwrap_or("")).expect(ERR_CSTR_NULL);
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
}


unsafe fn set_item(
    pamh: PamHandle,
    item_type: PamItemType,
    item: *const c_void,
) -> PamResult<()> {
    PamError::new(pam_set_item(pamh, item_type as c_int, item)).to_result(())
}

pub fn get_item(pamh: PamHandle, item_type: PamItemType) -> PamResult<Option<*const c_void>> {
    let mut raw_item: *const c_void = ptr::null();
    let r = unsafe { PamError::new(pam_get_item(pamh, item_type as c_int, &mut raw_item)) };
    if raw_item.is_null() {
        r.to_result(None)
    } else {
        r.to_result(Some(raw_item))
    }
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
        cleanup: Option<extern "C" fn(arg1: PamHandle, arg2: *mut c_void, arg3: c_int)>,
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
