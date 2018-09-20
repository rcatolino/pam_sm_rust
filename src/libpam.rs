#![allow(dead_code)]
#![allow(non_camel_case_types)]

use pam::{PamError, PamResult};
use std::ptr;
use std::option::Option;
use std::os::raw::{c_char, c_int, c_void};

use super::pam_types::*;

pub fn get_user(pamh: PamHandle, prompt: Option<*const c_char>) -> PamResult<Option<*const c_char>> {
    let mut raw_user : *const c_char = ptr::null();
    let r = unsafe {
        PamError::new(pam_get_user(pamh, &mut raw_user, prompt.unwrap_or(ptr::null())))
    };
    if raw_user.is_null() {
        r.to_result(None)
    } else {
        r.to_result(Some(raw_user))
    }
}

#[cfg_attr(feature = "cargo-clippy", allow(not_unsafe_ptr_arg_deref))]
pub fn set_item(pamh: PamHandle, item_type: PamItemType, item: *const c_void) -> PamResult<()> {
    PamError::new(unsafe { pam_set_item(pamh, item_type as c_int, item) }).to_result(())
}

pub fn get_item(pamh: PamHandle, item_type: PamItemType) -> PamResult<Option<*const c_void>> {
    let mut raw_item : *const c_void = ptr::null();
    let r = unsafe {
        PamError::new(pam_get_item(pamh, item_type as c_int, &mut raw_item))
    };
    if raw_item.is_null() {
        r.to_result(None)
    } else {
        r.to_result(Some(raw_item))
    }
}

pub fn get_authtok(pamh: PamHandle, item_type: PamItemType,
                   prompt: Option<*const c_char>) -> PamResult<Option<*const c_char>> {
    let mut raw_at : *const c_char = ptr::null();
    let r = unsafe {
        PamError::new(pam_get_authtok(pamh, item_type as i32, &mut raw_at, prompt.unwrap_or(ptr::null())))
    };
    if raw_at.is_null() {
        r.to_result(None)
    } else {
        r.to_result(Some(raw_at))
    }
}

// Raw functions
#[link(name="pam")]
extern "C" {
    pub fn pam_set_item(pamh: PamHandle, item_type: c_int, item: *const c_void) -> c_int;
    pub fn pam_get_item(pamh: PamHandle, item_type: c_int, item: *mut *const c_void) -> c_int;
    pub fn pam_strerror(pamh: PamHandle, errnum: c_int) -> *const c_char;
    pub fn pam_putenv(pamh: PamHandle, name_value: *const c_char) -> c_int;
    pub fn pam_getenv(pamh: PamHandle, name: *const c_char) -> *const c_char;
    pub fn pam_getenvlist(pamh: PamHandle) -> *mut *mut c_char;

    pub fn pam_set_data(pamh: PamHandle,
                        module_data_name: *const c_char,
                        data: *mut c_void,
                        cleanup: Option<extern "C" fn (arg1: PamHandle,
                                                       arg2: *mut c_void,
                                                       arg3: c_int)>) -> c_int;
    pub fn pam_get_data(pamh: PamHandle, module_data_name: *const c_char,
                        data: *mut *const c_void) -> c_int;
    pub fn pam_get_user(pamh: PamHandle, user: *mut *const c_char, prompt: *const c_char) -> c_int;
    pub fn pam_get_authtok(pamh: PamHandle, item: c_int, authok_ptr: *mut *const c_char,
		 prompt: *const c_char) -> c_int;
}

