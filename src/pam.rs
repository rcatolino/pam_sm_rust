pub use libc::{c_void, size_t};
pub use pam_sys::types::{PamFlag, PamReturnCode};
use pam_sys::types::{PamHandle, PamItemType};
use pam_sys::wrapped::{get_item};
use std::os::raw::c_char;
use std::ptr;
use std::ffi::CStr;

pub struct Pam(*mut PamHandle);

// Pam functions
impl Pam {
    unsafe fn get_item(&self, item_type: PamItemType) -> Result<Option<*const c_void>, PamReturnCode> {
        let mut raw_item : *const c_void = ptr::null();
        let result = get_item(self.0, item_type, &mut raw_item);
        if result == PamReturnCode::SUCCESS && !raw_item.is_null() {
            Ok(Some(raw_item))
        } else if result == PamReturnCode::SUCCESS && raw_item.is_null() {
            Ok(None)
        } else {
            Err(result)
        }
    }

    pub fn get_authtok<'a>(&self) -> Result<Option<&'a CStr>, PamReturnCode> {
        // Pam should keep the underlying token allocated for as long as the module is loaded
        // which make this safe
        unsafe {
            let pointer = try!(self.get_item(PamItemType::AUTHTOK));
            Ok(pointer.map(|p| CStr::from_ptr(p as *const c_char)))
        }
    }

    /*
    pub fn set_item(&self, item_type: PamItemType, item: *const c_void) -> PamReturnCode {
    }
    */
}

/// Default service module implementation
/// always returns SERVICE_ERR
/// You should override functions depending on what kind of module you implement
pub trait PamServiceModule {
    fn open_session(self: &Self, _: Pam, _: PamFlag,
                        _: size_t, _: *const u8) -> PamReturnCode {
        PamReturnCode::SERVICE_ERR
    }

    fn close_session(self: &Self, _: Pam, _: PamFlag,
                         _: size_t, _: *const u8) -> PamReturnCode {
        PamReturnCode::SERVICE_ERR
    }

    fn authenticate(self: &Self, _: Pam, _: PamFlag,
                        _: size_t, _: *const *const u8) -> PamReturnCode {
        PamReturnCode::SERVICE_ERR
    }

    fn setcred(self: &Self, _: Pam, _: PamFlag,
                   _: size_t, _: *const u8) -> PamReturnCode {
        PamReturnCode::SERVICE_ERR
    }

    fn acct_mgmt(self: &Self, _: Pam, _: PamFlag,
                     _: size_t, _: *const u8) -> PamReturnCode {
        PamReturnCode::SERVICE_ERR
    }

    fn chauthtok(self: &Self, _: Pam, _: PamFlag,
                     _: size_t, _: *const u8) -> PamReturnCode {
        PamReturnCode::SERVICE_ERR
    }
}

/// You have to implement a get_pam_sm function that returns a boxed PamServiceModule
/// implementation
#[allow(improper_ctypes)]
extern {
    #[no_mangle]
    fn get_pam_sm() -> Box<PamServiceModule>;
}

thread_local! {
    static PAMSM: Box<PamServiceModule> = unsafe { get_pam_sm() };
}

// Pam Callbacks
#[no_mangle]
pub extern "C" fn pam_sm_open_session(pamh: Pam, flags: PamFlag,
                           argc: size_t, argv: *const u8) -> PamReturnCode {
    return PAMSM.with(|sm| sm.open_session(pamh, flags, argc, argv));
}

#[no_mangle]
pub extern "C" fn pam_sm_close_session(pamh: Pam, flags: PamFlag,
                            argc: size_t, argv: *const u8) -> PamReturnCode {
    return PAMSM.with(|sm| sm.close_session(pamh, flags, argc, argv));
}

#[no_mangle]
pub extern "C" fn pam_sm_authenticate(pamh: Pam, flags: PamFlag,
                                      argc: size_t, argv: *const *const u8) -> PamReturnCode {
    return PAMSM.with(|sm| sm.authenticate(pamh, flags, argc, argv));
}

#[no_mangle]
pub extern "C" fn pam_sm_setcred(pamh: Pam, flags: PamFlag,
                      argc: size_t, argv: *const u8) -> PamReturnCode {
    return PAMSM.with(|sm| sm.setcred(pamh, flags, argc, argv));
}

#[no_mangle]
pub extern "C" fn pam_sm_acct_mgmt(pamh: Pam, flags: PamFlag,
                        argc: size_t, argv: *const u8) -> PamReturnCode {
    return PAMSM.with(|sm| sm.acct_mgmt(pamh, flags, argc, argv));
}

#[no_mangle]
pub extern "C" fn pam_sm_chauthtok(pamh: Pam, flags: PamFlag,
                        argc: size_t, argv: *const u8) -> PamReturnCode {
    return PAMSM.with(|sm| sm.chauthtok(pamh, flags, argc, argv));
}

