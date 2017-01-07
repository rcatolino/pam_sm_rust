pub use pam_sys::types::{PamFlag, PamReturnCode};
use libc::{c_void, size_t};
use pam_sys::types::{PamHandle, PamItemType};
use pam_sys::wrapped::{get_item};
use std::os::raw::c_char;
use std::ptr;
use std::ffi::CStr;
use std::str::Utf8Error;

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
    fn open_session(self: &Self, _: Pam, _: PamFlag, _: Vec<String>) -> PamReturnCode {
        PamReturnCode::SERVICE_ERR
    }

    fn close_session(self: &Self, _: Pam, _: PamFlag, _: Vec<String>) -> PamReturnCode {
        PamReturnCode::SERVICE_ERR
    }

    fn authenticate(self: &Self, _: Pam, _: PamFlag, _: Vec<String>) -> PamReturnCode {
        PamReturnCode::SERVICE_ERR
    }

    fn setcred(self: &Self, _: Pam, _: PamFlag, _: Vec<String>) -> PamReturnCode {
        PamReturnCode::SERVICE_ERR
    }

    fn acct_mgmt(self: &Self, _: Pam, _: PamFlag, _: Vec<String>) -> PamReturnCode {
        PamReturnCode::SERVICE_ERR
    }

    fn chauthtok(self: &Self, _: Pam, _: PamFlag, _: Vec<String>) -> PamReturnCode {
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
        pub extern "C" fn $pam_cb(pamh: Pam, flags: PamFlag,
                                   argc: size_t, argv: *const *const u8) -> PamReturnCode {
            match unsafe { extract_args(argc, argv) } {
                Ok(args) => PAMSM.with(|sm| sm.$rust_cb(pamh, flags, args)),
                Err(_) => PamReturnCode::SERVICE_ERR,
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

