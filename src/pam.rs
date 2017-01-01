pub use libc::{size_t};
pub use pam_sys::types::{PamFlag, PamReturnCode};

pub enum PamHandleInt {}
pub struct PamHandle(*mut PamHandleInt);

/// Default service module implementation
/// always returns SERVICE_ERR
/// You should override functions depending on what kind of module you implement
pub trait PamServiceModule {
    fn open_session(self: &Self, _: PamHandle, _: PamFlag,
                        _: size_t, _: *const u8) -> PamReturnCode {
        PamReturnCode::SERVICE_ERR
    }

    fn close_session(self: &Self, _: PamHandle, _: PamFlag,
                         _: size_t, _: *const u8) -> PamReturnCode {
        PamReturnCode::SERVICE_ERR
    }

    fn authenticate(self: &Self, _: PamHandle, _: PamFlag,
                        _: size_t, _: *const *const u8) -> PamReturnCode {
        PamReturnCode::SERVICE_ERR
    }

    fn setcred(self: &Self, _: PamHandle, _: PamFlag,
                   _: size_t, _: *const u8) -> PamReturnCode {
        PamReturnCode::SERVICE_ERR
    }

    fn acct_mgmt(self: &Self, _: PamHandle, _: PamFlag,
                     _: size_t, _: *const u8) -> PamReturnCode {
        PamReturnCode::SERVICE_ERR
    }

    fn chauthtok(self: &Self, _: PamHandle, _: PamFlag,
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

#[no_mangle]
pub extern "C" fn pam_sm_open_session(pamh: PamHandle, flags: PamFlag,
                           argc: size_t, argv: *const u8) -> PamReturnCode {
    println!("In pam_sm_open_session");
    return PAMSM.with(|sm| sm.open_session(pamh, flags, argc, argv));
}

#[no_mangle]
pub extern "C" fn pam_sm_close_session(pamh: PamHandle, flags: PamFlag,
                            argc: size_t, argv: *const u8) -> PamReturnCode {
    println!("In pam_sm_close_session");
    return PAMSM.with(|sm| sm.close_session(pamh, flags, argc, argv));
}

#[no_mangle]
pub extern "C" fn pam_sm_authenticate(pamh: PamHandle, flags: PamFlag,
                                      argc: size_t, argv: *const *const u8) -> PamReturnCode {
    println!("In pam_sm_authenticate");
    return PAMSM.with(|sm| sm.authenticate(pamh, flags, argc, argv));
}

#[no_mangle]
pub extern "C" fn pam_sm_setcred(pamh: PamHandle, flags: PamFlag,
                      argc: size_t, argv: *const u8) -> PamReturnCode {
    println!("In pam_sm_setcred");
    return PAMSM.with(|sm| sm.setcred(pamh, flags, argc, argv));
}

#[no_mangle]
pub extern "C" fn pam_sm_acct_mgmt(pamh: PamHandle, flags: PamFlag,
                        argc: size_t, argv: *const u8) -> PamReturnCode {
    println!("In pam_sm_acct_mgmt");
    return PAMSM.with(|sm| sm.acct_mgmt(pamh, flags, argc, argv));
}

#[no_mangle]
pub extern "C" fn pam_sm_chauthtok(pamh: PamHandle, flags: PamFlag,
                        argc: size_t, argv: *const u8) -> PamReturnCode {
    println!("In pam_sm_chauthtok");
    return PAMSM.with(|sm| sm.chauthtok(pamh, flags, argc, argv));
}

