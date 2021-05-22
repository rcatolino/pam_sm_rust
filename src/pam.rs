// Copyright (c) 2017 raphael.catolino@gmail.com

#![allow(non_camel_case_types)]

use pam_types::PamHandle;
use std::fmt;

/// Opaque PAM handle, with additional native methods available via `PamLibExt`.
pub struct Pam(pub(crate) PamHandle);

pub enum PamFlag {
    PAM_DATA_REPLACE = 0x2000_0000,
    PAM_SILENT = 0x8000,
    PAM_DISALLOW_NULL_AUTHTOK = 0x0001,
    ESTABLISH_CRED = 0x0002,
    DELETE_CRED = 0x0004,
    REINITIALIZE_CRED = 0x0008,
    REFRESH_CRED = 0x0010,
    CHANGE_EXPIRED_AUTHTOK = 0x0020,
}

impl fmt::Display for PamError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

macro_rules! i32_enum {
    ( $name:ident ($ukey:ident = $uvalue:expr) {
        $( $key:ident = $value:expr ),*
    }) => {
        #[derive(Clone, Copy, Debug, PartialEq)]
        pub enum $name {
            $( $key = $value, )*
            $ukey = $uvalue,
        }
        impl $name {
            #[cfg(feature = "libpam")]
            pub(crate) fn new(r: i32) -> $name {
                match r {
                    $( $value => $name::$key, )*
                    _ => $name::$ukey,
                }
            }
        }
    }
}

i32_enum! {
    PamError (UNKNOWN_RESULT = -1) {
        SUCCESS    = 0,		/* Successful function return */
        OPEN_ERR   = 1,		/* dlopen() failure when dynamically */
        SYMBOL_ERR     = 2,	/* Symbol not found */
        SERVICE_ERR    = 3,	/* Error in service module */
        SYSTEM_ERR     = 4,	/* System error */
        BUF_ERR    = 5,		/* Memory buffer error */
        PERM_DENIED    = 6,	/* Permission denied */
        AUTH_ERR   = 7,		/* Authentication failure */
        CRED_INSUFFICIENT  = 8,	/* Can not access authentication data */
        AUTHINFO_UNAVAIL   = 9,	/* Underlying authentication service can not retrieve authentication information  */
        USER_UNKNOWN   = 10,	/* User not known to the underlying authenticaiton module */
        MAXTRIES   = 11,		/* An authentication service has maintained a retry count which has been reached. No further retries should be attempted */
        NEW_AUTHTOK_REQD   = 12,	/* New authentication token required. */
        ACCT_EXPIRED   = 13,	/* User account has expired */
        SESSION_ERR    = 14,	/* Can not make/remove an entry for the specified session */
        CRED_UNAVAIL   = 15,	/* Underlying authentication service can not retrieve user credentials */
        CRED_EXPIRED   = 16,	/* User credentials expired */
        CRED_ERR   = 17,		/* Failure setting user credentials */
        NO_MODULE_DATA     = 18,	/* No module specific data is present */
        CONV_ERR   = 19,		/* Conversation error */
        AUTHTOK_ERR    = 20,	/* Authentication token manipulation error */
        AUTHTOK_RECOVERY_ERR   = 21, /* Authentication information cannot be recovered */
        AUTHTOK_LOCK_BUSY  = 22,   /* Authentication token lock busy */
        AUTHTOK_DISABLE_AGING  = 23, /* Authentication token aging disabled */
        TRY_AGAIN  = 24,	/* Preliminary check by password service */
        IGNORE     = 25,		/* Ignore underlying account module regardless of whether the control flag is required, optional, or sufficient */
        ABORT  = 26,            /* Critical error (?module fail now request) */
        AUTHTOK_EXPIRED    = 27, /* user's authentication token has expired */
        MODULE_UNKNOWN     = 28, /* module is not known */
        BAD_ITEM           = 29, /* Bad item passed to *_item() */
        CONV_AGAIN         = 30, /* conversation function is event driven and data is not available yet */
        INCOMPLETE         = 31 /* please call this function again to complete authentication stack. Before calling again, verify that conversation is completed */
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
        fn _check_pamsm_trait<T: pamsm::PamServiceModule>() {}
        fn _t() {
            _check_pamsm_trait::<$pamsm_ty>()
        }

        // Callback entry definition.
        macro_rules! pam_callback {
            ($pam_cb:ident, $rust_cb:ident) => {
                #[no_mangle]
                #[doc(hidden)]
                pub unsafe extern "C" fn $pam_cb(
                    pamh: pamsm::Pam,
                    flags: pamsm::PamFlag,
                    argc: usize,
                    argv: *const *const u8,
                ) -> pamsm::PamError {
                    use std::ffi::CStr;
                    use std::os::raw::c_char;

                    let mut args = Vec::<String>::with_capacity(argc);
                    for count in 0..(argc as isize) {
                        match { CStr::from_ptr(*argv.offset(count) as *const c_char).to_str() } {
                            Ok(s) => args.push(s.to_owned()),
                            Err(_) => return pamsm::PamError::SERVICE_ERR,
                        };
                    }
                    <$pamsm_ty>::$rust_cb(pamh, flags, args)
                }
            };
        }

        pam_callback!(pam_sm_open_session, open_session);
        pam_callback!(pam_sm_close_session, close_session);
        pam_callback!(pam_sm_authenticate, authenticate);
        pam_callback!(pam_sm_setcred, setcred);
        pam_callback!(pam_sm_acct_mgmt, acct_mgmt);
        pam_callback!(pam_sm_chauthtok, chauthtok);
    };
}
