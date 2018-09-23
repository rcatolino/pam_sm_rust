#![allow(dead_code)]
#![allow(non_camel_case_types)]

use std::ptr;
use std::fmt;
use std::ptr::write_volatile;
use std::option::Option;
use std::os::raw::{c_char, c_int, c_uint, c_void};
use libc;

pub type PamHandle = *const c_uint;

pub enum PamMsgStyle {
    PROMPT_ECHO_OFF =1,	/* Ask for password without echo */
    PROMPT_ECHO_ON  =2,	/* Ask for password with echo */
    ERROR_MSG       =3,	/* Display an error message */
    TEXT_INFO       =4,	/* Display arbitrary text */
    // Linux extensions
    PAM_MAX_NUM_MSG =32,
    PAM_RADIO_TYPE  =5,       /* yes/no/maybe conditionals */
    PAM_BINARY_PROMPT   =7,
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
            fn new(r: i32) -> $name {
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

#[repr(C)]
pub struct PamMessage {
    pub msg_style: PamMsgStyle,
    pub msg: *const u8,
}

#[repr(C)]
pub struct PamResponse {
    pub resp: *mut c_char,
    pub resp_retcode: PamError,
}

impl PamResponse {
    pub fn get_buff(&self) -> *const c_char {
        self.resp as *const c_char
    }

    pub fn cleanup(&mut self) {
        unsafe {
            if ! self.resp.is_null() {
                for _ in 0..libc::strlen(self.resp) {
                    write_volatile(self.resp, 0i8);
                }
                libc::free(self.resp as *mut libc::c_void);
            }
            let asptr: *mut PamResponse = self;
            libc::free(asptr as *mut libc::c_void);
        }
    }
}


#[repr(C)]
pub struct PamConv {
    #[cfg_attr(feature = "cargo-clippy", allow(type_complexity))]
    pub cb: Option<extern "C" fn (arg1: c_int, arg2: *mut *const PamMessage,
                                  arg3: *mut *mut PamResponse, arg4: *mut c_void)
                                  -> c_int>,
    pub appdata_ptr: *mut c_void,
}
#[repr(C)]
pub enum LogLvl {
    EMERG	=0,	/* system is unusable */
    ALERT	=1,	/* action must be taken immediately */
    CRIT	=2,	/* critical conditions */
    ERR		=3,	/* error conditions */
    WARNING	=4,	/* warning conditions */
    NOTICE	=5,	/* normal but significant condition */
    INFO	=6,	/* informational */
    DEBUG	=7,	/* debug-level messages */
}

pub enum PamFlag {
    PAM_SILENT = 0x8000,
    PAM_DISALLOW_NULL_AUTHTOK = 0x0001,
    ESTABLISH_CRED = 0x0002,
    DELETE_CRED = 0x0004,
    REINITIALIZE_CRED = 0x0008,
    REFRESH_CRED = 0x0010,
    CHANGE_EXPIRED_AUTHTOK = 0x0020,
}

#[repr(C)]
pub enum PamItemType {
     SERVICE	    = 1,	/* The service name */
     USER               = 2,	/* The user name */
     TTY                = 3,	/* The tty name */
     RHOST              = 4,	/* The remote host name */
     CONV               = 5,	/* The pam_conv structure */
     AUTHTOK            = 6,	/* The authentication token (password) */
     OLDAUTHTOK         = 7,	/* The old authentication token */
     RUSER              = 8,	/* The remote user name */
     USER_PROMPT        = 9,    /* the prompt for getting a username */
     FAIL_DELAY         = 10,   /* app supplied function to override failure delays */
     XDISPLAY           = 11,   /* X display name */
     XAUTHDATA          = 12,   /* X server authentication data */
     AUTHTOK_TYPE       = 13,   /* The type for pam_get_authtok */
}

pub type PamResult<T> = Result<T, PamError>;

impl PamError {
    fn to_result<T>(self, ok: T) -> PamResult<T> {
        if self == PamError::SUCCESS {
            Ok(ok)
        } else {
            Err(self)
        }
    }
}

impl fmt::Display for PamError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

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

