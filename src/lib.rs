// Copyright (C) 2016 Raphael Catolino
//! PAM Service Module wrappers
//! # Usage
//! For example, here is a time based authentication module :
//!
//! ```
//! extern crate pamsm;
//! extern crate time;
//!
//! use pamsm::{PamServiceModule, Pam, PamFlag, PamReturnCode};
//!
//! struct PamTime;
//!
//! impl PamServiceModule for PamTime {
//!     fn authenticate(self: &Self, pamh: Pam, _: PamFlag, args: Vec<String>) -> PamReturnCode {
//!         let hour = time::now().tm_hour;
//!         if hour != 4 {
//!             // Only allow authentication when it's 4 AM
//!             PamReturnCode::SUCCESS;
//!         } else {
//!             PamReturnCode::AUTH_ERR;
//!         }
//!     }
//! }
//!
//! #[no_mangle]
//! pub extern "C" fn get_pam_sm() -> Box<PamServiceModule> {
//!     return Box::new(PamTime {});
//! }
//! ```

extern crate pam_sys;
extern crate libc;

mod pam;
pub use self::pam::*;
