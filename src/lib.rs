// Copyright (C) 2016 Raphael Catolino
//! PAM Service Module wrappers
//! # Usage
//! For example, here is a time based authentication module :
//!
//! ```rust,no_run
//! #[macro_use] extern crate pamsm;
//! extern crate time;
//!
//! use pamsm::{PamServiceModule, Pam, PamFlag, PamError};
//!
//! struct PamTime;
//!
//! impl PamServiceModule for PamTime {
//!     fn authenticate(pamh: Pam, _: PamFlag, args: Vec<String>) -> PamError {
//!         let hour = time::now().tm_hour;
//!         if hour != 4 {
//!             // Only allow authentication when it's 4 AM
//!             PamError::SUCCESS
//!         } else {
//!             PamError::AUTH_ERR
//!         }
//!     }
//! }
//!
//! pam_module!(PamTime);
//! ```

extern crate libc;

mod pam;
pub mod pam_raw;
pub use self::pam::*;
pub use self::pam_raw::{PamFlag,PamError};

