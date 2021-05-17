#[macro_use]
extern crate pamsm;
extern crate time;

use std::ops::Deref;
use pamsm::{PamServiceModule, PamData, PamLibExt, Pam, PamFlag, PamError};

struct PamTime;

struct DateTime(time::OffsetDateTime);

impl PamData for DateTime {
    fn cleanup(&mut self, _pam: Pam, flags: i32, status: PamError) {
        if (flags & PamFlag::PAM_SILENT as i32) != 0 {
            println!("PamTime cleanup. Last authentication at {}, result {}", self.0, status);
        }
    }
}

impl DateTime {
    fn now() -> Self {
        DateTime(time::OffsetDateTime::try_now_local().unwrap_or(time::OffsetDateTime::now_utc()))
    }
}

impl Deref for DateTime {
    type Target = time::OffsetDateTime;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl PamServiceModule for PamTime {
    fn authenticate(pamh: Pam, _flags: PamFlag, _args: Vec<String>) -> PamError {

        // If you need password here, that works like this:
        //
        //  let pass = match pamh.get_authtok(None) {
        //      Ok(Some(p)) => p,
        //      Ok(None) => return PamError::AUTH_ERR,
        //      Err(e) => return e,
        //  };

        // Only allow authentication when it's 4 AM and user name is root
        let now = DateTime::now();
        let user = match pamh.get_user(None) {
            Ok(Some(u)) => u,
            Ok(None) => return PamError::USER_UNKNOWN,
            Err(e) => return e,
        };

        let hour = now.hour();
        match pamh.set_data("pamtime", Box::new(now)) {
            Err(e) => return e,
            Ok(_) => (),
        };

        if hour != 4 && user.to_str().unwrap_or("") == "root" {
            PamError::SUCCESS
        } else {
            PamError::AUTH_ERR
        }
    }
}

pam_module!(PamTime);
