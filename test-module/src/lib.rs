#[macro_use]
extern crate pamsm;
extern crate time;

use pamsm::{Pam, PamData, PamError, PamFlag, PamLibExt, PamServiceModule};

struct PamTime;

struct DateTime(time::OffsetDateTime);
struct Test {
    status: bool,
    hour: u8,
}

impl PamData for DateTime {
    fn cleanup(&mut self, _pam: Pam, flags: i32, status: PamError) {
        if (flags & PamFlag::PAM_SILENT as i32) == 0 {
            println!(
                "PamTime cleanup date time. Last authentication at {}, result {}, flags {}",
                self.0, status, flags
            );
            if (flags & PamFlag::PAM_DATA_REPLACE as i32) != 0 {
                println!("Pam data is being replaced");
            }
        }
    }
}

impl PamData for Test {
    fn cleanup(&mut self, _pam: Pam, flags: i32, status: PamError) {
        if (flags & PamFlag::PAM_SILENT as i32) == 0 {
            println!(
                "PamTime cleanup test. Last authentication at {}h : {}, result {}, flags {}",
                self.hour, self.status, status, flags
            );
        }
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

        // Only allow authentication when it's not 4 AM and user name is root
        let now = DateTime(time::OffsetDateTime::now_utc());
        let user = match pamh.get_user(None) {
            Ok(Some(u)) => u,
            Ok(None) => return PamError::USER_UNKNOWN,
            Err(e) => return e,
        };

        let hour = now.0.hour();
        match pamh.set_data("pamtime", Box::new(now)) {
            Err(e) => return e,
            Ok(_) => (),
        };

        let test = Test {
            status: hour != 4 && user.to_str().unwrap_or("") == "root",
            hour: hour,
        };

        let status = test.status;
        match pamh.set_data("pamtime", Box::new(test)) {
            Err(e) => return e,
            Ok(_) => (),
        };

        if status {
            PamError::SUCCESS
        } else {
            PamError::AUTH_ERR
        }
    }
}

pam_module!(PamTime);
