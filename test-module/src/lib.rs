#[macro_use]
extern crate pamsm;
extern crate time;

use pamsm::{PamServiceModule, PamLibExt, Pam, PamFlag, PamError};

struct PamTime;

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
        let hour = time::now().tm_hour;
        let user = match pamh.get_user(None) {
            Ok(Some(u)) => u,
            Ok(None) => return PamError::USER_UNKNOWN,
            Err(e) => return e,
        };

        if hour != 4 && user.to_str().unwrap_or("") == "root" {
            PamError::SUCCESS
        } else {
            PamError::AUTH_ERR
        }
    }
}

pam_module!(PamTime);
