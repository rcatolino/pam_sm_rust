#[macro_use]
extern crate pamsm;
extern crate rand;

use pamsm::{Pam, PamData, PamError, PamFlag, PamLibExt, PamServiceModule};
use rand::RngCore;
use std::fs::write;
use std::time::Instant;

struct PamTime;

#[derive(Debug, Clone)]
struct SessionStart(Instant);

impl PamData for SessionStart {
    fn cleanup(&self, _pam: Pam, flags: i32, status: PamError) {
        if (flags & PamFlag::SILENT as i32) == 0 {
            println!(
                "PamTime cleanup. Session opened for {:?}, result {}, flags {}",
                self.0.elapsed(),
                status,
                flags
            );
            if (flags & PamFlag::DATA_REPLACE as i32) != 0 {
                println!("Pam data is being replaced");
            }
        }
    }
}

impl PamServiceModule for PamTime {
    fn open_session(pamh: Pam, _flags: PamFlag, _args: Vec<String>) -> PamError {
        let now = SessionStart(Instant::now());
        if let Err(e) = unsafe { pamh.send_data("pamtime", now) } {
            return e;
        }

        let mut token = vec![0u8; 32];
        rand::thread_rng().fill_bytes(&mut token);
        let res = pamh.send_bytes(
            "pamtime_token",
            token,
            Some(|token, _, _, _| {
                if let Err(e) = write(".token.bin", token) {
                    println!("Error persisting token : {:?}", e);
                }
            }),
        );

        if let Err(e) = res {
            return e;
        }

        PamError::SUCCESS
    }

    fn close_session(_pamh: Pam, _flags: PamFlag, _args: Vec<String>) -> PamError {
        PamError::SUCCESS
    }

    fn authenticate(pamh: Pam, _flags: PamFlag, _args: Vec<String>) -> PamError {
        // If you need password here, that works like this:
        //
        //  let pass = match pamh.get_authtok(None) {
        //      Ok(Some(p)) => p,
        //      Ok(None) => return PamError::AUTH_ERR,
        //      Err(e) => return e,
        //  };

        // Only allow authentication when user name is root and the session is less than a minute
        // old
        let user = match pamh.get_user(None) {
            Ok(Some(u)) => u,
            Ok(None) => return PamError::USER_UNKNOWN,
            Err(e) => return e,
        };

        let s: SessionStart = match unsafe { pamh.retrieve_data("pamtime") } {
            Err(e) => return e,
            Ok(tref) => tref,
        };

        if user.to_str().unwrap_or("") == "root" && s.0.elapsed().as_secs() < 60 {
            PamError::SUCCESS
        } else {
            PamError::AUTH_ERR
        }
    }
}

pam_module!(PamTime);
