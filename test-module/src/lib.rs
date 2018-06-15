extern crate pamsm;
extern crate time;

use pamsm::{PamServiceModule, Pam};
use pamsm::pam_raw::{PamFlag, PamError};

struct PamTime;

impl PamServiceModule for PamTime {
    fn authenticate(self: &Self, pamh: Pam, _: PamFlag, args: Vec<String>) -> PamError {
        let hour = time::now().tm_hour;
        if hour != 4 {
            // Only allow authentication when it's 4 AM
            PamError::SUCCESS
        } else {
            PamError::AUTH_ERR
        }
    }
}

#[no_mangle]
pub extern "C" fn get_pam_sm() -> Box<PamServiceModule> {
    return Box::new(PamTime {});
}

pub fn main() {
}
