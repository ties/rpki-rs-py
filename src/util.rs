use chrono::{DateTime, Utc};
use rpki::repository::sigobj::SignedObject;

pub(crate) fn extract_signing_time(signed_object: &[u8]) -> Option<DateTime<Utc>> {
    match SignedObject::decode(signed_object, true) {
        Ok(signed_object) => Some(signed_object.signing_time().to_utc()),
        Err(_) => None,
    }
}
