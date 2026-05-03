use chrono::{DateTime, Utc};
use num_bigint::BigInt;
use pyo3::prelude::*;

#[pyclass(frozen, eq, hash, sequence)]
#[derive(PartialEq, Hash)]
pub struct Crl {
    #[pyo3(get)]
    this_update: DateTime<Utc>,
    #[pyo3(get)]
    next_update: DateTime<Utc>,

    #[pyo3(get)]
    object_serial: BigInt,
}

#[pymethods]
impl Crl {
    /// Creates and returns a CRL from raw content bytes.
    /// 
    /// # Arguments:
    /// 
    /// * `content` - the raw bytes of the CRL
    #[staticmethod]
    pub(crate) fn from_content(content: &[u8]) -> Option<Crl> {
        let crl = rpki::repository::Crl::decode(content)
            .ok()?;

        let object_serial = BigInt::from_bytes_be(num_bigint::Sign::Plus, &crl.crl_number().into_array());
        let this_update = crl.this_update().to_utc();
        let next_update = crl.next_update().to_utc();

        Some(Crl {
            this_update,
            next_update,

            object_serial,
        })
    }
}

