use chrono::{DateTime, Utc};
use num_bigint::BigInt;
use pyo3::prelude::*;

#[pyclass(frozen, eq, hash, sequence)]
#[derive(PartialEq, Hash)]
pub struct Cert {
    #[pyo3(get)]
    serial_number: BigInt,

    #[pyo3(get)]
    not_before: DateTime<Utc>,
    #[pyo3(get)]
    not_after: DateTime<Utc>,
}

#[pymethods]
impl Cert {
    /// Creates and returns a Cert from raw content bytes.
    ///
    /// # Arguments:
    ///
    /// * `content` - the raw bytes of the certificate
    #[staticmethod]
    pub(crate) fn from_content(content: &[u8]) -> Option<Cert> {
        let cert = rpki::repository::Cert::decode(content).ok()?;

        let validity = cert.validity();
        let not_before = validity.not_before().to_utc();
        let not_after = validity.not_after().to_utc();

        Some(Cert {
            serial_number: cert.serial_number().into(),

            not_before,
            not_after,
        })
    }
}
