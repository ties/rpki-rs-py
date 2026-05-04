use chrono::{DateTime, Utc};
use num_bigint::BigInt;
use pyo3::prelude::*;

use crate::util::extract_signing_time;

#[pyclass(frozen, eq, hash, sequence)]
#[derive(PartialEq, Hash)]
pub struct Aspa {
    #[pyo3(get)]
    serial_number: BigInt,

    #[pyo3(get)]
    ski: Vec<u8>,
    #[pyo3(get)]
    aki: Option<Vec<u8>>,
    // skip the issuer: The issuer name is nested in a x509 structure, with rpki-rs not providing a tool to get just the CN.
    #[pyo3(get)]
    signing_time: DateTime<Utc>,

    #[pyo3(get)]
    not_before: DateTime<Utc>,
    #[pyo3(get)]
    not_after: DateTime<Utc>,

    #[pyo3(get)]
    customer_as: u32,
    #[pyo3(get)]
    providers: Vec<u32>,
}

#[pymethods]
impl Aspa {
    /// Creates and returns a parsed ASPA object from raw content bytes.
    ///
    /// # Arguments:
    ///
    /// * `content` - the raw bytes of the certificate
    #[staticmethod]
    pub(crate) fn from_content(content: &[u8]) -> Option<Aspa> {
        let aspa = rpki::repository::Aspa::decode(content, true).ok()?;

        let aspa_content = aspa.content();
        let cert = aspa.cert();

        let validity = cert.validity();
        let not_before = validity.not_before().to_utc();
        let not_after = validity.not_after().to_utc();

        let ski = cert.subject_key_identifier().as_slice().to_vec();
        let aki = cert
            .authority_key_identifier()
            .map(|a| a.as_slice().to_vec());

        let providers = aspa_content
            .provider_as_set()
            .iter()
            .map(|pa| pa.into_u32())
            .collect();
        let customer_as = aspa_content.customer_as().into_u32();

        Some(Aspa {
            serial_number: cert.serial_number().into(),
            ski,
            aki,

            signing_time: extract_signing_time(content)?,
            not_before,
            not_after,

            customer_as,
            providers,
        })
    }
}
