use chrono::{DateTime, Utc};
use num_bigint::BigInt;
use pyo3::prelude::*;

#[pyclass(skip_from_py_object, frozen, eq, hash, sequence)]
#[derive(Clone, PartialEq, Hash)]
pub struct RevokedCertificate {
    #[pyo3(get)]
    serial_number: BigInt,

    #[pyo3(get)]
    revocation_date: DateTime<Utc>,
}

#[pymethods]
impl RevokedCertificate {
    #[new]
    fn new(serial_number: BigInt, revocation_date: DateTime<Utc>) -> Self {
        Self {
            serial_number,
            revocation_date,
        }
    }

    fn __repr__(&self) -> String {
        format!(
            "Serial: {} Revocation Date: {}",
            self.serial_number, self.revocation_date
        )
    }
}

#[pyclass(frozen, eq, hash, sequence)]
#[derive(PartialEq, Hash)]
pub struct Crl {
    #[pyo3(get)]
    crl_number: BigInt,

    #[pyo3(get)]
    this_update: DateTime<Utc>,
    #[pyo3(get)]
    next_update: DateTime<Utc>,

    #[pyo3(get)]
    revoked_certificates: Vec<RevokedCertificate>,
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
        let crl = rpki::repository::Crl::decode(content).ok()?;

        let revoked_certificates = crl
            .as_cert_list()
            .revoked_certs()
            .iter()
            .map(|revoked| RevokedCertificate {
                serial_number: revoked.user_certificate.into(),
                revocation_date: revoked.revocation_date.to_utc(),
            })
            .collect();

        Some(Crl {
            crl_number: crl.crl_number().into(),

            this_update: crl.this_update().to_utc(),
            next_update: crl.next_update().to_utc(),

            revoked_certificates,
        })
    }
}
