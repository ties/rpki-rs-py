use chrono::{DateTime, Utc};
use num_bigint::BigInt;
use pyo3::prelude::*;
use rpki::repository::sigobj::SignedObject;

#[pyclass(frozen, eq, hash)]
#[derive(Clone, PartialEq, Hash)]
/// Represents a file in a RPKI manifest.
struct FileAndHash {
    /// The file name.
    #[pyo3(get)]
    file: String,
    /// The file hash.
    #[pyo3(get)]
    hash: Vec<u8>,
}

#[pymethods]
impl FileAndHash {
    fn __repr__(&self) -> String {
        let mut buf = [0u8; 256/4];
        let hex_str = rpki::util::hex::encode(&self.hash, &mut buf);
        format!("FileAndHash(file={}, hash={})", self.file, hex_str)
    }
}

/// Represents a RPKI manifest. Sample:
/// 
/// Subject key identifier:   0B:E6:AF:F6:EA:FE:D9:15:7B:40:63:BD:4F:F7:26:88:A3:FA:E3:06
/// Authority key identifier: 17:8D:D5:1D:7E:40:B3:4B:43:9F:8F:DF:4D:05:14:11:C5:34:72:EA
/// Certificate issuer:       /CN=178dd51d7e40b34b439f8fdf4d051411c53472ea
/// Certificate serial:       01973D2CAE6EBF4F7F4E5BE4CCAD29016604
/// Authority info access:    rsync://rpki.ripe.net/repository/DEFAULT/F43VHX5As0tDn4_fTQUUEcU0cuo.cer
/// Subject info access:      rsync://rpki.ripe.net/repository/DEFAULT/1b/876fc7-6552-4d41-89ae-87aa9d8772f3/1/F43VHX5As0tDn4_fTQUUEcU0cuo.mft
/// Manifest number:          033C
/// Signing time:             Wed 04 Jun 2025 23:00:27 +0100
/// Manifest this update:     Wed 04 Jun 2025 23:00:27 +0100
/// Manifest next update:     Thu 05 Jun 2025 23:00:27 +0100
/// Files and hashes:         1: F43VHX5As0tDn4_fTQUUEcU0cuo.crl (hash: V7e8KEOIOLS0abcZBUFNanWqhhrWh/xmpE1SaNHx8JE=)
///                           2: sY0r0y4AruQYBO-qa1jtodSMRJI.roa (hash: fgiZ0pPukyfp5f/cG9pJMs5XjY+lIWQ3prMocyZ72Vo=)
/// Validation:               Failed, unable to get local issuer certificate
#[pyclass(frozen, eq, hash, sequence)]
#[derive(PartialEq, Hash)]
struct Manifest {
    #[pyo3(get)]
    ski: Vec<u8>,
    #[pyo3(get)]
    aki: Option<Vec<u8>>,
    // skip the issuer: The issuer name is nested in a x509 structure, with rpki-rs not providing a tool to get just the CN.
    #[pyo3(get)]
    signing_time: Option<DateTime<Utc>>,
    #[pyo3(get)]
    this_update: DateTime<Utc>,
    #[pyo3(get)]
    next_update: DateTime<Utc>,

    #[pyo3(get)]
    aia: Option<String>,
    #[pyo3(get)]
    sia: Option<String>,

    #[pyo3(get)]
    manifest_number: BigInt,

    #[pyo3(get)]
    file_list: Vec<FileAndHash>,
}

#[pymethods]
impl Manifest {
    #[staticmethod]
    fn from_content(content: &[u8]) -> Option<Manifest> {
        let signing_time = match SignedObject::decode(content, false) {
            Ok(signed_object)  => signed_object.signing_time().map(|t| t.to_utc()),
            Err(_) => return None,
        };

        if let Ok(mft) = rpki::repository::Manifest::decode(content, false) {
            let cert = mft.cert();
            let ski = cert.subject_key_identifier().as_slice().to_vec();
            let aki = cert.authority_key_identifier().map(|aki| aki.as_slice().to_vec());

            let issuer_aia = cert.ca_issuer().map(|issuer| issuer.to_string());
            let mft_sia = cert.signed_object().map(|sia| sia.to_string());

            let manifest_number = BigInt::from_bytes_be(num_bigint::Sign::Plus, &mft.content().manifest_number().into_array());

            let file_list: Vec<FileAndHash> = mft.content().iter().map(|entry|
                FileAndHash {
                    // Convert &Bytes to String using std::str::from_utf8 and to_string
                    file: std::str::from_utf8(entry.file().as_ref())
                        .unwrap_or_default()
                        .to_string(),
                    hash: entry.hash().to_vec(),
            }).collect();


            return Some(Manifest {
                ski,
                aki,
                signing_time,
                this_update: mft.this_update().to_utc(),
                next_update: mft.next_update().to_utc(),
                aia: issuer_aia,
                sia: mft_sia,
                manifest_number,
                file_list,
            });
        }
        None
    }

    fn __len__(&self) -> usize {
        self.file_list.len()
    }

    fn __getitem__(&self, index: usize) -> PyResult<FileAndHash> {
        if index < self.file_list.len() {
            Ok(self.file_list[index].clone())
        } else {
            Err(pyo3::exceptions::PyIndexError::new_err("Index out of range"))
        }
    }
}


/// Extract the signing time from a CMS signed object.
#[pyfunction]
fn cms_signing_time(content: &[u8]) -> PyResult<Option<i64>> {
    // Placeholder for CMS signing time functionality
    if let Ok(signed_object) = SignedObject::decode(content, false) {
        match signed_object.signing_time() {
            Some(time) => return Ok(Some(time.timestamp())),
            None => return Ok(None),
        }
    }
    Ok(None)
}

/// A Python module implemented in Rust.
#[pymodule]
fn rpki_rs(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(cms_signing_time, m)?)?;
    m.add_class::<Manifest>()?;
    Ok(())
}
