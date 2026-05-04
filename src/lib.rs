use std::str::FromStr;

use anyhow::{anyhow, bail};


use pyo3::{exceptions::PyValueError, prelude::*};
use rpki::repository::sigobj::SignedObject;

use crate::{aspa::Aspa, cert::Cert, crl::Crl, manifest::Manifest, repository::RpkiObjectType, util::extract_signing_time};

mod repository;

mod aspa;
mod crl;
mod cert;
mod manifest;
mod roa;
mod util;

enum ParsedRpkiObject {
    Aspa(Aspa),
    Manifest(Manifest),
    Crl(Crl),
    Certificate(Cert),
}

impl ParsedRpkiObject {
    fn into_py_any(self, py: Python<'_>) -> PyResult<Py<PyAny>> {
        match self {
            ParsedRpkiObject::Aspa(inner) => Ok(Py::new(py, inner)?.into()),
            ParsedRpkiObject::Certificate(inner) => Ok(Py::new(py, inner)?.into()),
            ParsedRpkiObject::Crl(inner) => Ok(Py::new(py, inner)?.into()),
            ParsedRpkiObject::Manifest(inner) => Ok(Py::new(py, inner)?.into()),
        }
    }
}

/// Parse the `data` as an RPKI object with the given name.
/// 
/// # Arguments
/// 
/// * `filename` - name of the file.
/// * `data` - content of the file.
/// 
fn parse_blob(filename: &str, data: &[u8]) -> Result<ParsedRpkiObject, anyhow::Error> {
    let file_type = RpkiObjectType::from_str(filename)
        .map_err(|e| anyhow!(e))?;

    match file_type {
        RpkiObjectType::Aspa => Aspa::from_content(data).map(|a| ParsedRpkiObject::Aspa(a)).ok_or(anyhow!("Could not parse ASPA")),
        RpkiObjectType::Cert => Cert::from_content(data).map(|cert| ParsedRpkiObject::Certificate(cert)).ok_or(anyhow!("Could not parse certificate")),
        RpkiObjectType::Crl => Crl::from_content(data).map(|c| ParsedRpkiObject::Crl(c)).ok_or(anyhow!("Could not parse crl")),
        RpkiObjectType::Manifest => Manifest::from_content(data).map(|m| ParsedRpkiObject::Manifest(m)).ok_or(anyhow!("Could not parse manifest")),
        _ => bail!("Unsupported type")

    }
}

#[pyfunction]
fn parse(py: Python<'_>, filename: &str, data: &[u8]) -> PyResult<Py<PyAny>> {
    let parsed = parse_blob(filename, data)
        .map_err(|e| PyValueError::new_err(e.to_string()))?;

    parsed.into_py_any(py)
}


/// Returns the signing time from a CMS signed object.
/// 
/// # Arguments
/// 
/// * `content` - The raw CMS content
#[pyfunction]
fn cms_signing_time(content: &[u8]) -> PyResult<Option<i64>> {
    Ok(extract_signing_time(content).map(|st| st.timestamp()))
}

/// A Python module implemented in Rust.
#[pymodule]
fn rpki_rs(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(cms_signing_time, m)?)?;
    m.add_function(wrap_pyfunction!(parse, m)?)?;
    m.add_class::<Manifest>()?;
    Ok(())
}
