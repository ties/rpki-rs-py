use std::str::FromStr;

use anyhow::{anyhow, bail};


use pyo3::{exceptions::PyValueError, prelude::*};
use rpki::repository::sigobj::SignedObject;

use crate::{manifest::Manifest, repository::RpkiObjectType};

mod repository;
mod manifest;

enum ParsedRpkiObject {
    Manifest(Manifest)
}

impl ParsedRpkiObject {
    fn into_py_any(self, py: Python<'_>) -> PyResult<Py<PyAny>> {
        match self {
            ParsedRpkiObject::Manifest(inner) => Ok(Py::new(py, inner)?.into()),
        }
    }
}

fn parse_blob(filename: &str, data: &[u8]) -> Result<ParsedRpkiObject, anyhow::Error> {
    let file_type = RpkiObjectType::from_str(filename)
        .map_err(|e| anyhow!(e))?;

    match file_type {
        RpkiObjectType::Manifest => Manifest::from_content(data).map(|m| ParsedRpkiObject::Manifest(m)).ok_or(anyhow!("Could not parse data.")),
        _ => bail!("Unsupported type")

    }
}

#[pyfunction]
fn parse(py: Python<'_>, filename: &str, data: &[u8]) -> PyResult<Py<PyAny>> {
    let parsed = parse_blob(filename, data)
        .map_err(|e| PyValueError::new_err(e.to_string()))?;

    parsed.into_py_any(py)
}


/// Extract the signing time from a CMS signed object.
#[pyfunction]
fn cms_signing_time(content: &[u8]) -> PyResult<Option<i64>> {
    // Placeholder for CMS signing time functionality
    if let Ok(signed_object) = SignedObject::decode(content, false) {
        return Ok(Some(signed_object.signing_time().timestamp()));
    }
    Ok(None)
}

/// A Python module implemented in Rust.
#[pymodule]
fn rpki_rs(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(cms_signing_time, m)?)?;
    m.add_function(wrap_pyfunction!(parse, m)?)?;
    m.add_class::<Manifest>()?;
    Ok(())
}
