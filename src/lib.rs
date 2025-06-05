use pyo3::prelude::*;
use rpki::repository::sigobj::SignedObject;

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
    return Ok(None)
}

/// A Python module implemented in Rust.
#[pymodule]
fn rpki_rs(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(cms_signing_time, m)?)?;
    Ok(())
}
