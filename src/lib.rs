use pyo3::prelude::*;
#[allow(unused_imports)]
use pyo3::exceptions::PyValueError;
// use pyo3::{wrap_pyfunction, wrap_pymodule};
// use pyo3::wrap_pymodule;

// #[warn(unused_imports)]
// use concrete::*;

pub mod encoder;
pub use encoder::Encoder;
pub mod plaintext;
pub use plaintext::Plaintext;

pub mod lwe_params;
pub use lwe_params::LWEParams;
pub mod lwe_secret_key;
pub use lwe_secret_key::LWESecretKey;
pub mod rlwe_params;
pub use rlwe_params::RLWEParams;
pub mod rlwe_secret_key;
pub use rlwe_secret_key::RLWESecretKey;

pub mod lwe_ksk;
pub use lwe_ksk::LWEKSK;
pub mod lwe_bsk;
pub use lwe_bsk::LWEBSK;

pub mod lwe;
pub use lwe::LWE;
pub mod vector_lwe;
pub use vector_lwe::VectorLWE;
pub mod vector_rlwe;
pub use vector_rlwe::VectorRLWE;


#[macro_export]
macro_rules! translate_error {
    ( $x: expr ) => {
        match $x {
            Ok(v) => Ok(v),
            Err(e) => Err(PyValueError::new_err(e.to_string())),
        }
    };
}

pub(crate) fn helper_is_int(value: f64) -> bool {
    let ivalue = value as i32;
    let remainder = value - ivalue as f64;
    return remainder == 0.0;
}


#[pymodule]
fn pyconcrete(py: Python, m: &PyModule) -> PyResult<()> {
    // m.add_wrapped(wrap_pyfunction!(encode_test))?;
    // m.add_wrapped(wrap_pyfunction!(lwe_params))?;
    encoder::register(py, m)?;
    plaintext::register(py, m)?;

    lwe_params::register(py, m)?;
    lwe_params::register(py, m)?;
    lwe_secret_key::register(py, m)?;
    rlwe_params::register(py, m)?;
    rlwe_secret_key::register(py, m)?;

    lwe_ksk::register(py, m)?;
    lwe_bsk::register(py, m)?;
    
    lwe::register(py, m)?;
    vector_lwe::register(py, m)?;
    vector_rlwe::register(py, m)?;

    Ok(())
}


// macro_rules! pub_mod_use {
//     ($I:ident) => {
//         pub mod $I;
//         pub use $I::*;
//     };
// }
// #[macro_use]
// pub mod error;
// pub_mod_use!(lwe_params);
// pub_mod_use!(encoder);
// pub_mod_use!(lwe);
// pub_mod_use!(plaintext);
// pub_mod_use!(vector_rlwe);
// pub_mod_use!(vector_lwe);
// pub_mod_use!(lwe_ksk);
// pub_mod_use!(lwe_bsk);
// pub_mod_use!(lwe_secret_key);
// pub_mod_use!(rlwe_params);
// pub_mod_use!(rlwe_secret_key);
