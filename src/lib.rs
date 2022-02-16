use pyo3::prelude::*;
#[allow(unused_imports)]
use pyo3::exceptions::PyValueError;
// use pyo3::{wrap_pyfunction, wrap_pymodule};
// use pyo3::wrap_pymodule;

// #[warn(unused_imports)]
// use concrete::*;

// pub_mod_use!(lwe_ksk);
// pub_mod_use!(lwe_bsk);
// pub_mod_use!(lwe_secret_key);
// pub_mod_use!(rlwe_params);
// pub_mod_use!(rlwe_secret_key);

pub mod lwe_params;
pub use lwe_params::LWEParams;
pub mod encoder;
pub use encoder::Encoder;
// pub_mod_use!(lwe);
pub mod plaintext;
pub use plaintext::Plaintext;
// pub_mod_use!(vector_rlwe);
// pub_mod_use!(vector_lwe);
// pub mod lwe_secret_key;
// pub use lwe_secret_key::LWESecretKey;
// pub mod rlwe_params;
// pub use rlwe_params::RLWEParams;
// pub mod rlwe_secret_key;
// pub use rlwe_secret_key::RLWESecretKey;


#[macro_export]
macro_rules! translate_error {
    ( $x: expr ) => {
        match $x {
            Ok(v) => Ok(v),
            Err(e) => Err(PyValueError::new_err(e.to_string())),
        }
    };
}

#[pymodule]
fn pyconcrete(py: Python, m: &PyModule) -> PyResult<()> {
    // m.add_wrapped(wrap_pyfunction!(encode_test))?;
    // m.add_wrapped(wrap_pyfunction!(lwe_params))?;
    lwe_params::register(py, m)?;
    encoder::register(py, m)?;
    // plaintext::register(py, m)?;


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
