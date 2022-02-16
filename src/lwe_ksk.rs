use pyo3::prelude::*;
use concrete;
// use super::{LWESecretKey};

#[pyclass]
#[derive(Debug, PartialEq)]
pub struct LWEKSK {
    // pub ciphertexts: crypto::lwe::LweKeyswitchKey<Vec<Torus>>,
    // pub base_log: usize,
    // pub level: usize,
    // pub dimension_before: usize,
    // pub dimension_after: usize,
    // pub variance: f64,
    pub data: concrete::LWEKSK,
}

#[pymethods]
impl LWEKSK {
    /// Generate an empty LWE key switching key
    ///
    /// # Argument
    /// * `sk_before` - an LWE secret key (input for the key switch)
    /// * `sk_after` - an LWE secret key (output for the key switch)
    /// * `base_log` - the log2 of the decomposition base
    /// * `level` - the number of levels of the decomposition
    ///
    /// # Output
    /// * an LWEKSK
    #[staticmethod]
    pub fn zero(
        sk_before: &crate::LWESecretKey,
        sk_after: &crate::LWESecretKey,
        base_log: usize,
        level: usize,
    ) -> LWEKSK {
        let data = concrete::LWEKSK::zero(&sk_before.data, &sk_after.data, base_log, level);
        LWEKSK{ data }
    }

    /// Generate a valid LWE key switching key
    /// # Argument
    /// * `sk_before` - an LWE secret key (input for the key switch)
    /// * `sk_after` - an LWE secret key (output for the key switch)
    /// * `base_log` - the log2 of the decomposition base
    /// * `level` - the number of levels of the decomposition
    ///
    /// # Output
    /// * an LWEKSK
    #[new]
    pub fn new(
        sk_before: &crate::LWESecretKey,
        sk_after: &crate::LWESecretKey,
        base_log: usize,
        level: usize,
    ) -> LWEKSK {
        let data = concrete::LWEKSK::new(&sk_before.data, &sk_after.data, base_log, level);
        LWEKSK{ data }
    }

    pub fn save(&self, path: &str) {
        self.data.save(path);
    }

    #[staticmethod]
    pub fn load(path: &str) -> crate::LWEKSK {
        let data = concrete::LWEKSK::load(path);
        LWEKSK{ data }
    }

    pub fn __repr__(&self) -> String {
        self.data.to_string()
    }
    
}

pub fn register(_py: Python, m: &PyModule) -> PyResult<()> {
    m.add_class::<LWEKSK>()?;

    Ok(())
}
