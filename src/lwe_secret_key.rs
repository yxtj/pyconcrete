use pyo3::prelude::*;
use pyo3::exceptions::*;
use concrete;
use super::translate_error;

#[pyclass]
#[derive(Debug, PartialEq, Clone)]
pub struct LWESecretKey {
    // pub val: LweSecretKey<BinaryKeyKind, Vec<u64>>,
    // pub dimension: usize,
    // pub std_dev: f64,
    pub data: concrete::LWESecretKey,
}

#[pymethods]
impl LWESecretKey {
    #[getter]
    pub fn get_dimension(&self) -> usize {
        self.data.dimension
    }

    #[setter]
    pub fn set_dimension(&mut self, v: usize) {
        self.data.dimension = v;
    }

    #[getter]
    pub fn get_std_dev(&self) -> f64 {
        self.data.std_dev
    }

    #[setter]
    pub fn set_std_dev(&mut self, v: f64) {
        self.data.std_dev = v;
    }

    /// Generate a new secret key from an LWEParams
    /// # Argument
    /// * `p` - an LWEParams instance
    /// # Output
    /// * a new LWESecretKey
    #[new]
    pub fn new(params: &crate::LWEParams) -> LWESecretKey {
        concrete::LWESecretKey::new(params)
    }

    /// Generate a new secret key from a raw dimension (i.e. without a LWEParams input)
    /// # Argument
    /// * `dimension` s the length the LWE mask
    /// * `std_dev` - the standard deviation for the encryption
    /// # Output
    /// * a new LWESecretKey
    #[staticmethod]
    pub fn new_raw(dimension: usize, std_dev: f64) -> LWESecretKey {
        concrete::LweSecretKey::new_raw(dimension, std_dev)
    }

    /// Convert an LWE secret key into an RLWE secret key
    /// # Input
    /// * `polynomial_size` - the size of the polynomial of the output RLWE secret key
    /// # Output
    /// * an RLWE secret key
    pub fn to_rlwe_secret_key(
        &self,
        polynomial_size: usize,
    ) -> PyResult<crate::RLWESecretKey> {
        translate_error!(self.data.to_rlwe_secret_key(usize))
    }

    /// Return the variance of the error distribution associated with the secret key
    /// # Output
    /// * a variance
    pub fn get_variance(&self) -> f64 {
        f64::powi(self.data.std_dev, 2i32)
    }

    pub fn save(&self, path: &str) -> PyResult<()> {
        translate_error!(self.data.save(path))
    }

    #[staticmethod]
    pub fn load(path: &str) -> PyResult<LWESecretKey> {
        let data = concrete::LWESecretKey::load(path).unwrap();
        Ok(LWESecretKey{ data })
    }

    pub fn __repr__(&self) -> String {
        self.data.to_string()
    }
}

pub fn register(_py: Python, m: &PyModule) -> PyResult<()> {
    m.add_class::<LWESecretKey>()?;

    Ok(())
}
