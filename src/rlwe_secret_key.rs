use pyo3::prelude::*;
use pyo3::exceptions::*;
use concrete;
use super::translate_error;

#[pyclass]
#[derive(Debug, PartialEq)]
pub struct RLWESecretKey {
    // pub val: GlweSecretKey<BinaryKeyKind, Vec<u64>> ,
    // pub polynomial_size: usize,
    // pub dimension: usize,
    // pub std_dev: f64,
    pub data: concrete::RLWEParams,
}

impl RLWESecretKey {
    #[getter]
    pub fn get_polynomial_size(&self) -> usize> {
        self.data.polynomial_size
    }

    #[setter]
    pub fn set_polynomial_size(&mut self, v: usize) {
        self.data.polynomial_size = v;
    }

    #[getter]
    pub fn get_dimension(&self) -> usize> {
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
    
    /// Generate a new secret key from an RLWEParams
    /// # Argument
    /// * `params` - an RLWEParams instance
    /// # Output
    /// * a new RLWESecretKey
    #[new]
    pub fn new(params: &crate::RLWEParams) -> RLWESecretKey {
        concrete::RLWESecretKey::new(params)
    }

    /// Generate a new secret key from a raw dimension (i.e. without a RLWEParams input)
    /// # Argument
    /// * `polynomial_size` - the size of the polynomial
    /// * `dimension` - the length the LWE mask
    /// # Output
    /// * a new RLWESecretKey
    #[staticmethod]
    pub fn new_raw(polynomial_size: usize, dimension: usize, std_dev: f64) -> RLWESecretKey {
        concrete::RLWESecretKey::new_raw(polynomial_size, dimension, std_dev)
    }

    /// Convert an RLWE secret key into an LWE secret key
    /// # Output
    /// * an LWE secret key
    pub fn to_lwe_secret_key(&self) -> crate::LWESecretKey {
        crate::LWESecretKey {
            data: concrete::LWESecretKey{
                val: LweSecretKey::binary_from_container(self.val.clone().into_tensor().into_container()),
                dimension: self.dimension * self.polynomial_size,
                std_dev: self.std_dev,
            }
        }
    }

    /// Return the variance of the error distribution associated with the secret key
    /// # Output
    /// * the variance
    pub fn get_variance(&self) -> f64 {
        f64::powi(self.data.std_dev, 2i32)
    }

    pub fn save(&self, path: &str) -> PyResult<()> {
        translate_error!(self.data.save(path))
    }

    #[staticmethod]
    pub fn load(path: &str) -> PyResult<RLWESecretKey> {
        let data = concrete::RLWESecretKey::load(path).unwrap();
        Ok(RLWESecretKey{ data })
    }

    pub fn __repr__(&self) -> String {
        self.data.to_string()
    }
}

pub fn register(_py: Python, m: &PyModule) -> PyResult<()> {
    m.add_class::<RLWESecretKey>()?;

    Ok(())
}

