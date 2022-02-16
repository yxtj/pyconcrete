use pyo3::prelude::*;
use pyo3::exceptions::PyValueError;
use pyo3::types::{PyFunction};
use concrete;
use concrete::{Torus};
use super::{translate_error};//, LWESecretKey};

#[pyclass]
#[derive(Debug, PartialEq, Clone)]
pub struct LWEBSK {
    // pub ciphertexts: FourierBootstrapKey<AlignedVec<Complex64>,u64>,
    // pub variance: f64,
    // pub dimension: usize,
    // pub polynomial_size: usize,
    // pub base_log: usize,
    // pub level: usize,
    pub data: concrete::LWEBSK,
}

#[pymethods]
impl LWEBSK {

    #[getter]
    pub fn get_variance(&self) -> f64 {
        self.data.variance
    }

    #[setter]
    pub fn set_variance(&mut self, v: f64) {
        self.data.variance = v;
    }

    #[getter]
    pub fn get_dimension(&self) -> usize {
        self.data.dimension
    }

    #[setter]
    pub fn set_dimension(&mut self, v: usize) {
        self.data.dimension = v;
    }

    #[getter]
    pub fn get_polynomial_size(&self) -> usize {
        self.data.polynomial_size
    }

    #[setter]
    pub fn set_polynomial_size(&mut self, v: usize) {
        self.data.polynomial_size = v;
    }

    #[getter]
    pub fn get_base_log(&self) -> usize {
        self.data.base_log
    }

    #[setter]
    pub fn set_base_log(&mut self, v: usize) {
        self.data.base_log = v;
    }

    #[getter]
    pub fn get_level(&self) -> usize {
        self.data.level
    }

    #[setter]
    pub fn set_level(&mut self, v: usize) {
        self.data.level = v;
    }

    /// Return the dimension of an LWE we can bootstrap with this key
    pub fn get_lwe_dimension(&self) -> usize {
        self.data.get_lwe_dimension()
    }

    /// Return the log2 of the polynomial size of the RLWE involved in the bootstrap
    pub fn get_polynomial_size_log(&self) -> usize {
        self.data.get_polynomial_size_log()
    }

    /// Build a lookup table af a function from two encoders
    ///
    /// # Argument
    /// * `encoder_input` - the encoder of the input (of the bootstrap)
    /// * `encoder_output` - the encoder of the output (of the bootstrap)
    /// * `f` - a function
    ///
    /// # Output
    /// * a slice of Torus containing the lookup table
    // pub fn generate_functional_look_up_table<F: Fn(f64) -> f64>(
    //     &self,
    //     encoder_input: &crate::Encoder,
    //     encoder_output: &crate::Encoder,
    //     f: F,
    // ) -> PyResult<Vec<Torus>> {
    //     // TODO: func
    //     translate_error!(self.data.generate_functional_look_up_table(
    //         &encoder_input.data, &encoder_output.data, f))
    // }
    pub fn generate_functional_look_up_table(
        &self,
        encoder_input: &crate::Encoder,
        encoder_output: &crate::Encoder,
        f: &PyFunction,
    ) -> PyResult<Vec<Torus>> {
        let fun = |x| f.call1((x,)).unwrap().extract::<f64>().unwrap();
        translate_error!(self.data.generate_functional_look_up_table(
            &encoder_input.data, &encoder_output.data, fun))
    }

    /// Build a lookup table for the identity function from two encoders
    ///
    /// # Argument
    /// * `encoder_input` - the encoder of the input (of the bootstrap)
    /// * `encoder_output` - the encoder of the output (of the bootstrap)
    ///
    /// # Output
    /// * a slice of Torus containing the lookup table
    pub fn generate_identity_look_up_table(
        &self,
        encoder_input: &crate::Encoder,
        encoder_output: &crate::Encoder,
    ) -> PyResult<Vec<Torus>> {
        translate_error!(self.data.generate_identity_look_up_table(
            &encoder_input.data, &encoder_output.data))
    }

    /// Create a valid bootstrapping key
    ///
    /// # Argument
    /// * `sk_before` - an LWE secret key (input for the bootstrap)
    /// * `sk_after` - an LWE secret key (output for the bootstrap)
    /// * `base_log` - the log2 of the decomposition base
    /// * `level` - the number of levels of the decomposition
    ///
    /// # Output
    /// * an LWEBSK
    #[new]
    pub fn new(
        sk_input: &crate::LWESecretKey,
        sk_output: &crate::RLWESecretKey,
        base_log: usize,
        level: usize,
    ) -> LWEBSK {
        let data = concrete::LWEBSK::new(&sk_input.data, &sk_output.data, base_log, level);
        LWEBSK{ data }
    }

    /// Create an empty bootstrapping key
    ///
    /// # Argument
    /// * `sk_before` - an LWE secret key (input for the bootstrap)
    /// * `sk_after` - an LWE secret key (output for the bootstrap)
    /// * `base_log` - the log2 of the decomposition base
    /// * `level` - the number of levels of the decomposition
    ///
    /// # Output
    /// * an LWEBSK
    #[staticmethod]
    pub fn zero(
        sk_input: &crate::LWESecretKey,
        sk_output: &crate::RLWESecretKey,
        base_log: usize,
        level: usize,
    ) -> LWEBSK {
        let data = concrete::LWEBSK::zero(&sk_input.data, &sk_output.data, base_log, level);
        LWEBSK{ data }
    }

    pub fn save(&self, path: &str) {
        self.data.save(path);
    }

    #[staticmethod]
    pub fn load(path: &str) -> crate::LWEBSK {
        let data = concrete::LWEBSK::load(path);
        LWEBSK{ data }
    }

    pub fn __repr__(&self) -> String {
        self.data.to_string()
    }
}

pub fn register(_py: Python, m: &PyModule) -> PyResult<()> {
    m.add_class::<LWEBSK>()?;

    Ok(())
}

