use pyo3::prelude::*;
use concrete;

// use concrete::LWEParams;
// use concrete::LWE128_630;

#[pyclass]
#[derive(Debug, Clone, PartialEq)]
pub struct LWEParams {
    // #[pyo3(get, set)]
    // pub dimension: usize,
    // #[pyo3(get, set)]
    // pub log2_std_dev: i32,
    pub data: concrete::lwe_params::LWEParams,
}

#[pymethods]
impl LWEParams {
    /// Instantiate a new LWEParams with the provided dimension and standard deviation
    /// # Arguments
    /// * `dimension` -the size of an LWE mask
    /// * `std_dev` -the standard deviation used for the error normal distribution
    /// # Output
    /// * a new instantiation of an LWEParams
    #[new]
    pub fn new(dimension: usize, log2_std_dev: i32) -> LWEParams {
        LWEParams {
            data: concrete::lwe_params::LWEParams {
                dimension,
                log2_std_dev,
            }
        }
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
    pub fn get_log2_std_dev(&self) -> i32 {
        self.data.log2_std_dev
    }

    #[setter]
    pub fn set_log2_std_dev(&mut self, v: i32) {
        self.data.log2_std_dev = v;
    }

    pub fn get_std_dev(&self) -> f64 {
        f64::powi(2., self.data.log2_std_dev)
    }

    pub fn save(&self, path: &str) -> PyResult<()> {
        self.data.save(path).expect("Failed in saving LWE paramter");
        Ok(())
    }

    #[staticmethod]
    pub fn load(path: &str) -> PyResult<LWEParams> {
        let data = concrete::lwe_params::LWEParams::load(path).unwrap();
        Ok(LWEParams{ data })
    }

    fn __repr__(&self) -> String {
        format!("{}", self.data)
    }
}

pub fn register(_py: Python, m: &PyModule) -> PyResult<()> {
    m.add_class::<LWEParams>()?;

    Ok(())
}

