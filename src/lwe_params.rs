use pyo3::prelude::*;
use pyo3::exceptions::*;
use concrete;
use super::translate_error;

#[pyclass]
#[derive(Debug, Clone, PartialEq)]
pub struct LWEParams {
    // #[pyo3(get, set)]
    // pub dimension: usize,
    // #[pyo3(get, set)]
    // pub log2_std_dev: i32,
    pub data: concrete::lwe_params::LWEParams,
}

/*
//////////////////////////
// 128 bits of security //
//////////////////////////

/// 128 bits of security with a dimension of 256 (LWE estimator, September 15th 2020)
pub const LWE128_256: LWEParams = LWEParams {
    dimension: 256,
    log2_std_dev: -5,
};

/// 128 bits of security with a dimension of 512 (LWE estimator, September 15th 2020)
pub const LWE128_512: LWEParams = LWEParams {
    dimension: 512,
    log2_std_dev: -11,
};

/// 128 bits of security with a dimension of 630 (LWE estimator, September 15th 2020)
pub const LWE128_630: LWEParams = LWEParams {
    dimension: 630,
    log2_std_dev: -14,
};

/// 128 bits of security with a dimension of 650 (LWE estimator, September 15th 2020)
pub const LWE128_650: LWEParams = LWEParams {
    dimension: 650,
    log2_std_dev: -15,
};

/// 128 bits of security with a dimension of 688 (LWE estimator, September 15th 2020)
pub const LWE128_688: LWEParams = LWEParams {
    dimension: 688,
    log2_std_dev: -16,
};

/// 128 bits of security with a dimension of 710 (LWE estimator, September 15th 2020)
pub const LWE128_710: LWEParams = LWEParams {
    dimension: 710,
    log2_std_dev: -17,
};

/// 128 bits of security with a dimension of 750 (LWE estimator, September 15th 2020)
pub const LWE128_750: LWEParams = LWEParams {
    dimension: 750,
    log2_std_dev: -18,
};

/// 128 bits of security with a dimension of 800 (LWE estimator, September 15th 2020)
pub const LWE128_800: LWEParams = LWEParams {
    dimension: 800,
    log2_std_dev: -19,
};

/// 128 bits of security with a dimension of 830 (LWE estimator, September 15th 2020)
pub const LWE128_830: LWEParams = LWEParams {
    dimension: 830,
    log2_std_dev: -20,
};

/// 128 bits of security with a dimension of 1024 (LWE estimator, September 15th 2020)
pub const LWE128_1024: LWEParams = LWEParams {
    dimension: 1024,
    log2_std_dev: -25,
};

/// 128 bits of security with a dimension of 2048 (LWE estimator, September 15th 2020)
pub const LWE128_2048: LWEParams = LWEParams {
    dimension: 2048,
    log2_std_dev: -52, // warning u32
};

/// 128 bits of security with a dimension of 4096 (LWE estimator, September 15th 2020)
pub const LWE128_4096: LWEParams = LWEParams {
    dimension: 4096,
    log2_std_dev: -105, // warning u64
};

////////////////////////////////////////////////////
//                80 bits of security             //
////////////////////////////////////////////////////

/// 80 bits of security with a dimension of 256 (LWE estimator, September 15th 2020)
pub const LWE80_256: LWEParams = LWEParams {
    dimension: 256,
    log2_std_dev: -9,
};

/// 80 bits of security with a dimension of 512 (LWE estimator, September 15th 2020)
pub const LWE80_512: LWEParams = LWEParams {
    dimension: 512,
    log2_std_dev: -19,
};

/// 80 bits of security with a dimension of 630 (LWE estimator, September 15th 2020)
pub const LWE80_630: LWEParams = LWEParams {
    dimension: 630,
    log2_std_dev: -24,
};

/// 80 bits of security with a dimension of 650 (LWE estimator, September 15th 2020)
pub const LWE80_650: LWEParams = LWEParams {
    dimension: 650,
    log2_std_dev: -25,
};

/// 80 bits of security with a dimension of 688 (LWE estimator, September 15th 2020)
pub const LWE80_688: LWEParams = LWEParams {
    dimension: 688,
    log2_std_dev: -26,
};

/// 80 bits of security with a dimension of 710 (LWE estimator, September 15th 2020)
pub const LWE80_710: LWEParams = LWEParams {
    dimension: 710,
    log2_std_dev: -27,
};

/// 80 bits of security with a dimension of 750 (LWE estimator, September 15th 2020)
pub const LWE80_750: LWEParams = LWEParams {
    dimension: 750,
    log2_std_dev: -29,
};

/// 80 bits of security with a dimension of 800 (LWE estimator, September 15th 2020)
pub const LWE80_800: LWEParams = LWEParams {
    dimension: 800,
    log2_std_dev: -31, // warning u32
};

/// 80 bits of security with a dimension of 830 (LWE estimator, September 15th 2020)
pub const LWE80_830: LWEParams = LWEParams {
    dimension: 830,
    log2_std_dev: -32, // warning u32
};

/// 80 bits of security with a dimension of 1024 (LWE estimator, September 15th 2020)
pub const LWE80_1024: LWEParams = LWEParams {
    dimension: 1024,
    log2_std_dev: -40, // warning u32
};

/// 80 bits of security with a dimension of 2048 (LWE estimator, September 15th 2020)
pub const LWE80_2048: LWEParams = LWEParams {
    dimension: 2048,
    log2_std_dev: -82, // warning u64
};
*/

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
        let data = translate_error!(concrete::LWEParams::load(path))?;
        Ok(LWEParams{ data })
    }

    pub fn __repr__(&self) -> String {
        self.data.to_string()
    }
}

pub fn register(_py: Python, m: &PyModule) -> PyResult<()> {
    m.add_class::<LWEParams>()?;

    Ok(())
}

