use pyo3::prelude::*;
use pyo3::exceptions::*;
use concrete;
use super::translate_error;

/// Structure describing the security parameters for encryption with RLWE ciphertexts
/// # Attributes
/// - `polynomial_size`: the number of coefficients in a polynomial
/// - `dimension`: the size of an RLWE mask
/// - `log2_std_dev`: the log2 of the standard deviation used for the error normal distribution
#[pyclass]
#[derive(Debug, Clone, PartialEq)]
pub struct RLWEParams {
    // pub polynomial_size: usize,
    // pub dimension: usize,
    // pub log2_std_dev: i32,
    pub data : concrete::RLWEParams,
}
/*
////////////////////////////////////////
// 128 bits of security - dimension 1 //
////////////////////////////////////////

/// 128 bits of security with a polynomial_size of 1 and a polynomial size of 256 (LWE estimator, September 15th 2020)
pub const RLWE128_256_1: RLWEParams = RLWEParams {
    dimension: 1,
    polynomial_size: 256,
    log2_std_dev: -5,
};
/// 128 bits of security with a polynomial_size of 1 and a polynomial size of 512 (LWE estimator, September 15th 2020)
pub const RLWE128_512_1: RLWEParams = RLWEParams {
    dimension: 1,
    polynomial_size: 512,
    log2_std_dev: -11,
};
/// 128 bits of security with a polynomial_size of 1 and a polynomial size of 1024 (LWE estimator, September 15th 2020)
pub const RLWE128_1024_1: RLWEParams = RLWEParams {
    dimension: 1,
    polynomial_size: 1024,
    log2_std_dev: -25,
};
/// 128 bits of security with a polynomial_size of 1 and a polynomial size of 2048 (LWE estimator, September 15th 2020)
pub const RLWE128_2048_1: RLWEParams = RLWEParams {
    dimension: 1,
    polynomial_size: 2048,
    log2_std_dev: -52, // warning u32
};
/// 128 bits of security with a polynomial_size of 1 and a polynomial size of 4096 (LWE estimator, September 15th 2020)
pub const RLWE128_4096_1: RLWEParams = RLWEParams {
    dimension: 1,
    polynomial_size: 4096,
    log2_std_dev: -105, // warning u64
};

////////////////////////////////////////
// 128 bits of security - dimension 2 //
////////////////////////////////////////

/// 128 bits of security with a polynomial_size of 2 and a polynomial size of 256 (LWE estimator, September 15th 2020)
pub const RLWE128_256_2: RLWEParams = RLWEParams {
    dimension: 2,
    polynomial_size: 256,
    log2_std_dev: -11,
};
/// 128 bits of security with a polynomial_size of 2 and a polynomial size of 512 (LWE estimator, September 15th 2020)
pub const RLWE128_512_2: RLWEParams = RLWEParams {
    dimension: 2,
    polynomial_size: 512,
    log2_std_dev: -25,
};

////////////////////////////////////////
// 128 bits of security - dimension 4 //
////////////////////////////////////////

/// 128 bits of security with a polynomial_size of 4 and a polynomial size of 256 (LWE estimator, September 15th 2020)
pub const RLWE128_256_4: RLWEParams = RLWEParams {
    dimension: 4,
    polynomial_size: 256,
    log2_std_dev: -25,
};

///////////////////////////////////////
// 80 bits of security - dimension 1 //
///////////////////////////////////////

/// 80 bits of security with a polynomial_size of 1 and a polynomial size of 256 (LWE estimator, September 15th 2020)
pub const RLWE80_256_1: RLWEParams = RLWEParams {
    dimension: 1,
    polynomial_size: 256,
    log2_std_dev: -9,
};
/// 80 bits of security with a polynomial_size of 1 and a polynomial size of 512 (LWE estimator, September 15th 2020)
pub const RLWE80_512_1: RLWEParams = RLWEParams {
    dimension: 1,
    polynomial_size: 512,
    log2_std_dev: -19,
};
/// 80 bits of security with a polynomial_size of 1 and a polynomial size of 1024 (LWE estimator, September 15th 2020)
pub const RLWE80_1024_1: RLWEParams = RLWEParams {
    dimension: 1,
    polynomial_size: 1024,
    log2_std_dev: -40, // warning u32
};
/// 80 bits of security with a polynomial_size of 1 and a polynomial size of 2048 (LWE estimator, September 15th 2020)
pub const RLWE80_2048_1: RLWEParams = RLWEParams {
    dimension: 1,
    polynomial_size: 2048,
    log2_std_dev: -82, // warning u64
};

///////////////////////////////////////
// 80 bits of security - dimension 2 //
///////////////////////////////////////

/// 80 bits of security with a polynomial_size of 2 and a polynomial size of 256 (LWE estimator, September 15th 2020)
pub const RLWE80_256_2: RLWEParams = RLWEParams {
    dimension: 2,
    polynomial_size: 256,
    log2_std_dev: -19,
};
/// 80 bits of security with a polynomial_size of 2 and a polynomial size of 512 (LWE estimator, September 15th 2020)
pub const RLWE80_512_2: RLWEParams = RLWEParams {
    dimension: 2,
    polynomial_size: 512,
    log2_std_dev: -40, // warning u32
};

///////////////////////////////////////
// 80 bits of security - dimension 4 //
///////////////////////////////////////

/// 80 bits of security with a polynomial_size of 4 and a polynomial size of 256 (LWE estimator, September 15th 2020)
pub const RLWE80_256_4: RLWEParams = RLWEParams {
    dimension: 4,
    polynomial_size: 256,
    log2_std_dev: -40, // warning u32
};
*/

#[pymethods]
impl RLWEParams {
    /// Instantiate a new RLWEParams with the provided dimension and standard deviation
    /// # Arguments
    /// * `polynomial_size` - the number of coefficients in a polynomial
    /// * `dimension` - the size of an RLWE mask
    /// * `std_dev` - the standard deviation used for the error normal distribution
    /// # Output
    /// * a new instantiation of an RLWEParams
    /// * NotPowerOfTwoError if `polynomial_size` is not a power of 2
    #[new]
    pub fn new(
        polynomial_size: usize,
        dimension: usize,
        log2_std_dev: i32,
    ) -> PyResult<RLWEParams> {
        let data = translate_error!(concrete::RLWEParams::new(polynomial_size, dimension, log2_std_dev))?;
        Ok(RLWEParams{ data })
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
        translate_error!(self.data.save(path))
    }

    #[staticmethod]
    pub fn load(path: &str) -> PyResult<RLWEParams> {
        let data = translate_error!(concrete::RLWEParams::load(path))?;
        Ok(RLWEParams{ data })
    }

    pub fn __repr__(&self) -> String {
        self.data.to_string()
    }
}

pub fn register(_py: Python, m: &PyModule) -> PyResult<()> {
    m.add_class::<RLWEParams>()?;

    Ok(())
}

