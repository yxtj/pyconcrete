use pyo3::prelude::*;
use pyo3::exceptions::*;
use pyo3::types::PyList;
use concrete;
use concrete::Torus;
use super::translate_error;

/// Structure describing a list of plaintext values with their respective Encoder
/// # Attributes
/// * `encoder` - the list of the encoders (one for each plaintext)
/// * `plaintexts` - the list of plaintexts
/// * `nb_plaintexts` - the size of both lists
#[pyclass]
#[derive(Debug, Clone, PartialEq)]
pub struct Plaintext {
    // pub encoders: Vec<crate::Encoder>,
    // pub plaintexts: Vec<Torus>,
    // pub nb_plaintexts: usize,
    pub data: concrete::Plaintext,
}

#[pymethods]
impl Plaintext {
    // #[getter]
    // pub fn get_encoders(&self) -> &Vec<crate::Encoder> {
    //     self.data.encoders
    // }

    // #[setter]
    // pub fn set_encoders(&mut self, v: &Vec<crate::Encoder>) {
    //     self.data.encoders = v;
    // }

    #[getter]
    pub fn get_plaintexts(&self) -> Vec<Torus> {
        self.data.plaintexts.clone()
    }

    #[setter]
    pub fn set_plaintexts(&mut self, v: Vec<Torus>) {
        self.data.plaintexts = v;
    }

    #[getter]
    pub fn get_nb_plaintexts(&self) -> usize {
        self.data.nb_plaintexts
    }

    #[setter]
    pub fn set_nb_plaintexts(&mut self, v: usize) {
        self.data.nb_plaintexts = v;
    }

    /// Instantiate a new empty Plaintext (set to zero) of a certain size
    /// # Argument
    /// * `nb_plaintexts` - the number of plaintext that would be in the Plaintext instance
    /// # Output
    /// * a new instantiation of an empty Plaintext (set to zero) of a certain size
    /// # Example
    /// ```rust
    /// use concrete::Plaintext;
    /// let nb_ct: usize = 100;
    /// let plaintexts = Plaintext::zero(nb_ct);
    /// ```
    #[staticmethod]
    pub fn zero(nb_plaintexts: usize) -> Plaintext {
        Plaintext {
            data: concrete::Plaintext{
                encoders: vec![concrete::Encoder::zero(); nb_plaintexts],
                plaintexts: vec![0; nb_plaintexts],
                nb_plaintexts,
            }
        }
    }

    /// Instantiate a new Plaintext filled with plaintexts
    /// # Argument
    /// * `messages`- a list of messages as u64
    /// * `encoder`- an encoder
    /// # Output
    /// * a new instance of Plaintext containing the plaintext of each message with respect to encoder
    /// # Example
    /// ```rust
    /// use concrete::{Encoder, Plaintext};
    ///
    /// // create an Encoder instance where messages are in the interval [-5, 5[
    /// let encoder = Encoder::new(-5., 5., 8, 0).unwrap();
    ///
    /// // create a list of messages in our interval
    /// let messages: Vec<f64> = vec![-3.2, 4.3, 0.12, -1.1, 2.78];
    ///
    /// // create a new Plaintext instance filled with the plaintexts we want
    /// let pt = Plaintext::encode(&messages, &encoder).unwrap();
    ///
    /// // print the Plaintext
    /// println!("ec = {}", pt);
    /// ```
    #[staticmethod]
    pub fn encode(messages: Vec<f64>, encoder: &crate::Encoder) -> PyResult<Plaintext> {
        let data = concrete::Plaintext::encode(&messages, &encoder.data).unwrap();
        Ok(Plaintext{ data })
    }

    /// Decode one single plaintext (from the list of plaintexts in this Plaintext instance) according to its own encoder
    /// # Arguments
    /// * `nth` - the index of the plaintext to decode
    /// # Output
    /// * the decoded value as a f64
    /// # Example
    /// ```rust
    /// use concrete::{Encoder, Plaintext};
    ///
    /// // create an Encoder instance where messages are in the interval [-5, 5[
    /// let encoder = Encoder::new(-5., 5., 8, 0).unwrap();
    ///
    /// // create a list of messages in our interval
    /// let messages: Vec<f64> = vec![-3.2, 4.3, 0.12, -1.1, 2.78];
    ///
    /// // create a new Plaintext instance filled with the plaintexts we want
    /// let pt = Plaintext::encode(&messages, &encoder).unwrap();
    ///
    /// let n: usize = 2;
    /// let m = pt.decode_nth(n).unwrap();
    /// ```
    pub fn decode_nth(&self, nth: usize) -> PyResult<f64> {
        translate_error!(self.data.decode_nth(nth))
    }

    /// Encode several messages according to the list of Encoders in this instance
    /// # Arguments
    /// * `messages` - a list of messages as f64
    /// # Example
    /// ```rust
    /// use concrete::{Encoder, Plaintext};
    ///
    /// // create a list of 5 Encoder instances where messages are in the interval [-5, 5[
    /// let encoders = vec![Encoder::new(-5., 5., 8, 0).unwrap(); 5];
    ///
    /// // create a list of messages in our interval
    /// let messages: Vec<f64> = vec![-3.2, 4.3, 0.12, -1.1, 2.78];
    ///
    /// // create a new Plaintext instance that can contain 5 plaintexts
    /// let mut ec = Plaintext::zero(5);
    ///
    /// // set the encoders
    /// ec.set_encoders(&encoders);
    ///
    /// // encode our messages
    /// ec.encode_inplace(&messages);
    /// ```
    // pub fn encode_inplace(&mut self, messages: &[f64]) -> PyResult<()> {
    //     translate_error!(self.data.encode_inplace(messages))
    // }
    pub fn encode_inplace(&mut self, messages: Vec<f64>) -> PyResult<()> {
        translate_error!(self.data.encode_inplace(&messages))
    }

    /// Decode every plaintexts in this Plaintext instance according to its list of Encoders
    /// # Example
    /// ```rust
    /// use concrete::{Encoder, Plaintext};
    ///
    /// // create an Encoder instance where messages are in the interval [-5, 5[
    /// let encoder = Encoder::new(-5., 5., 8, 0).unwrap();
    ///
    /// // create a list of messages in our interval
    /// let messages: Vec<f64> = vec![-3.2, 4.3, 0.12, -1.1, 2.78];
    ///
    /// // create a new Plaintext instance filled with the plaintexts we want
    /// let mut ec = Plaintext::encode(&messages, &encoder).unwrap();
    ///
    /// let new_msgs: Vec<f64> = ec.decode().unwrap();
    /// ```
    pub fn decode(&self) -> PyResult<Vec<f64>> {
        translate_error!(self.data.decode())
    }

    /// Set the encoder list of this instance from an input list of encoders
    /// # Argument
    /// * `encoders` - a list of Encoder elements
    /// # Example
    /// ```rust
    /// use concrete::{Encoder, Plaintext};
    ///
    /// let nb_ct = 100;
    /// let mut pt = Plaintext::zero(nb_ct);
    /// let encoders = vec![Encoder::zero(); nb_ct];
    /// // setting the encoders
    /// pt.set_encoders(&encoders);
    /// ```
    // pub fn set_encoders(&mut self, encoders: &[crate::Encoder]) {
    //     self.data.set_encoders(&encoders)
    // }
    pub fn set_encoders(&mut self, encoders: &PyList) {
        let vec : Vec<concrete::Encoder> = encoders.iter().map(
            |t| t.extract::<crate::Encoder>().unwrap().data
        ).collect();
        self.data.set_encoders(&vec)
    }

    /// Set the encoder list of this instance from a unique input encoder
    /// # Argument
    /// * `encoder` - an Encoder
    /// # Example
    /// ```rust
    /// use concrete::{Encoder, Plaintext};
    ///
    /// let nb_ct = 100;
    /// let mut pt = Plaintext::zero(nb_ct);
    /// let encoder = Encoder::zero();
    /// // setting the encoders
    /// pt.set_encoders_from_one(&encoder);
    /// ```
    pub fn set_encoders_from_one(&mut self, encoder: &crate::Encoder) {
        self.data.set_encoders_from_one(&encoder.data)
    }

    /// Set the nth encoder of the encoder list of this instance from an input encoder
    /// # Argument
    /// * `encoder` - an Encoder
    /// # Example
    /// ```rust
    /// use concrete::{Encoder, Plaintext};
    ///
    /// let nb_ct = 100;
    /// let mut pt = Plaintext::zero(nb_ct);
    /// let encoder_1 = Encoder::zero();
    /// let encoder_2 = Encoder::zero();
    /// let n: usize = 2;
    /// // setting the encoders
    /// pt.set_encoders_from_one(&encoder_1);
    /// pt.set_nth_encoder(n, &encoder_2);
    /// ```
    pub fn set_nth_encoder(&mut self, nth: usize, encoder: &crate::Encoder) {
        self.data.encoders[nth].copy(&encoder.data);
    }

    pub fn save(&self, path: &str) -> PyResult<()> {
        translate_error!(self.data.save(path))
    }

    #[staticmethod]
    pub fn load(path: &str) -> PyResult<Plaintext> {
        let data = concrete::Plaintext::load(path).unwrap();
        Ok(Plaintext{ data })
    }

    pub fn __repr__(&self) -> String {
        self.data.to_string()
    }
}

pub fn register(_py: Python, m: &PyModule) -> PyResult<()> {
    m.add_class::<Plaintext>()?;

    Ok(())
}

