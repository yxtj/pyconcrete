use pyo3::prelude::*;
use pyo3::exceptions::*;
// use pyo3::types::PyList;
use concrete;
use concrete::{Torus};
use super::{translate_error, Plaintext};

/// Structure describing one particular Encoding
/// # Attributes
/// * `o` - the offset of the encoding
/// * `delta` - the delta of the encoding
/// * `nb_bit_precision` - the minimum number of bits to represent a plaintext
/// * `nb_bit_padding` - the number of bits set to zero in the MSB
#[pyclass]
#[derive(Debug, Clone, PartialEq)]
pub struct Encoder {
    // pub o: f64,     // with margin between 1 and 0
    // pub delta: f64, // with margin between 1 and 0
    // pub nb_bit_precision: usize,
    // pub nb_bit_padding: usize,
    // pub round: bool,
    pub data: concrete::Encoder,
}

#[pymethods]
impl Encoder {
    #[getter]
    pub fn get_o(&self) -> f64 {
        self.data.o
    }

    #[setter]
    pub fn set_o(&mut self, v: f64) {
        self.data.o = v;
    }

    #[getter]
    pub fn get_delta(&self) -> f64 {
        self.data.delta
    }

    #[setter]
    pub fn set_delta(&mut self, v: f64) {
        self.data.delta = v;
    }

    #[getter]
    pub fn get_nb_bit_precision(&self) -> usize {
        self.data.nb_bit_precision
    }

    #[setter]
    pub fn set_nb_bit_precision(&mut self, v: usize) {
        self.data.nb_bit_precision = v;
    }

    #[getter]
    pub fn get_nb_bit_padding(&self) -> usize {
        self.data.nb_bit_padding
    }

    #[setter]
    pub fn set_nb_bit_padding(&mut self, v: usize) {
        self.data.nb_bit_padding = v;
    }

    #[getter]
    pub fn get_round(&self) -> bool {
        self.data.round
    }

    #[setter]
    pub fn set_round(&mut self, v: bool) {
        self.data.round = v;
    }

    /// Instantiate a new Encoder with the provided interval as [min,max[
    /// This encoder is meant to be use in an approximate context.
    ///
    /// # Arguments
    /// * `min`- the minimum real value of the interval
    /// * `max`- the maximum real value of the interval
    /// * `nb_bit_precision` - number of bits to represent a plaintext
    /// * `nb_bit_padding` - number of bits for left padding with zeros
    /// # Output
    /// * a new instantiation of an Encoder
    /// # Example
    /// ```rust
    /// use concrete::Encoder;
    ///
    /// // parameters
    /// let min: f64 = 0.2;
    /// let max: f64 = 0.8;
    /// let nb_bit_precision = 8;
    /// let nb_bit_padding = 4;
    ///
    /// // instantiation
    /// let encoder = Encoder::new(min, max, nb_bit_precision, nb_bit_padding).unwrap();
    /// ```
    #[new]
    pub fn new(
        min: f64,
        max: f64,
        nb_bit_precision: usize,
        nb_bit_padding: usize,
    ) -> PyResult<Encoder> {
        let data = translate_error!(concrete::Encoder::new(min, max, nb_bit_precision, nb_bit_padding))?;
        Ok(Encoder{ data })
    }

    /// Instantiate a new Encoder with the provided interval as [min,max[
    /// This encoder is meant to be use in an exact computation context.
    /// It will round at encode and at decode.
    ///
    /// # Arguments
    /// * `min`- the minimum real value of the interval
    /// * `max`- the maximum real value of the interval
    /// * `nb_bit_precision` - number of bits to represent a plaintext
    /// * `nb_bit_padding` - number of bits for left padding with zeros
    /// # Output
    /// * a new instantiation of an Encoder
    /// # Example
    /// ```rust
    /// use concrete::Encoder;
    ///
    /// // parameters
    /// let min: f64 = 0.2;
    /// let max: f64 = 0.8;
    /// let nb_bit_precision = 8;
    /// let nb_bit_padding = 4;
    ///
    /// // instantiation
    /// let encoder = Encoder::new(min, max, nb_bit_precision, nb_bit_padding).unwrap();
    /// ```
    #[staticmethod]
    pub fn new_rounding_context(
        min: f64,
        max: f64,
        nb_bit_precision: usize,
        nb_bit_padding: usize,
    ) -> PyResult<Encoder> {
        let data = translate_error!(concrete::Encoder::new_rounding_context(
            min, max, nb_bit_precision, nb_bit_padding))?;
        Ok(Encoder{ data })
    }

    /// After an homomorphic operation, update an encoder using the variance
    /// # Arguments
    /// * `variance` - variance
    /// # Output
    /// * return the number of bits of precision affected by the noise
    /// # Example
    /// ```rust
    /// use concrete::Encoder;
    ///
    /// // parameters
    /// let min: f64 = 0.2;
    /// let max: f64 = 0.8;
    /// let nb_bit_precision = 8;
    /// let nb_bit_padding = 4;
    ///
    /// // instantiation
    /// let mut encoder = Encoder::new(min, max, nb_bit_precision, nb_bit_padding).unwrap();
    /// let variance: f64 = f64::powi(2., -30);
    /// let nb_bit_overlap: usize = encoder.update_precision_from_variance(variance).unwrap();
    /// ```
    pub fn update_precision_from_variance(
        &mut self,
        variance: f64,
    ) -> PyResult<usize> {
        translate_error!(self.data.update_precision_from_variance(variance))
    }

    /// Instantiate a new Encoder with the provided interval as [center-radius,center+radius[
    /// # Arguments
    /// * `center` - the center value of the interval
    /// * `radius` - the distance between the center and the endpoints of the interval
    /// * `nb_bit_precision` - number of bits to represent a plaintext
    /// * `nb_bit_padding` - number of bits for left padding with zeros
    /// # Output
    /// * a new instantiation of an Encoder
    /// # Example
    /// ```rust
    /// use concrete::Encoder;
    ///
    /// // parameters
    /// let center: f64 = 0.;
    /// let radius: f64 = 5.4;
    /// let nb_bit_precision = 8;
    /// let nb_bit_padding = 4;
    ///
    /// // instantiation
    /// let encoder = Encoder::new_centered(center, radius, nb_bit_precision, nb_bit_padding).unwrap();
    /// ```
    #[staticmethod]
    pub fn new_centered(
        center: f64,
        radius: f64,
        nb_bit_precision: usize,
        nb_bit_padding: usize,
    ) -> PyResult<Encoder> {
        let data = translate_error!(concrete::Encoder::new_centered(
            center, radius, nb_bit_precision, nb_bit_padding))?;
        Ok(Encoder{ data })
    }

    /// Encode one single message according to this Encoder parameters
    /// # Arguments
    /// * `message` - a message as a f64
    /// # Output
    /// * a new instantiation of an Plaintext containing only one encoded value (the one we just computed with this function)
    /// # Example
    /// ```rust
    /// use concrete::Encoder;
    ///
    /// // parameters
    /// let min: f64 = 0.2;
    /// let max: f64 = 0.8;
    /// let nb_bit_precision = 8;
    /// let nb_bit_padding = 4;
    /// let message = 0.6;
    ///
    /// // creation of the encoder
    /// let encoder = Encoder::new(min, max, nb_bit_precision, nb_bit_padding).unwrap();
    ///
    /// // encoding
    /// let m = encoder.encode_single(message).unwrap();
    /// ```
    pub fn encode_single(&self, message: f64) -> PyResult<Plaintext> {
        let data = translate_error!(self.data.encode_single(message))?;
        Ok(Plaintext{ data })
    }

    /// Decode one single plaintext according to this Encoder parameters
    /// # Arguments
    /// * `ec` - an plaintext
    /// # Output
    /// * the decoded value as a f64
    /// # Example
    /// ```rust
    /// use concrete::Encoder;
    ///
    /// // parameters
    /// let min: f64 = 0.2;
    /// let max: f64 = 0.8;
    /// let nb_bit_precision = 8;
    /// let nb_bit_padding = 4;
    /// let message = 0.6;
    ///
    /// // creation of the encoder
    /// let encoder = Encoder::new(min, max, nb_bit_precision, nb_bit_padding).unwrap();
    ///
    /// // encoding
    /// let m = encoder.encode_single(message).unwrap();
    ///
    /// // decoding
    /// let new_message = encoder.decode_single(m.plaintexts[0]).unwrap();
    /// ```
    pub fn decode_single(&self, ec: Torus) -> PyResult<f64> {
        translate_error!(self.data.decode_single(ec))
    }

    /// Instantiate a new empty Encoder (set to zero)
    /// # Output
    /// * a new instantiation of an empty Encoder (set to zero)
    /// # Example
    /// ```rust
    /// use concrete::Encoder;
    /// let encoder = Encoder::zero();
    /// ```
    #[staticmethod]
    pub fn zero() -> Encoder {
        Encoder {
            data: concrete::Encoder{
                o: 0.,
                delta: 0.,
                nb_bit_precision: 0,
                nb_bit_padding: 0,
                round: false,
            }
        }
    }

    /// Encode several message according to this (one) Encoder parameters
    /// The output Plaintext will have plaintexts all computed with the same Encoder parameters
    /// # Arguments
    /// * `messages`- a list of messages as a f64
    /// # Example
    /// ```rust
    /// use concrete::Encoder;
    /// // parameters
    /// let (min, max): (f64, f64) = (0.2, 0.4);
    /// let (precision, padding): (usize, usize) = (8, 4);
    /// let messages: Vec<f64> = vec![0.3, 0.34];
    /// let encoder = Encoder::new(min, max, precision, padding).unwrap();
    /// let plaintexts = encoder.encode(&messages).unwrap();
    /// ```
    // pub fn encode(&self, messages: &[f64]) -> PyResult<Plaintext> {
    pub fn encode(&self, messages: Vec<f64>) -> PyResult<Plaintext> {
        let data = translate_error!(self.data.encode(&messages))?;
        Ok(Plaintext{ data })
    }

    /// Computes the smallest real number that this encoding can handle
    pub fn get_granularity(&self) -> f64 {
        self.data.delta / f64::powi(2., self.data.nb_bit_precision as i32)
    }

    pub fn get_min(&self) -> f64 {
        self.data.o
    }

    pub fn get_max(&self) -> f64 {
        self.data.o + self.data.delta - self.data.get_granularity()
    }

    pub fn get_size(&self) -> f64 {
        self.data.delta - self.data.get_granularity()
    }

    /// Copy the content of the input encoder inside the self encoder
    /// # Argument
    /// * `encoder`- the encoder to be copied
    /// # Example
    /// ```rust
    /// use concrete::Encoder;
    /// // parameters
    /// let (min, max): (f64, f64) = (0.2, 0.4);
    /// let (precision, padding): (usize, usize) = (8, 4);
    ///
    /// let encoder_1 = Encoder::new(min, max, precision, padding).unwrap();
    /// let mut encoder_2 = Encoder::zero();
    /// encoder_2.copy(&encoder_1);
    /// ```
    pub fn copy(&mut self, encoder: &Encoder) {
        self.data.o = encoder.data.o;
        self.data.delta = encoder.data.delta;
        self.data.nb_bit_precision = encoder.data.nb_bit_precision;
        self.data.nb_bit_padding = encoder.data.nb_bit_padding;
    }

    /// Crete a new encoder as if one computes a square function divided by 4
    /// # Argument
    /// * `nb_bit_padding`- number of bits for left padding with zeros
    /// # Example
    /// ```rust
    /// use concrete::Encoder;
    ///
    /// // parameters
    /// let min: f64 = 0.2;
    /// let max: f64 = 0.8;
    /// let nb_bit_precision = 8;
    /// let nb_bit_padding = 4;
    ///
    /// // instantiation
    /// let encoder_in = Encoder::new(min, max, nb_bit_precision, nb_bit_padding).unwrap();
    /// let encoder_out = encoder_in
    ///     .new_square_divided_by_four(nb_bit_padding)
    ///     .unwrap();
    /// ```
    pub fn new_square_divided_by_four(
        &self,
        nb_bit_padding: usize,
    ) -> PyResult<Encoder> {
        let data = translate_error!(self.data.new_square_divided_by_four(nb_bit_padding))?;
        Ok(Encoder{ data })
    }

    /// Wrap the core_api encode function with the padding
    /// # Argument
    /// * `m` - the message to encode
    /// # Example
    /// ```rust
    /// use concrete::Encoder;
    ///
    /// // parameters
    /// let min: f64 = 0.2;
    /// let max: f64 = 0.8;
    /// let nb_bit_precision = 8;
    /// let nb_bit_padding = 4;
    ///
    /// // message
    /// let m = 0.3;
    /// // instantiation
    /// let encoder = Encoder::new(min, max, nb_bit_precision, nb_bit_padding).unwrap();
    ///
    /// let plaintext = encoder.encode_core(m).unwrap();
    /// ```
    pub fn encode_core(&self, m: f64) -> PyResult<Torus> {
        translate_error!(self.data.encode_core(m))
    }

    /// Wrap the core_api encode function with the padding and allows to encode a message that is outside of the interval of the encoder
    /// It is used for correction after homomorphic computation
    /// # Argument
    /// * `m` - the message to encode
    /// ```rust
    /// use concrete::Encoder;
    ///
    /// // parameters
    /// let min: f64 = 0.2;
    /// let max: f64 = 0.8;
    /// let nb_bit_precision = 8;
    /// let nb_bit_padding = 4;
    ///
    /// // message
    /// let m = 1.2;
    /// // instantiation
    /// let encoder = Encoder::new(min, max, nb_bit_precision, nb_bit_padding).unwrap();
    ///
    /// let plaintext = encoder.encode_outside_interval_operators(m).unwrap();
    /// ```
    pub fn encode_outside_interval_operators(&self, m: f64) -> PyResult<Torus> {
        translate_error!(self.data.encode_outside_interval_operators(m))
    }

    /// Wrap the core_api decode function with the padding and the rounding
    ///
    /// # Argument
    /// * `pt` - the noisy plaintext
    /// ```rust
    /// use concrete::Encoder;
    ///
    /// // parameters
    /// let min: f64 = 0.2;
    /// let max: f64 = 0.8;
    /// let nb_bit_precision = 8;
    /// let nb_bit_padding = 4;
    ///
    /// // message
    /// let m = 0.3;
    /// // instantiation
    /// let encoder = Encoder::new(min, max, nb_bit_precision, nb_bit_padding).unwrap();
    ///
    /// let plaintext = encoder.encode_core(m).unwrap();
    /// let new_message = encoder.decode_core(plaintext).unwrap();
    /// ```
    pub fn decode_core(&self, pt: Torus) -> PyResult<f64> {
        translate_error!(self.data.decode_core(pt))
    }

    /// Check if the Encoder looks valid or not
    /// # Output
    /// return a boolean, true means that it is valid
    pub fn is_valid(&self) -> bool {
        !(self.data.nb_bit_precision == 0 || self.data.delta <= 0.)
    }

    pub fn save(&self, path: &str) -> PyResult<()> {
        translate_error!(self.data.save(path))
    }

    #[staticmethod]
    pub fn load(path: &str) -> PyResult<Encoder> {
        let data = translate_error!(concrete::Encoder::load(path))?;
        Ok(Encoder{ data })
    }

    /// Modify the encoding to be use after an homomorphic opposite
    /// ```rust
    /// use concrete::Encoder;
    ///
    /// // parameters
    /// let min: f64 = 0.2;
    /// let max: f64 = 0.8;
    /// let nb_bit_precision = 8;
    /// let nb_bit_padding = 4;
    ///
    /// // message
    /// let m = 0.3;
    /// // instantiation
    /// let mut encoder = Encoder::new(min, max, nb_bit_precision, nb_bit_padding).unwrap();
    ///
    /// encoder.opposite_inplace();
    /// ```
    pub fn opposite_inplace(&mut self) -> PyResult<()> {
        let old_max = self.data.o + self.data.delta - self.data.get_granularity();
        let new_o = -old_max;
        self.data.o = new_o;
        Ok(())
    }

    pub fn __repr__(&self) -> String {
        self.data.to_string()
    }
}


pub fn register(_py: Python, m: &PyModule) -> PyResult<()> {
    m.add_class::<Encoder>()?;

    Ok(())
}

