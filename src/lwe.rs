//! lwe ciphertext module
use pyo3::prelude::*;
use pyo3::exceptions::*;
use concrete;
use super::translate_error;

/// Structure containing a single LWE ciphertext.
///
/// # Attributes
/// * `ciphertext` - the LWE ciphertexts
/// * `variances` - the variance of the noise of the LWE ciphertext
/// * `dimension` - the length the LWE mask
/// * `encoder` - the encoder of the LWE ciphertext
#[pyclass]
// #[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct LWE {
    // pub ciphertext: crypto::lwe::LweCiphertext<Vec<Torus>>,
    // pub variance: f64,
    // pub dimension: usize,
    // pub encoder: crate::Encoder,
    pub data: concrete::LWE,
}

impl GenericAdd<f64, CryptoAPIError> for LWE {
    fn add(&self, right: f64) -> Result<LWE, CryptoAPIError> {
        self.add_constant_dynamic_encoder(right)
    }
    fn add_inplace(&mut self, right: f64) -> Result<(), CryptoAPIError> {
        self.add_constant_dynamic_encoder_inplace(right)
    }
}

impl GenericAdd<&LWE, CryptoAPIError> for LWE {
    fn add(&self, right: &LWE) -> Result<LWE, CryptoAPIError> {
        self.add_with_padding(right)
    }
    fn add_inplace(&mut self, right: &LWE) -> Result<(), CryptoAPIError> {
        self.add_with_padding_inplace(right)
    }
}

#[pymethods]
impl LWE {

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
    pub fn get_encoder(&self) -> &crate::Encoder {
        self.data.encoder
    }

    #[setter]
    pub fn set_encoder(&mut self, v: crate::Encoder) {
        self.data.encoder = v;
    }

    /// Instantiate a new LWE filled with zeros from a dimension
    ///
    /// # Arguments
    /// * `dimension` - the length the LWE mask
    ///
    /// # Output
    /// * a new instantiation of an LWE
    /// * ZeroCiphertextsInStructureError if we try to create a structure with no ciphertext in it
    ///
    /// # Example
    /// ```rust
    /// use concrete::*;
    ///
    /// // creates an LWE ciphertext with a dimension of 630
    /// let empty_ciphertexts = LWE::zero(630).unwrap();
    /// ```
    #[staticmethod]
    pub fn zero(dimension: usize) -> PyResult<crate::LWE> {
        translate_error!(concrete::LWE::zero(dimension))
    }

    /// Encode a message and then directly encrypt the plaintext into an LWE structure
    ///
    /// # Arguments
    /// * `sk` - an LWE secret key
    /// * `message` -  a  message as u64
    /// * `encoder` - an Encoder
    ///
    /// # Output
    /// an LWE structure
    ///
    /// ```rust
    /// use concrete::*;
    ///
    /// // encoder
    /// let encoder = Encoder::new(-2., 6., 4, 4).unwrap();
    ///
    /// // generate a secret key
    /// let secret_key = LWESecretKey::new(&LWE128_1024);
    ///
    /// // a message
    /// let message: f64 = -1.;
    ///
    /// // encode and encrypt
    /// let mut ciphertext = LWE::encode_encrypt(&secret_key, message, &encoder).unwrap();
    /// ```
    #[staticmethod]
    pub fn encode_encrypt(
        sk: &crate::LWESecretKey,
        message: f64,
        encoder: &crate::Encoder,
    ) -> PyResult<LWE> {
        translate_error!(concrete::LWE::encode_encrypt(&sk.data, message, &encoder.data))
    }

    /// Encrypt a raw plaintext (a Torus element instead of a struct Plaintext) with the provided key and standard deviation
    /// # Arguments
    /// * `sk` - an LWE secret key
    /// * `plaintext` - a Torus element
    /// * `std_dev` - the standard deviation used for the error normal distribution
    ///
    /// # Example
    /// ```rust
    /// use concrete::*;
    ///
    /// // create an Encoder instance where messages are in the interval [-5, 5[
    /// let encoder = Encoder::new(-5., 5., 8, 0).unwrap();
    ///
    /// // create one plaintext
    /// let pt: u64 = 0;
    ///
    /// // create one LWESecretKey
    /// let sk = LWESecretKey::new(&LWE128_630);
    ///
    /// // create a new LWE that encrypts pt
    /// let mut ct = LWE::zero(sk.dimension).unwrap();
    /// ct.encrypt_raw(&sk, pt).unwrap();
    /// ```
    pub fn encrypt_raw(
        &mut self,
        sk: &crate::LWESecretKey,
        plaintext: Torus,
    ) -> PyResult<()> {
        translate_error!(concrete::LWE::encrypt_raw(&sk.data, plaintext))
    }

    /// Decrypt the ciphertext, meaning compute the phase and directly decode the output
    ///
    /// # Arguments
    /// * `sk` - an LWE secret key
    /// # Output
    /// * `result` - a f64
    /// * DimensionError - if the ciphertext and the key have incompatible dimensions
    /// ```rust
    /// use concrete::*;
    ///
    /// // create an Encoder instance where messages are in the interval [-5, 5[
    /// let encoder = Encoder::new(-5., 5., 8, 0).unwrap();
    ///
    /// // create a list of messages in our interval
    /// let message: f64 = -3.2;
    ///
    /// // create an LWESecretKey
    /// let sk = LWESecretKey::new(&LWE128_630);
    ///
    /// // create a new LWE that encrypts pt
    /// let mut ct = LWE::encode_encrypt(&sk,message, &encoder).unwrap();
    ///
    /// // decryption
    /// let res = ct.decrypt_decode(&sk).unwrap();
    /// ```
    pub fn decrypt_decode(&self, sk: &crate::LWESecretKey) -> PyResult<f64> {
        translate_error!(self.data.decrypt_decode(&sk.data))
    }

    /// Decrypt the ciphertext, meaning compute the phase and directly decode the output as if the encoder was in a rounding context
    ///
    /// # Arguments
    /// * `sk` - an LWE secret key
    /// # Output
    /// * `result` - a f64
    /// * DimensionError - if the ciphertext and the key have incompatible dimensions
    /// ```rust
    /// use concrete::*;
    ///
    /// // create an Encoder instance where messages are in the interval [-5, 5[
    /// let encoder = Encoder::new(-5., 5., 8, 0).unwrap();
    ///
    /// // create a list of messages in our interval
    /// let message: f64 = -3.2;
    ///
    /// // create an LWESecretKey
    /// let sk = LWESecretKey::new(&LWE128_630);
    ///
    /// // create a new LWE that encrypts pt
    /// let mut ct = LWE::encode_encrypt(&sk,message, &encoder).unwrap();
    ///
    /// // decryption
    /// let res = ct.decrypt_decode(&sk).unwrap();
    /// ```
    pub fn decrypt_decode_round(&self, sk: &crate::LWESecretKey) -> PyResult<f64> {
        translate_error!(self.data.decrypt_decode_round(&sk.data))
    }

    /// Add a small message to a LWE ciphertext and does not change the encoding but changes the bodies of the ciphertext
    ///
    /// # Argument
    /// * `message` - a f64
    ///
    /// # Output
    /// * a new LWE
    ///
    /// # Example
    /// ```rust
    /// use concrete::*;
    ///
    /// // encoder
    /// let encoder = Encoder::new(100., 110., 8, 0).unwrap();
    ///
    /// // generate a secret key
    /// let secret_key = LWESecretKey::new(&LWE128_1024);
    ///
    /// // two messages
    /// let message_1: f64 = 106.276;
    /// let message_2: f64 =-4.9;
    ///
    /// // encode and encrypt
    /// let ciphertext = LWE::encode_encrypt(&secret_key,message_1, &encoder).unwrap();
    ///
    /// // addition between ciphertext and message_2
    /// let ct_add = ciphertext.add_constant_static_encoder(message_2).unwrap();
    /// ```
    pub fn add_constant_static_encoder(&self, message: f64) -> PyResult<crate::LWE> {
        let data = translate_error!(concrete::LWE::add_constant_static_encoder(message)).unwrap();
        Ok(LWE{ data })
    }

    /// Add small messages to a LWE ciphertext and does not change the encoding but changes the bodies of the ciphertexts
    ///
    /// # Argument
    /// * `messages` - a list of messages as f64
    ///
    /// # Example
    /// ```rust
    /// use concrete::*;
    ///
    /// // encoder
    /// let encoder = Encoder::new(100., 110., 8, 0).unwrap();
    ///
    /// // generate a secret key
    /// let secret_key = LWESecretKey::new(&LWE128_1024);
    ///
    /// // two messages
    /// let message_1: f64 = 106.276;
    /// let message_2: f64 =-4.9;
    ///
    /// // encode and encrypt
    /// let mut ciphertext = LWE::encode_encrypt(&secret_key,message_1, &encoder).unwrap();
    ///
    /// // addition between ciphertext and message_2
    /// ciphertext.add_constant_static_encoder_inplace(message_2).unwrap();
    /// ```
    pub fn add_constant_static_encoder_inplace(
        &mut self,
        message: f64,
    ) -> PyResult<()> {
        translate_error!(self.data.add_constant_static_encoder_inplace(message))
    }

    /// Add a message to a LWE ciphertext and translate the interval of a distance equal to the message but does not change either the bodies or the masks of the ciphertext
    ///
    /// # Argument
    /// * `message` - a f64
    ///
    /// # Output
    /// * a new LWE
    /// * InvalidEncoderError if invalid encoder
    ///
    /// # Example
    /// ```rust
    /// use concrete::*;
    ///
    /// // encoder
    /// let encoder = Encoder::new(100., 110., 8, 0).unwrap();
    ///
    /// // generate a secret key
    /// let secret_key = LWESecretKey::new(&LWE128_1024);
    ///
    /// // two lists of messages
    /// let message_1: f64 = 106.276;
    /// let message_2: f64 = -4.9;
    ///
    /// // encode and encrypt
    /// let mut ciphertext = LWE::encode_encrypt(&secret_key, message_1, &encoder).unwrap();
    ///
    /// // addition between ciphertext and message_2
    /// let ct = ciphertext
    ///     .add_constant_dynamic_encoder(message_2)
    ///     .unwrap();
    /// ```
    pub fn add_constant_dynamic_encoder(&self, message: f64) -> PyResult<crate::LWE> {
        let data = translate_error!(self.data.add_constant_dynamic_encoder(message)).unwrap();
        Ok(LWE{ data })
    }

    /// Add a message to a LWE ciphertext and translate the interval of a distance equal to the message but does not change either the bodies or the masks of the ciphertext
    ///
    /// # Argument
    /// * `message` - a f64
    ///
    /// # Output
    /// * InvalidEncoderError if invalid encoder
    ///
    /// # Example
    /// ```rust
    /// use concrete::*;
    ///
    /// // encoder
    /// let encoder = Encoder::new(100., 110., 8, 0).unwrap();
    ///
    /// // generate a secret key
    /// let secret_key = LWESecretKey::new(&LWE128_1024);
    ///
    /// // two lists of messages
    /// let message_1: f64= 106.276;
    /// let message_2: f64 = -4.9;
    ///
    /// // encode and encrypt
    /// let mut ciphertext = LWE::encode_encrypt(&secret_key, message_1, &encoder).unwrap();
    ///
    /// // addition between ciphertext and message_2
    /// ciphertext
    ///     .add_constant_dynamic_encoder_inplace(message_2)
    ///     .unwrap();
    /// ```
    pub fn add_constant_dynamic_encoder_inplace(
        &mut self,
        message: f64,
    ) -> PyResult<()> {
        translate_error!(self.data.add_constant_dynamic_encoder_inplace(message))
    }

    /// Compute an homomorphic addition between two LWE ciphertexts
    ///
    /// # Arguments
    /// * `ct` - an LWE struct
    /// * `new_min` - the min of the interval for the resulting Encoder
    ///
    /// # Output
    /// * a new LWE
    /// * DimensionError - if the ciphertexts have incompatible dimensions
    /// * DeltaError - if the ciphertexts have incompatible deltas
    /// * PaddingError - if the ciphertexts have incompatible paddings
    /// * NotEnoughPaddingError - if nb bit of padding is zero
    ///
    /// # Example
    /// ```rust
    /// use concrete::*;
    ///
    /// // encoder
    /// let encoder_1 = Encoder::new(100., 110., 8, 0).unwrap();
    /// let encoder_2 = Encoder::new(0., 10., 8, 0).unwrap();
    ///
    /// // generate a secret key
    /// let secret_key = LWESecretKey::new(&LWE128_1024);
    ///
    /// // two lists of messages
    /// let message_1: f64 = 106.276;
    /// let message_2: f64 =4.9;
    ///
    /// // new_min
    /// let new_min: f64 = 103.;
    ///
    /// // encode and encrypt
    /// let ciphertext_1 = LWE::encode_encrypt(&secret_key, message_1, &encoder_1).unwrap();
    /// let ciphertext_2 = LWE::encode_encrypt(&secret_key, message_2, &encoder_2).unwrap();
    ///
    /// // addition between ciphertext_1 and ciphertext_2
    /// let ct_add = ciphertext_1
    ///     .add_with_new_min(&ciphertext_2, new_min)
    ///     .unwrap();
    /// ```
    pub fn add_with_new_min(
        &self,
        ct: &crate::LWE,
        new_min: f64,
    ) -> PyResult<crate::LWE> {
        translate_error!(self.data.add_with_new_min(&ct.data, new_min))
    }

    /// Compute an homomorphic addition between two LWE ciphertexts
    ///
    /// # Arguments
    /// * `ct` - an LWE struct
    /// * `new_min` - the min of the interval for the resulting Encoder
    ///
    /// # Output
    /// * DimensionError - if the ciphertexts have incompatible dimensions
    /// * DeltaError - if the ciphertexts have incompatible deltas
    /// * PaddingError - if the ciphertexts have incompatible paddings
    /// * NotEnoughPaddingError - if nb bit of padding is zero
    ///
    /// # Example
    /// ```rust
    /// use concrete::*;
    ///
    /// // encoder
    /// let encoder_1 = Encoder::new(100., 110., 8, 0).unwrap();
    /// let encoder_2 = Encoder::new(0., 10., 8, 0).unwrap();
    ///
    /// // generate a secret key
    /// let secret_key = LWESecretKey::new(&LWE128_1024);
    ///
    /// // two lists of messages
    /// let message_1: f64 = 106.276;
    /// let message_2: f64 = 4.9;
    ///
    /// // encode and encrypt
    /// let mut ciphertext_1 = LWE::encode_encrypt(&secret_key, message_1, &encoder_1).unwrap();
    /// let ciphertext_2 = LWE::encode_encrypt(&secret_key, message_2, &encoder_2).unwrap();
    ///
    /// // new_min
    /// let new_min: f64 = 103.;
    ///
    /// // addition between ciphertext_1 and ciphertext_2
    /// ciphertext_1
    ///     .add_with_new_min_inplace(&ciphertext_2, new_min)
    ///     .unwrap();
    /// ```
    pub fn add_with_new_min_inplace(
        &mut self,
        ct: &crate::LWE,
        new_min: f64,
    ) -> PyResult<()> {
        translate_error!(self.data.add_with_new_min_inplace(&ct.data, new_min))
    }

    /// Compute an homomorphic addition between two LWE ciphertexts.
    /// The center of the output Encoder is the sum of the two centers of the input Encoders.
    /// # Arguments
    /// * `ct` - an LWE struct
    ///
    /// # Output
    /// * a new LWE
    /// ```rust
    /// use concrete::*;
    ///
    /// let min_1: f64 = 85.;
    /// let min_2: f64 = -2.;
    /// let delta: f64 = 34.5;
    ///
    /// let max_1: f64 = min_1 + delta;
    /// let max_2: f64 = min_2 + delta;
    ///
    /// let (precision, padding) = (5, 2);
    /// let margin: f64 = 10.;
    ///
    /// // encoder
    /// let encoder_1 = Encoder::new(min_1 - margin, max_1 + margin, precision, padding).unwrap();
    /// let encoder_2 = Encoder::new(min_2 - margin, max_2 + margin, precision, padding).unwrap();
    ///
    /// // generate a secret key
    /// let secret_key = LWESecretKey::new(&LWE128_1024);
    ///
    /// // two lists of messages
    /// let message_1: f64 = 106.276;
    /// let message_2: f64 = 4.9;
    ///
    /// // encode and encrypt
    /// let ciphertext_1 = LWE::encode_encrypt(&secret_key, message_1, &encoder_1).unwrap();
    /// let ciphertext_2 = LWE::encode_encrypt(&secret_key, message_2, &encoder_2).unwrap();
    ///
    /// // addition between ciphertext_1 and ciphertext_2
    /// let new_ciphertext = ciphertext_1.add_centered(&ciphertext_2).unwrap();
    /// ```
    pub fn add_centered(&self, ct: &crate::LWE) -> PyResult<crate::LWE> {
        translate_error!(self.data.add_centered(&ct.data))
    }

    /// Compute an homomorphic addition between two LWE ciphertexts.
    /// The center of the output Encoder is the sum of the two centers of the input Encoders
    ///
    /// # Arguments
    /// * `ct` - an LWE struct
    ///
    /// # Output
    /// * DimensionError - if the ciphertexts have incompatible dimensions
    /// * DeltaError - if the ciphertexts have incompatible deltas
    ///
    /// # Example
    /// ```rust
    /// use concrete::*;
    ///
    /// let min_1: f64 = 85.;
    /// let min_2: f64 = -2.;
    /// let delta: f64 = 34.5;
    ///
    /// let max_1: f64 = min_1 + delta;
    /// let max_2: f64 = min_2 + delta;
    ///
    /// let (precision, padding) = (5, 2);
    /// let margin: f64 = 10.;
    ///
    /// // encoder
    /// let encoder_1 = Encoder::new(min_1 - margin, max_1 + margin, precision, padding).unwrap();
    /// let encoder_2 = Encoder::new(min_2 - margin, max_2 + margin, precision, padding).unwrap();
    ///
    /// // generate a secret key
    /// let secret_key = LWESecretKey::new(&LWE128_1024);
    ///
    /// // two lists of messages
    /// let message_1: f64 = 106.276;
    /// let message_2: f64 = 4.9;
    ///
    /// // encode and encrypt
    /// let mut ciphertext_1 = LWE::encode_encrypt(&secret_key, message_1, &encoder_1).unwrap();
    /// let ciphertext_2 = LWE::encode_encrypt(&secret_key, message_2, &encoder_2).unwrap();
    ///
    /// // addition between ciphertext_1 and ciphertext_2
    /// ciphertext_1.add_centered_inplace(&ciphertext_2).unwrap();
    /// ```
    pub fn add_centered_inplace(&mut self, ct: &crate::LWE) -> PyResult<()> {
        translate_error!(self.data.add_centered_inplace(&ct.data))
    }

    /// Compute an addition between two LWE ciphertexts by eating one bit of padding.
    /// Note that the number of bits of message stays the same: min(nb1,nb2)
    ///
    /// # Argument
    /// * `ct` - an LWE struct
    ///
    /// # Output
    /// * a new LWE
    /// * DimensionError - if the ciphertexts have incompatible dimensions
    /// * DeltaError - if the ciphertexts have incompatible deltas
    /// * PaddingError - if the ciphertexts have incompatible paddings
    /// * NotEnoughPaddingError - if nb bit of padding is zero
    ///
    /// # Example
    /// ```rust
    /// use concrete::*;
    ///
    /// // encoder
    /// let encoder_1 = Encoder::new(100., 110., 8, 1).unwrap();
    /// let encoder_2 = Encoder::new(0., 10., 8, 1).unwrap();
    ///
    /// // generate a secret key
    /// let secret_key = LWESecretKey::new(&LWE128_1024);
    ///
    /// // two lists of messages
    /// let message_1: f64 = 106.276;
    /// let message_2: f64 = 4.9;
    ///
    /// // encode and encrypt
    /// let ciphertext_1 = LWE::encode_encrypt(&secret_key, message_1, &encoder_1).unwrap();
    /// let ciphertext_2 = LWE::encode_encrypt(&secret_key, message_2, &encoder_2).unwrap();
    ///
    /// let ct_add = ciphertext_1.add_with_padding(&ciphertext_2);
    /// ```
    pub fn add_with_padding(&self, ct: &crate::LWE) -> PyResult<crate::LWE> {
        translate_error!(self.add_with_padding(&ct.data))
    }

    /// Compute an addition between two LWE ciphertexts by eating one bit of padding.
    /// Note that the number of bits of message stays the same: min(nb1,nb2)
    ///
    /// # Argument
    /// * `ct` - an LWE struct
    ///
    /// # Output
    /// * DimensionError - if the ciphertexts have incompatible dimensions
    /// * DeltaError - if the ciphertexts have incompatible deltas
    /// * PaddingError - if the ciphertexts have incompatible paddings
    /// * NotEnoughPaddingError - if nb bit of padding is zero
    ///
    /// # Example
    /// ```rust
    /// use concrete::*;
    ///
    /// // encoder
    /// let encoder_1 = Encoder::new(100., 110., 8, 1).unwrap();
    /// let encoder_2 = Encoder::new(0., 10., 8, 1).unwrap();
    ///
    /// // generate a secret key
    /// let secret_key = LWESecretKey::new(&LWE128_1024);
    ///
    /// // two lists of messages
    /// let message_1: f64 = 106.276;
    /// let message_2: f64 = 4.9;
    ///
    /// // encode and encrypt
    /// let mut ciphertext_1 = LWE::encode_encrypt(&secret_key, message_1, &encoder_1).unwrap();
    /// let ciphertext_2 = LWE::encode_encrypt(&secret_key, message_2, &encoder_2).unwrap();
    ///
    /// ciphertext_1.add_with_padding_inplace(&ciphertext_2);
    /// ```
    pub fn add_with_padding_inplace(&mut self, ct: &crate::LWE) -> PyResult<()> {
        translate_error!(self.data.add_with_padding_inplace(&ct.data))
    }

    /// Compute an addition between two LWE ciphertexts by eating one bit of padding.
    /// Note that the number of bits of message increases: max(nb1,nb2) + 1
    ///
    /// # Argument
    /// * `ct` - an LWE struct
    ///
    /// # Output
    /// * a new LWE
    /// * DimensionError - if the ciphertexts have incompatible dimensions
    /// * DeltaError - if the ciphertexts have incompatible deltas
    /// * PaddingError - if the ciphertexts have incompatible paddings
    /// * NotEnoughPaddingError - if nb bit of padding is zero
    ///
    /// # Example
    /// ```rust
    /// use concrete::*;
    ///
    /// // encoder
    /// let encoder_1 = Encoder::new(0., 255., 8, 1).unwrap();
    /// let encoder_2 = Encoder::new(0., 255., 8, 1).unwrap();
    ///
    /// // generate a secret key
    /// let secret_key = LWESecretKey::new(&LWE128_1024);
    ///
    /// // two lists of messages
    /// let message_1: f64 = 106.;
    /// let message_2: f64 = 4.;
    ///
    /// // encode and encrypt
    /// let ciphertext_1 = LWE::encode_encrypt(&secret_key, message_1, &encoder_1).unwrap();
    /// let ciphertext_2 = LWE::encode_encrypt(&secret_key, message_2, &encoder_2).unwrap();
    ///
    /// let ct_add = ciphertext_1.add_with_padding_exact(&ciphertext_2);
    /// ```
    pub fn add_with_padding_exact(&self, ct: &crate::LWE) -> PyResult<crate::LWE> {
        translate_error!(self.data.add_with_padding_exact(&ct.data))
    }

    /// Compute an addition between two LWE ciphertexts by eating one bit of padding.
    /// Note that the number of bits of message increases: max(nb1,nb2) + 1
    ///
    /// # Argument
    /// * `ct` - an LWE struct
    ///
    /// # Output
    /// * DimensionError - if the ciphertexts have incompatible dimensions
    /// * DeltaError - if the ciphertexts have incompatible deltas
    /// * PaddingError - if the ciphertexts have incompatible paddings
    /// * NotEnoughPaddingError - if nb bit of padding is zero
    ///
    /// # Example
    /// ```rust
    /// use concrete::*;
    ///
    /// // encoder
    /// let encoder_1 = Encoder::new(0., 255., 8, 1).unwrap();
    /// let encoder_2 = Encoder::new(0., 255., 8, 1).unwrap();
    ///
    /// // generate a secret key
    /// let secret_key = LWESecretKey::new(&LWE128_1024);
    ///
    /// // two lists of messages
    /// let message_1: f64 = 106.;
    /// let message_2: f64 = 4.;
    ///
    /// // encode and encrypt
    /// let mut ciphertext_1 = LWE::encode_encrypt(&secret_key, message_1, &encoder_1).unwrap();
    /// let ciphertext_2 = LWE::encode_encrypt(&secret_key, message_2, &encoder_2).unwrap();
    ///
    /// ciphertext_1.add_with_padding_exact_inplace(&ciphertext_2);
    /// ```
    pub fn add_with_padding_exact_inplace(
        &mut self,
        ct: &crate::LWE,
    ) -> PyResult<()> {
        translate_error!(self.add_with_padding_exact_inplace(&ct.data))
    }

    /// Compute an subtraction between two LWE ciphertexts by eating one bit of padding.
    /// Note that the number of bits of message stays the same: min(nb1,nb2)
    ///
    /// # Argument
    /// * `ct` - an LWE struct
    ///
    /// # Output
    /// * a new LWE
    /// * DimensionError - if the ciphertexts have incompatible dimensions
    /// * DeltaError - if the ciphertexts have incompatible deltas
    /// * PaddingError - if the ciphertexts have incompatible paddings
    /// * NotEnoughPaddingError - if nb bit of padding is zero
    ///
    /// # Example
    /// ```rust
    /// use concrete::*;
    ///
    /// // encoder
    /// let encoder_1 = Encoder::new(100., 110., 8, 1).unwrap();
    /// let encoder_2 = Encoder::new(0., 10., 8, 1).unwrap();
    ///
    /// // generate a secret key
    /// let secret_key = LWESecretKey::new(&LWE128_1024);
    ///
    /// // two lists of messages
    /// let message_1: f64 = 106.276;
    /// let message_2: f64 = 4.9;
    ///
    /// // encode and encrypt
    /// let ciphertext_1 = LWE::encode_encrypt(&secret_key, message_1, &encoder_1).unwrap();
    /// let ciphertext_2 = LWE::encode_encrypt(&secret_key, message_2, &encoder_2).unwrap();
    ///
    /// let ct_sub = ciphertext_1.add_with_padding(&ciphertext_2);
    /// ```
    pub fn sub_with_padding(&self, ct: &crate::LWE) -> PyResult<crate::LWE> {
        translate_error!(self.data.sub_with_padding(&ct.data))
    }

    /// Compute an subtraction between two LWE ciphertexts by eating one bit of padding.
    /// Note that the number of bits of message stays the same: min(nb1,nb2)
    ///
    /// # Argument
    /// * `ct` - an LWE struct
    ///
    /// # Output
    /// * DimensionError - if the ciphertexts have incompatible dimensions
    /// * DeltaError - if the ciphertexts have incompatible deltas
    /// * PaddingError - if the ciphertexts have incompatible paddings
    /// * NotEnoughPaddingError - if nb bit of padding is zero
    ///
    /// # Example
    /// ```rust
    /// use concrete::*;
    ///
    /// // encoder
    /// let encoder_1 = Encoder::new(100., 110., 8, 1).unwrap();
    /// let encoder_2 = Encoder::new(0., 10., 8, 1).unwrap();
    ///
    /// // generate a secret key
    /// let secret_key = LWESecretKey::new(&LWE128_1024);
    ///
    /// // two lists of messages
    /// let message_1: f64 = 106.276;
    /// let message_2: f64 = 4.9;
    ///
    /// // encode and encrypt
    /// let mut ciphertext_1 = LWE::encode_encrypt(&secret_key, message_1, &encoder_1).unwrap();
    /// let ciphertext_2 = LWE::encode_encrypt(&secret_key, message_2, &encoder_2).unwrap();
    ///
    /// ciphertext_1.sub_with_padding_inplace(&ciphertext_2);
    /// ```
    pub fn sub_with_padding_inplace(&mut self, ct: &crate::LWE) -> PyResult<()> {
        translate_error!(self.data.sub_with_padding_inplace(&ct.data))
    }

    /// Compute an subtraction between two LWE ciphertexts by eating one bit of padding.
    /// Note that the number of bits of message increases: max(nb1,nb2) + 1
    ///
    /// # Argument
    /// * `ct` - an LWE struct
    ///
    /// # Output
    /// * a new LWE
    /// * DimensionError - if the ciphertexts have incompatible dimensions
    /// * DeltaError - if the ciphertexts have incompatible deltas
    /// * PaddingError - if the ciphertexts have incompatible paddings
    /// * NotEnoughPaddingError - if nb bit of padding is zero
    ///
    /// # Example
    /// ```rust
    /// use concrete::*;
    ///
    /// // encoder
    /// let encoder_1 = Encoder::new(0., 255., 8, 1).unwrap();
    /// let encoder_2 = Encoder::new(0., 255., 8, 1).unwrap();
    ///
    /// // generate a secret key
    /// let secret_key = LWESecretKey::new(&LWE128_1024);
    ///
    /// // two lists of messages
    /// let message_1: f64 = 106.;
    /// let message_2: f64 = 4.;
    ///
    /// // encode and encrypt
    /// let ciphertext_1 = LWE::encode_encrypt(&secret_key, message_1, &encoder_1).unwrap();
    /// let ciphertext_2 = LWE::encode_encrypt(&secret_key, message_2, &encoder_2).unwrap();
    ///
    /// let ct_sub = ciphertext_1.sub_with_padding_exact(&ciphertext_2);
    /// ```
    pub fn sub_with_padding_exact(&self, ct: &crate::LWE) -> PyResult<crate::LWE> {
        translate_error!(self.data.sub_with_padding_exact(&ct.data))
    }

    /// Compute an subtraction between two LWE ciphertexts by eating one bit of padding.
    /// Note that the number of bits of message increases: max(nb1,nb2) + 1
    ///
    /// # Argument
    /// * `ct` - an LWE struct
    ///
    /// # Output
    /// * DimensionError - if the ciphertexts have incompatible dimensions
    /// * DeltaError - if the ciphertexts have incompatible deltas
    /// * PaddingError - if the ciphertexts have incompatible paddings
    /// * NotEnoughPaddingError - if nb bit of padding is zero
    ///
    /// # Example
    /// ```rust
    /// use concrete::*;
    ///
    /// // encoder
    /// let encoder_1 = Encoder::new(0., 255., 8, 1).unwrap();
    /// let encoder_2 = Encoder::new(0., 255., 8, 1).unwrap();
    ///
    /// // generate a secret key
    /// let secret_key = LWESecretKey::new(&LWE128_1024);
    ///
    /// // two lists of messages
    /// let message_1: f64 = 106.;
    /// let message_2: f64 = 4.;
    ///
    /// // encode and encrypt
    /// let mut ciphertext_1 = LWE::encode_encrypt(&secret_key, message_1, &encoder_1).unwrap();
    /// let ciphertext_2 = LWE::encode_encrypt(&secret_key, message_2, &encoder_2).unwrap();
    ///
    /// ciphertext_1.sub_with_padding_exact_inplace(&ciphertext_2);
    /// ```
    pub fn sub_with_padding_exact_inplace(
        &mut self,
        ct: &crate::LWE,
    ) -> PyResult<()> {
        translate_error!(self.data.sub_with_padding_exact_inplace(&ct.data)
    }

    /// Multiply LWE ciphertext with small integer message and does not change the encoding but changes the body and mask of the ciphertext
    ///
    /// # Argument
    /// * `messages` - a list of integer messages
    ///
    /// # Output
    /// * a new LWE
    ///
    /// # Example
    /// ```rust
    /// use concrete::*;
    ///
    /// // params
    /// let (min, max): (f64, f64) = (-150., 204.);
    /// let b = min.abs().min(max.abs()) / 20.;
    /// let precision = 6;
    /// let padding = 2;
    ///
    /// // encoder
    /// let encoder = Encoder::new(min, max, precision, padding).unwrap();
    ///
    /// // generate a secret key
    /// let secret_key = LWESecretKey::new(&LWE128_1024);
    ///
    /// // two lists of messages
    /// let message_1: f64 = 6.923;
    /// let message_2: i32= 2;
    ///
    /// // encode and encrypt
    /// let mut ciphertext = LWE::encode_encrypt(&secret_key, message_1, &encoder).unwrap();
    /// let new_ciphertext = ciphertext.mul_constant_static_encoder(message_2).unwrap();
    /// ```
    pub fn mul_constant_static_encoder(&self, message: i32) -> PyResult<crate::LWE> {
        translate_error!(self.data.mul_constant_static_encoder(message))
    }

    /// Multiply LWE ciphertext with small integer message and does not change the encoding but changes the body and mask of the ciphertext
    ///
    /// # Argument
    /// * `messages` - a list of integer messages
    ///
    /// # Example
    /// ```rust
    /// use concrete::*;
    ///
    /// // params
    /// let (min, max): (f64, f64) = (-150., 204.);
    /// let b = min.abs().min(max.abs()) / 20.;
    /// let precision = 6;
    /// let padding = 2;
    ///
    /// // encoder
    /// let encoder = Encoder::new(min, max, precision, padding).unwrap();
    ///
    /// // generate a secret key
    /// let secret_key = LWESecretKey::new(&LWE128_1024);
    ///
    /// // two lists of messages
    /// let message_1: f64 = 6.923;
    /// let message_2: i32= 2;
    ///
    /// // encode and encrypt
    /// let mut ciphertext = LWE::encode_encrypt(&secret_key, message_1, &encoder).unwrap();
    /// ciphertext
    ///     .mul_constant_static_encoder_inplace(message_2)
    ///     .unwrap();
    /// ```
    pub fn mul_constant_static_encoder_inplace(
        &mut self,
        message: i32,
    ) -> PyResult<()> {
        translate_error!(self.data.mul_constant_static_encoder_inplace(message))
    }

    /// Multiply each LWE ciphertext with a real constant and do change the encoding and the ciphertexts by consuming some bits of padding
    /// it needs to have the same number of constant than ciphertexts
    /// it also needs that the input encoding all contained zero in their intervals
    /// the output precision is the minimum between the input and the number of bits of padding consumed
    ///
    /// # Argument
    /// * `scale` - a positive scaling factor which has to be greater that any of the messages.abs()
    /// * `nb_bit_padding` - the number of bits of padding to be consumed
    /// * `messages` - a list of real messages as f64
    ///
    /// # Output
    /// * a new LWE
    ///
    /// # Example
    /// ```rust
    /// use concrete::*;
    ///
    /// // params
    /// let (min, max): (f64, f64) = (-150., 204.);
    /// let precision = 6;
    /// let padding = precision + 3;
    ///
    /// // encoder
    /// let encoder = Encoder::new(min, max, precision, padding).unwrap();
    ///
    /// // generate a secret key
    /// let secret_key = LWESecretKey::new(&LWE128_1024);
    ///
    /// // two lists of messages
    /// let message_1: f64 = -106.276;
    /// let message_2: f64 = 2.432;
    /// let b: f64 = 6.;
    ///
    /// // encode and encrypt
    /// let ciphertext = LWE::encode_encrypt(&secret_key, message_1, &encoder).unwrap();
    /// let new_ciphertext = ciphertext
    ///     .mul_constant_with_padding(message_2, b, precision)
    ///     .unwrap();
    /// ```
    pub fn mul_constant_with_padding(
        &self,
        constant: f64,
        max_constant: f64,
        nb_bit_padding: usize,
    ) -> PyResult<crate::LWE> {
        translate_error!(self.data.mul_constant_with_padding(constant, max_constant, nb_bit_padding))
    }

    /// Multiply each LWE ciphertext with a real constant and do change the encoding and the ciphertexts by consuming some bits of padding
    /// it needs to have the same number of constant than ciphertexts
    /// it also needs that the input encoding all contained zero in their intervals
    /// the output precision is the minimum between the input and the number of bits of padding consumed
    ///
    /// # Argument
    /// * `scale` - a positive scaling factor which has to be greater that any of the messages.abs()
    /// * `nb_bit_padding` - the number of bits of padding to be consumed
    /// * `messages` - a list of real messages as f64
    ///
    /// # Output
    /// * ConstantMaximumError - if one element of `constants` if bigger than `max_constant`
    /// * ZeroInIntervalError - if zero is not in the interval described by the encoders
    /// * NotEnoughPaddingError - if there is not enough padding
    ///
    /// # Example
    /// ```rust
    /// use concrete::*;
    ///
    /// // params
    /// let (min, max): (f64, f64) = (-150., 204.);
    /// let precision = 6;
    /// let padding = precision + 3;
    ///
    /// // encoder
    /// let encoder = Encoder::new(min, max, precision, padding).unwrap();
    ///
    /// // generate a secret key
    /// let secret_key = LWESecretKey::new(&LWE128_1024);
    ///
    /// // two lists of messages
    /// let message_1: f64 = -106.276;
    /// let message_2: f64 = 2.432;
    /// let b: f64 = 6.;
    ///
    /// // encode and encrypt
    /// let mut ciphertext = LWE::encode_encrypt(&secret_key, message_1, &encoder).unwrap();
    /// ciphertext
    ///     .mul_constant_with_padding_inplace(message_2, b, precision)
    ///     .unwrap();
    /// ```
    pub fn mul_constant_with_padding_inplace(
        &mut self,
        constant: f64,
        max_constant: f64,
        nb_bit_padding: usize,
    ) -> PyResult<()> {
        translate_error!(self.data.mul_constant_static_encoder_inplace(constant, max_constant, nb_bit_padding))
    }

    /// Compute the opposite of the n-th LWE ciphertext in the structure
    ///
    /// # Output
    /// * a new LWE ciphertext
    ///
    /// # Example
    /// ```rust
    /// use concrete::*;
    ///
    /// // params
    /// let (min, max): (f64, f64) = (-150., 204.);
    /// let precision = 6;
    /// let padding = 5;
    ///
    /// // encoder
    /// let encoder = Encoder::new(min, max, precision, padding).unwrap();
    ///
    /// // generate a secret key
    /// let secret_key = LWESecretKey::new(&LWE128_1024);
    ///
    /// // two lists of messages
    /// let message_1: f64 =-106.276;
    ///
    /// // encode and encrypt
    /// let ciphertext = LWE::encode_encrypt(&secret_key, message_1, &encoder).unwrap();
    ///
    /// let new_ciphertext = ciphertext.opposite().unwrap();
    /// ```
    pub fn opposite(&self) -> PyResult<crate::LWE> {
        translate_error!(self.data.opposite())
    }

    /// Compute the opposite of the n-th LWE ciphertext in the structure
    ///
    /// # Output
    /// * IndexError - if the requested ciphertext does not exist
    /// * InvalidEncoderError - if the encoder of the requested ciphertext is not valid (i.e. with nb_bit_precision = 0 or delta = 0)
    /// # Example
    /// ```rust
    /// use concrete::*;
    ///
    /// // params
    /// let (min, max): (f64, f64) = (-150., 204.);
    /// let precision = 6;
    /// let padding = 5;
    ///
    /// // encoder
    /// let encoder = Encoder::new(min, max, precision, padding).unwrap();
    ///
    /// // generate a secret key
    /// let secret_key = LWESecretKey::new(&LWE128_1024);
    ///
    /// // two lists of messages
    /// let message_1: f64 = -106.276;
    ///
    /// // encode and encrypt
    /// let mut ciphertext = LWE::encode_encrypt(&secret_key, message_1, &encoder).unwrap();
    ///
    /// ciphertext.opposite_inplace().unwrap();
    /// ```
    pub fn opposite_inplace(&mut self) -> PyResult<()> {
        translate_error!(self.data.opposite_inplace())
    }

    /// Compute a key switching operation on every ciphertext from the LWE struct self
    ///
    /// # Argument
    /// * `ksk` - the key switching key
    ///
    /// # Output
    /// * a LWE struct
    ///
    ///
    /// # Example
    /// ```rust
    /// use concrete::*;
    ///
    /// // params
    /// let (min, max): (f64, f64) = (-150., 204.);
    /// let precision = 6;
    /// let padding = 1;
    /// let level: usize = 3;
    /// let base_log: usize = 3;
    ///
    /// // encoder
    /// let encoder = Encoder::new(min, max, precision, padding).unwrap();
    ///
    /// // generate a secret key
    /// let secret_key = LWESecretKey::new(&LWE128_1024);
    ///
    /// // two lists of messages
    /// let message: f64 = -106.276;
    ///
    /// // generate two secret keys
    /// let secret_key_before = LWESecretKey::new(&LWE128_1024);
    /// let secret_key_after = LWESecretKey::new(&LWE128_1024);
    ///
    /// // generate the key switching key
    /// let ksk = LWEKSK::new(&secret_key_before, &secret_key_after, base_log, level);
    ///
    /// // a list of messages that we encrypt
    /// let ciphertext_before =
    ///     LWE::encode_encrypt(&secret_key_before, message, &encoder).unwrap();
    ///
    /// // key switch
    /// let ciphertext_after = ciphertext_before.keyswitch(&ksk).unwrap();
    /// ```
    pub fn keyswitch(&self, ksk: &crate::LWEKSK) -> PyResult<crate::LWE> {
        translate_error!(self.data.keyswitch(&ksk.data))
    }

    /// Compute a bootstrap on the LWE
    ///
    /// # Argument
    /// * `bsk` - the bootstrapping key
    ///
    /// # Output
    /// * a LWE struct
    /// * IndexError - if the requested ciphertext does not exist
    /// * DimensionError - if the bootstrapping key and the input ciphertext have incompatible dimensions
    ///
    /// # Example
    /// ```rust
    /// use concrete::*;
    ///
    /// // params
    /// let (min, max): (f64, f64) = (-150., 204.);
    /// let precision = 4;
    /// let padding = 1;
    /// let level: usize = 3;
    /// let base_log: usize = 3;
    ///
    /// // encoder
    /// let encoder = Encoder::new(min, max, precision, padding).unwrap();
    ///
    /// // generate a secret key
    /// let secret_key = LWESecretKey::new(&LWE128_1024);
    ///
    /// // a message
    /// let message: f64 = -106.276;
    ///
    /// // generate two secret keys
    /// let rlwe_secret_key = RLWESecretKey::new(&RLWE128_1024_1);
    /// let secret_key_before = LWESecretKey::new(&LWE128_630);
    /// let secret_key_after = rlwe_secret_key.to_lwe_secret_key();
    ///
    /// // bootstrapping key
    /// let bootstrapping_key =
    ///     LWEBSK::new(&secret_key_before, &rlwe_secret_key, base_log, level);
    ///
    /// // encode and encrypt
    /// let ciphertext_before =
    ///     LWE::encode_encrypt(&secret_key_before,message, &encoder).unwrap();
    ///
    /// let ciphertext_out = ciphertext_before
    ///     .bootstrap(&bootstrapping_key)
    ///     .unwrap();
    /// ```
    pub fn bootstrap(&self, bsk: &crate::LWEBSK) -> PyResult<crate::LWE> {
        // TODO:
        // self.bootstrap_with_function(bsk, |x| x, &self.encoder)
        self.data.bootstrap_with_function(bsk, |x| x, &self.data.encoder.data)
    }

    /// Compute a bootstrap and apply an arbitrary function to the LWE ciphertext
    ///
    /// # Argument
    /// * `bsk` - the bootstrapping key
    /// * `f` - the function to aply
    /// * `encoder_output` - a list of output encoders
    ///
    /// # Output
    /// * a LWE struct
    /// * IndexError - if the requested ciphertext does not exist
    /// * DimensionError - if the bootstrapping key and the input ciphertext have incompatible dimensions
    ///
    /// # Example
    /// ```rust
    /// use concrete::*;
    ///
    /// // params
    /// let (min, max): (f64, f64) = (-150., 204.);
    /// let precision = 4;
    /// let padding = 1;
    /// let level: usize = 3;
    /// let base_log: usize = 3;
    ///
    /// // encoder
    /// let encoder_input = Encoder::new(min, max, precision, padding).unwrap();
    /// let encoder_output = Encoder::new(0., max, precision, padding).unwrap();
    ///
    /// // generate a secret key
    /// let secret_key = LWESecretKey::new(&LWE128_1024);
    ///
    /// // a message
    /// let message: f64 = -106.276;
    ///
    /// // generate secret keys
    /// let rlwe_secret_key = RLWESecretKey::new(&RLWE128_1024_1);
    /// let secret_key_before = LWESecretKey::new(&LWE128_630);
    /// let secret_key_after = rlwe_secret_key.to_lwe_secret_key();
    ///
    /// // bootstrapping key
    /// let bootstrapping_key =
    ///     LWEBSK::new(&secret_key_before, &rlwe_secret_key, base_log, level);
    ///
    /// // encode and encrypt
    /// let ciphertext_before =
    ///     LWE::encode_encrypt(&secret_key_before, message, &encoder_input).unwrap();
    ///
    /// let ciphertext_out = ciphertext_before
    ///     .bootstrap_with_function(&bootstrapping_key, |x| f64::max(0., x), &encoder_output)
    ///     .unwrap();
    /// ```
    pub fn bootstrap_with_function<F: Fn(f64) -> f64>(
        &self,
        bsk: &crate::LWEBSK,
        f: F,
        encoder_output: &crate::Encoder,
    ) -> PyResult<crate::LWE> {
        // TODO:
        translate_error!(self.data.bootstrap_with_function(&bsk, f, &encoder_output.data))
    }

    /// Multiply two LWE ciphertexts thanks to two bootstrapping procedures
    /// need to have 2 bits of padding at least
    ///
    /// # Argument
    /// * `ct` - an LWE struct containing the second LWE for the multiplication
    /// * `bsk` - the bootstrapping key used to evaluate the function
    /// * `n_self` - the index of the ciphertext to multiply in the self struct
    /// * `n_ct` - the index of the ciphertext to multiply in the ct struct
    ///
    /// # Output
    /// * a LWE struct
    /// * NotEnoughPaddingError - if one of the input does not have at least 2 bits of padding
    ///
    /// # Example
    /// ```rust
    /// use concrete::*;
    ///
    /// // params
    /// let (min_1, max_1): (f64, f64) = (-150., 204.);
    /// let min_2: f64 = 30.;
    /// let max_2: f64 = min_2 + max_1 - min_1;
    ///
    /// let precision = 4;
    /// let padding = 2;
    /// let level: usize = 3;
    /// let base_log: usize = 3;
    ///
    /// // encoder
    /// let encoder_1 = Encoder::new(min_1, max_1, precision, padding).unwrap();
    /// let encoder_2 = Encoder::new(min_2, max_2, precision, padding).unwrap();
    ///
    /// // generate a secret key
    /// let secret_key = LWESecretKey::new(&LWE128_650);
    ///
    /// // two lists of messages
    /// let message_1: f64 = -127.;
    /// let message_2: f64 = 72.7;
    ///
    /// // generate secret keys
    /// let rlwe_secret_key = RLWESecretKey::new(&RLWE128_1024_1);
    /// let secret_key_before = LWESecretKey::new(&LWE128_630);
    /// let secret_key_after = rlwe_secret_key.to_lwe_secret_key();
    ///
    /// // bootstrapping key
    /// let bootstrapping_key =
    ///     LWEBSK::new(&secret_key_before, &rlwe_secret_key, base_log, level);
    ///
    /// // a list of messages that we encrypt
    /// let ciphertext_1 =
    ///     LWE::encode_encrypt(&secret_key_before, message_1, &encoder_1).unwrap();
    ///
    /// let ciphertext_2 =
    ///     LWE::encode_encrypt(&secret_key_before, message_2, &encoder_2).unwrap();
    ///
    /// let ciphertext_out = ciphertext_1
    ///     .mul_from_bootstrap(&ciphertext_2, &bootstrapping_key)
    ///     .unwrap();
    /// ```
    pub fn mul_from_bootstrap(
        &self,
        ct: &crate::LWE,
        bsk: &crate::LWEBSK,
    ) -> PyResult<crate::LWE> {
        translate_error!(self.mul_from_bootstrap(&ct.data, &bsk.data))
    }

    /// Return the size of one LWE ciphertext with the parameters of self
    ///
    /// # Output
    /// * a usize with the size of a single LWE ciphertext
    pub fn get_ciphertext_size(&self) -> usize {
        self.data.dimension + 1
    }

    pub fn save(&self, path: &str) -> PyResult<()> {
        translate_error!(self.data.save(path))
    }

    #[staticmethod]
    pub fn load(path: &str) -> PyResult<LWE> {
        let data = concrete::LWE::load(path).unwrap();
        Ok(LWE{ data })
    }

    /// Removes nb bits of padding
    ///
    /// # Arguments
    /// * `nb` - number of bits of padding to remove
    ///
    /// ```rust
    /// use concrete::*;
    ///
    /// // encoder
    /// let encoder = Encoder::new(-2., 6., 4, 4).unwrap();
    ///
    /// // generate a secret key
    /// let secret_key = LWESecretKey::new(&LWE128_1024);
    ///
    /// // a message
    /// let message: f64 = -1.;
    ///
    /// // encode and encrypt
    /// let mut ciphertext = LWE::encode_encrypt(&secret_key, message, &encoder).unwrap();
    ///
    /// // removing 2 bits of padding
    /// ciphertext.remove_padding_inplace(2).unwrap();
    /// ```
    pub fn remove_padding_inplace(&mut self, nb: usize) -> PyResult<()> {
        translate_error!(self.remove_padding_inplace(nb))
    }

    pub fn __repr__(&self) -> String {
        self.data.to_string()
    }
}

pub fn register(_py: Python, m: &PyModule) -> PyResult<()> {
    m.add_class::<LWE>()?;

    Ok(())
}

