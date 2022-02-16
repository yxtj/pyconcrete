//! vector_rlwe ciphertext module

use pyo3::prelude::*;
use pyo3::exceptions::*;
// use pyo3::types::{PyList, PyFunction};
use concrete;
use concrete::{Torus};
use super::translate_error;

/// Structure containing a list of RLWE ciphertexts
/// They all have the same dimension (i.e. the length of the RLWE mask).
/// They all have the same number of coefficients in each of their polynomials (which is described by `polynomial_size`).
/// `polynomial_size` has to be a power of 2.
/// `nb_ciphertexts` has to be at least 1.
///
/// # Attributes
/// * `ciphertexts` - the concatenation of all the RLWE ciphertexts of the list
/// * `variances` - the variances of the noise of each RLWE ciphertext of the list
/// * `dimension` - the length the RLWE mask
/// * `polynomial_size` - the number of coefficients in a polynomial
/// * `nb_ciphertexts` - the number of RLWE ciphertexts present in the list
/// * `encoders` - the encoders of each RLWE ciphertext of the list
#[pyclass]
#[derive(Debug, Clone, PartialEq)]
pub struct VectorRLWE {
    // pub ciphertexts: GlweList<Vec<Torus>>,
    // pub variances: Vec<f64>,
    // pub dimension: usize,
    // pub polynomial_size: usize,
    // pub nb_ciphertexts: usize,
    // pub encoders: Vec<crate::Encoder>,
    pub data: concrete::VectorRLWE,
}

#[pymethods]
impl VectorRLWE {
    
    #[getter]
    pub fn get_variances(&self) -> Vec<f64> {
        self.data.variances.clone()
    }

    #[setter]
    pub fn set_variances(&mut self, v: Vec<f64>) {
        self.data.variances = v;
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
    pub fn get_nb_ciphertexts(&self) -> usize {
        self.data.nb_ciphertexts
    }

    #[setter]
    pub fn set_nb_ciphertexts(&mut self, v: usize) {
        self.data.nb_ciphertexts = v;
    }

    #[getter]
    pub fn get_encoders(&self) -> Vec<crate::Encoder> {
        self.data.encoders.iter().map(|x| crate::Encoder{data:x.clone()}).collect()
    }

    // #[setter]
    // pub fn set_encoders(&mut self, v: &Vec<crate::Encoder>) {
    //     self.data.encoders = v;
    // }

    /// Instantiate a new VectorRLWE filled with zeros from a polynomial size, a dimension and a number of ciphertexts
    ///
    /// # Arguments
    /// * `polynomial_size` - the number of coefficients in polynomials
    /// * `dimension` - the length the RLWE mask
    /// * `nb_ciphertexts` - the number of RLWE ciphertexts to be stored in the structure
    ///
    /// # Output
    /// * a new instantiation of an VectorRLWE
    /// * NotPowerOfTwoError if `polynomial_size` is not a power of 2
    /// * ZeroCiphertextsInStructureError if we try to create a structure with no ciphertext in it
    ///
    /// # Example
    /// ```rust
    /// use concrete::*;
    ///
    /// // creates a list of 3 empty RLWE ciphertexts with a polynomial size of 630 and a dimension of 1
    /// let empty_ciphertexts = VectorRLWE::zero(1024, 1, 3).unwrap();
    /// ```
    #[staticmethod]
    pub fn zero(
        polynomial_size: usize,
        dimension: usize,
        nb_ciphertexts: usize,
    ) -> PyResult<crate::VectorRLWE> {
        let data = translate_error!(concrete::VectorRLWE::zero(polynomial_size, dimension, nb_ciphertexts))?;
        Ok(VectorRLWE{ data })
    }

    /// Encrypt several raw plaintexts (list of Torus element instead of a struct Plaintext) with the provided key and standard deviation into one RLWE ciphertext
    /// The slots of the RLWE ciphertext are filled with the provided plaintexts and if there are less plaintexts than slots, we pad with zeros
    ///
    /// # Arguments
    /// * `sk` - an LWE secret key
    /// * `plaintexts` - a list of plaintexts
    /// * `params` - RLWE parameters
    ///
    /// # Output
    /// * a new instantiation of an VectorRLWE encrypting the plaintexts provided in one ciphertext RLWE
    ///
    /// # Example
    /// ```rust
    /// use concrete::*;
    /// // generate a secret key
    /// let dimension: usize = 1;
    /// let polynomial_size: usize = 1024;
    /// let log_std_dev: i32 = -20;
    /// let sk = RLWESecretKey::new(&RLWE128_1024_1);
    ///
    /// // random settings for the encoder and some random messages
    /// let (min, max) = (-43., -10.);
    /// let (precision, padding) = (5, 2);
    /// let encoder = Encoder::new(min, max, precision, padding).unwrap();
    /// let messages: Vec<f64> = vec![-39.69, -19.37, -40.74, -41.26, -35.77];
    ///
    /// // encode
    /// let enc_messages = encoder.encode(&messages).unwrap();
    ///
    /// // encrypt and decrypt
    /// let ct = VectorRLWE::encrypt_packed(&sk, &enc_messages).unwrap();
    /// ```
    #[staticmethod]
    pub fn encrypt_packed(
        sk: &crate::RLWESecretKey,
        plaintexts: &crate::Plaintext,
    ) -> PyResult<crate::VectorRLWE> {
        let data = translate_error!(concrete::VectorRLWE::encrypt_packed(&sk.data, &plaintexts.data))?;
        Ok(VectorRLWE{ data })
    }

    /// Encode and encrypt several messages with the provided key into one RLWE ciphertext
    /// It means that the polynomial encrypted is P(X)=m0+m1X+m2X^2 ... with (m0, m1, m2, ...) the messages that have been encoded
    ///
    /// # Arguments
    /// * `sk` - an LWE secret key
    /// * `messages` - a list of messages
    /// * `encoder` - an encoder
    ///
    /// # Output
    /// * a new instantiation of an VectorRLWE encrypting the plaintexts provided in one RLWE ciphertext
    ///
    /// # Example
    /// ```rust
    /// use concrete::*;
    /// // generate a secret key
    /// let dimension: usize = 1;
    /// let polynomial_size: usize = 1024;
    /// let log_std_dev: i32 = -20;
    /// let sk = RLWESecretKey::new(&RLWE128_1024_1);
    ///
    /// // random settings for the encoder and some random messages
    /// let (min, max) = (-43., -10.);
    /// let (precision, padding) = (5, 2);
    /// let encoder = Encoder::new(min, max, precision, padding).unwrap();
    /// let messages: Vec<f64> = vec![-39.69, -19.37, -40.74, -41.26, -35.77];
    ///
    /// // encode and encrypt
    /// let ct = VectorRLWE::encode_encrypt_packed(&sk, &messages, &encoder).unwrap();
    /// ```
    #[staticmethod]
    pub fn encode_encrypt_packed(
        sk: &crate::RLWESecretKey,
        messages: Vec<f64>,
        encoder: &crate::Encoder,
    ) -> PyResult<VectorRLWE> {
        let data = translate_error!(concrete::VectorRLWE::encode_encrypt_packed(&sk.data, &messages, &encoder.data))?;
        Ok(VectorRLWE{ data })
    }

    /// Encode and encrypt n messages with the provided key into n RLWE ciphertext with only the constant coefficient filled with the message
    /// It means that the polynomial encrypted is P(X)=m with m the message that has been encoded
    ///
    /// # Arguments
    /// * `sk` - an LWE secret key
    /// * `plaintexts` - a list of plaintexts
    ///
    /// # Output
    /// * a new instantiation of an VectorRLWE encrypting the plaintexts provided in as many RLWE ciphertexts as there was messages
    ///
    /// # Example
    /// ```rust
    /// use concrete::*;
    /// // generate a secret key
    /// let dimension: usize = 1;
    /// let polynomial_size: usize = 1024;
    /// let log_std_dev: i32 = -20;
    /// let sk = RLWESecretKey::new(&RLWE128_1024_1);
    ///
    /// // random settings for the encoder and some random messages
    /// let (min, max) = (-43., -10.);
    /// let (precision, padding) = (5, 2);
    /// let encoder = Encoder::new(min, max, precision, padding).unwrap();
    /// let messages: Vec<f64> = vec![-39.69, -19.37, -40.74, -41.26, -35.77];
    ///
    /// // encode
    /// let enc_messages = encoder.encode(&messages).unwrap();
    ///
    /// // encrypt and decrypt
    /// let ct = VectorRLWE::encrypt(&sk, &enc_messages).unwrap();
    /// ```
    #[staticmethod]
    pub fn encrypt(
        sk: &crate::RLWESecretKey,
        plaintexts: &crate::Plaintext,
    ) -> PyResult<VectorRLWE> {
        let data = translate_error!(concrete::VectorRLWE::encrypt(&sk.data, &plaintexts.data))?;
        Ok(VectorRLWE{ data })
    }

    /// Encode and encrypt n messages with the provided key into n RLWE ciphertext with only the constant coefficient filled with the message
    /// It means that the polynomial encrypted is P(X)=m with m the the message that have been encoded
    ///
    /// # Arguments
    /// * `sk` - an LWE secret key
    /// * `messages` - a list of messages
    /// * `encoder` - an encoder
    ///
    /// # Output
    /// * a new instantiation of an VectorRLWE encrypting the plaintexts provided in as many RLWE ciphertexts as there was messages
    ///
    /// # Example
    /// ```rust
    /// use concrete::*;
    /// // generate a secret key
    /// let dimension: usize = 1;
    /// let polynomial_size: usize = 1024;
    /// let log_std_dev: i32 = -20;
    /// let sk = RLWESecretKey::new(&RLWE128_1024_1);
    ///
    /// // random settings for the encoder and some random messages
    /// let (min, max) = (-43., -10.);
    /// let (precision, padding) = (5, 2);
    /// let encoder = Encoder::new(min, max, precision, padding).unwrap();
    /// let messages: Vec<f64> = vec![-39.69, -19.37, -40.74, -41.26, -35.77];
    ///
    /// // encrypt and decrypt
    /// let ct = VectorRLWE::encode_encrypt(&sk, &messages, &encoder).unwrap();
    /// ```
    #[staticmethod]
    pub fn encode_encrypt(
        sk: &crate::RLWESecretKey,
        messages: Vec<f64>,
        encoder: &crate::Encoder,
    ) -> PyResult<VectorRLWE> {
        let data = translate_error!(concrete::VectorRLWE::encode_encrypt(&sk.data, &messages, &encoder.data))?;
        Ok(VectorRLWE{ data })
    }

    /// Encrypt several raw plaintexts (list of Torus element instead of a struct Plaintext) with the provided key and standard deviation into several ciphertexts RLWE (each coefficient of the polynomial plaintexts is filled)
    ///
    /// # Arguments
    /// * `sk` - an LWE secret key
    /// * `plaintexts` - a list of plaintexts
    ///
    /// # Output
    /// * WrongSizeError if the plaintext slice length is not a multiple of polynomial size
    /// * NoNoiseInCiphertextError if the noise distribution is too small for the integer representation
    pub fn encrypt_packed_raw(
        &mut self,
        sk: &crate::RLWESecretKey,
        plaintexts: Vec<Torus>,
    ) -> PyResult<()> {
        translate_error!(self.data.encrypt_packed_raw(&sk.data, &plaintexts))
    }

    /// Compute the decryption of each ciphertext
    ///
    /// # Argument
    /// * `sk` - an glwe secret key
    ///
    /// # Output
    /// * an array of f64
    /// * PolynomialSizeError - if the polynomial size of the secret key and the polynomial size of the RLWE ciphertext are different
    /// * DimensionError - if the dimension of the secret key and the dimension of the RLWE cipertext are different
    ///
    /// # Example
    /// ```rust
    /// use concrete::*;
    /// // generate a secret key
    /// let dimension: usize = 1;
    /// let polynomial_size: usize = 1024;
    /// let log_std_dev: i32 = -20;
    /// let sk = RLWESecretKey::new(&RLWE128_1024_1);
    ///
    /// // random settings for the encoder and some random messages
    /// let (min, max) = (-43., -10.);
    /// let (precision, padding) = (5, 2);
    /// let encoder = Encoder::new(min, max, precision, padding).unwrap();
    /// let messages: Vec<f64> = vec![-39.69, -19.37, -40.74, -41.26, -35.77];
    ///
    /// // encode
    /// let enc_messages = encoder.encode(&messages).unwrap();
    ///
    /// // encrypt and decrypt
    /// let ct = VectorRLWE::encrypt(&sk, &enc_messages).unwrap();
    /// let res = ct.decrypt_decode(&sk).unwrap();
    /// ```
    pub fn decrypt_decode(&self, sk: &crate::RLWESecretKey) -> PyResult<Vec<f64>> {
        translate_error!(self.data.decrypt_decode(&sk.data))
    }

    /// Compute the decryption of each ciphertext in a rounding setting
    ///
    /// # Argument
    /// * `sk` - an glwe secret key
    ///
    /// # Output
    /// * an array of f64
    /// * PolynomialSizeError - if the polynomial size of the secret key and the polynomial size of the RLWE ciphertext are different
    /// * DimensionError - if the dimension of the secret key and the dimension of the RLWE cipertext are different
    ///
    /// # Example
    /// ```rust
    /// use concrete::*;
    /// // generate a secret key
    /// let dimension: usize = 1;
    /// let polynomial_size: usize = 1024;
    /// let log_std_dev: i32 = -20;
    /// let sk = RLWESecretKey::new(&RLWE128_1024_1);
    ///
    /// // random settings for the encoder and some random messages
    /// let (min, max) = (-43., -10.);
    /// let (precision, padding) = (5, 2);
    /// let encoder = Encoder::new(min, max, precision, padding).unwrap();
    /// let messages: Vec<f64> = vec![-39.69, -19.37, -40.74, -41.26, -35.77];
    ///
    /// // encode
    /// let enc_messages = encoder.encode(&messages).unwrap();
    ///
    /// // encrypt and decrypt
    /// let ct = VectorRLWE::encrypt(&sk, &enc_messages).unwrap();
    /// let res = ct.decrypt_decode(&sk).unwrap();
    /// ```
    pub fn decrypt_decode_round(
        &self,
        sk: &crate::RLWESecretKey,
    ) -> PyResult<Vec<f64>> {
        translate_error!(self.data.decrypt_decode_round(&sk.data))
    }

    /// Compute the decryption of each ciphertext and returns also the associated encoder
    /// if nb=3 we return the coefficient 0 of the ciphertext 0,
    /// the coefficient 1 of the ciphertext 0 and the coefficient 2 of the ciphertext 0
    ///
    /// # Argument
    /// * `sk` - an glwe secret key
    /// * `nb` - the number of coeff we want to decrypt
    ///
    /// # Output
    /// * an array of f64
    /// * an array of encoders
    /// * PolynomialSizeError - if the polynomial size of the secret key and the polynomial size of the RLWE ciphertext are different
    /// * DimensionError - if the dimension of the secret key and the dimension of the RLWE cipertext are different
    /// # Example
    /// ```rust
    /// use concrete::*;
    /// // generate a secret key
    /// let dimension: usize = 1;
    /// let polynomial_size: usize = 1024;
    /// let log_std_dev: i32 = -20;
    /// let sk = RLWESecretKey::new(&RLWE128_1024_1);
    ///
    /// // random settings for the encoder and some random messages
    /// let (min, max) = (-43., -10.);
    /// let (precision, padding) = (5, 2);
    /// let encoder = Encoder::new(min, max, precision, padding).unwrap();
    /// let messages: Vec<f64> = vec![-39.69, -19.37, -40.74, -41.26, -35.77];
    ///
    /// // encode
    /// let enc_messages = encoder.encode(&messages).unwrap();
    ///
    /// // encrypt and decrypt
    /// let ct = VectorRLWE::encrypt(&sk, &enc_messages).unwrap();
    /// let (res, encoders) = ct.decrypt_with_encoders(&sk).unwrap();
    /// ```
    pub fn decrypt_with_encoders(
        &self,
        sk: &crate::RLWESecretKey,
    ) -> PyResult<(Vec<f64>, Vec<crate::Encoder>)> {
        let (values, encoders) = translate_error!(self.data.decrypt_with_encoders(&sk.data))?;
        let tmp = encoders.iter().map(|x| crate::Encoder{ data: x.clone() }).collect();
        Ok((values, tmp))
    }

    /// Extract the n_coeff-th coefficient of the n_ciphertext-th RLWE ciphertext
    ///
    /// # Argument
    /// * `n_coeff` - the desired coefficient, starts at zero
    /// * `n_ciphertext` - the desired RLWE ciphertext, starts at zero
    ///
    /// # Output
    /// * the desired LWE as a VectorRLWE structure
    /// * IndexError - if the requested ciphertext does not exist
    /// * MonomialError - if the requested monomial does not exist
    ///
    /// # Example
    /// ```rust
    /// use concrete::*;
    /// // generate a secret key
    /// let dimension: usize = 1;
    /// let polynomial_size: usize = 1024;
    /// let log_std_dev: i32 = -20;
    /// let sk = RLWESecretKey::new(&RLWE128_1024_1);
    ///
    /// // random settings for the encoder and some random messages
    /// let (min, max) = (-43., -10.);
    /// let (precision, padding) = (5, 2);
    /// let encoder = Encoder::new(min, max, precision, padding).unwrap();
    /// let messages: Vec<f64> = vec![-39.69, -19.37, -40.74, -41.26, -35.77];
    ///
    /// // encode and encrypt
    /// let ct = VectorRLWE::encode_encrypt_packed(&sk, &messages, &encoder).unwrap();
    ///
    /// // convert into LWE secret key
    /// let lwe_sk = sk.to_lwe_secret_key();
    ///
    /// // extract a filled coefficient
    /// let n_coeff = 2;
    /// let n_ct = 0;
    /// let res = ct.extract_1_lwe(n_coeff, n_ct).unwrap();
    /// ```
    pub fn extract_1_lwe(
        &self,
        n_coeff: usize,
        n_ciphertext: usize,
    ) -> PyResult<crate::VectorLWE> {
        let data = translate_error!(self.data.extract_1_lwe(n_coeff, n_ciphertext))?;
        Ok(crate::VectorLWE{ data })
    }

    /// Add small messages to a VectorRLWE ciphertext and does not change the encoding but changes the bodies of the ciphertexts
    /// the first message is added to the first coefficient that has a valid encoder
    /// the second message is added to the second coefficient that has a valid encoder
    /// ...
    ///
    /// # Argument
    /// * `messages` - a list of messages as f64
    ///
    /// # Output
    /// * A new VectorRLWE
    /// * NotEnoughValidEncoderError - if messages is bigger than the number of valid encoders
    pub fn add_constant_static_encoder(
        &self,
        messages: Vec<f64>,
    ) -> PyResult<crate::VectorRLWE> {
        let data = translate_error!(self.data.add_constant_static_encoder(&messages))?;
        Ok(VectorRLWE{ data })
    }

    /// Add small messages to a VectorRLWE ciphertext and does not change the encoding but changes the bodies of the ciphertexts
    /// the first message is added to the first coefficient that has a valid encoder
    /// the second message is added to the second coefficient that has a valid encoder
    /// ...
    ///
    /// # Argument
    /// * `messages` - a list of messages as f64
    ///
    /// # Output
    /// * NotEnoughValidEncoderError - if messages is bigger than the number of valid encoders
    pub fn add_constant_static_encoder_inplace(
        &mut self,
        messages: Vec<f64>,
    ) -> PyResult<()> {
        translate_error!(self.data.add_constant_static_encoder_inplace(&messages))
    }

    /// Add messages to an VectorRLWE ciphertext and translate the interval of a distance equal to the message but does not change either the bodies or the masks of the ciphertexts
    /// the first message is added to the first coefficient that has a valid encoder
    /// the second message is added to the second coefficient that has a valid encoder
    /// ...
    ///
    /// # Argument
    /// * `messages` - a list of messages as f64
    ///
    /// # Output
    /// * a new VectorRLWE
    /// * NotEnoughValidEncoderError - if messages is bigger than the number of valid encoders
    pub fn add_constant_dynamic_encoder(
        &self,
        messages: Vec<f64>,
    ) -> PyResult<crate::VectorRLWE> {
        let data = translate_error!(self.data.add_constant_dynamic_encoder(&messages))?;
        Ok(VectorRLWE{ data })
    }

    /// Add messages to an VectorRLWE ciphertext and translate the interval of a distance equal to the message but does not change either the bodies or the masks of the ciphertexts
    /// the first message is added to the first coefficient that has a valid encoder
    /// the second message is added to the second coefficient that has a valid encoder
    /// ...
    ///
    /// # Argument
    /// * `messages` - a list of messages as f64
    /// * NotEnoughValidEncoderError - if messages is bigger than the number of valid encoders
    pub fn add_constant_dynamic_encoder_inplace(
        &mut self,
        messages: Vec<f64>,
    ) -> PyResult<()> {
        translate_error!(self.data.add_constant_dynamic_encoder_inplace(&messages))
    }

    /// Compute an homomorphic addition between two VectorRLWE ciphertexts and the center of the output Encoder is the sum of the two centers of the input Encoders
    ///
    /// # Arguments
    /// * `ct` - an VectorRLWE struct
    ///
    /// # Output
    /// * a new VectorRLWE
    /// * DimensionError - if the ciphertexts have incompatible dimensions
    /// * PolynomialSizeError - if the ciphertexts have incompatible polynomial size
    /// * DeltaError - if the ciphertext encoders have incompatible deltas
    pub fn add_centered(
        &self,
        ct: &crate::VectorRLWE,
    ) -> PyResult<crate::VectorRLWE> {
        let data = translate_error!(self.data.add_centered(&ct.data))?;
        Ok(VectorRLWE{ data })
    }

    /// Compute an homomorphic addition between two VectorRLWE ciphertexts and the center of the output Encoder is the sum of the two centers of the input Encoders
    ///
    /// # Arguments
    /// * `ct` - an VectorRLWE struct
    ///
    /// # Output
    /// * DimensionError - if the ciphertexts have incompatible dimensions
    /// * PolynomialSizeError - if the ciphertexts have incompatible polynomial size
    /// * DeltaError - if the ciphertext encoders have incompatible deltas
    pub fn add_centered_inplace(&mut self, ct: &crate::VectorRLWE) -> PyResult<()> {
        translate_error!(self.data.add_centered_inplace(&ct.data))
    }

    /// Compute an addition between two VectorRLWE ciphertexts by eating one bit of padding
    ///
    /// # Argument
    /// * `ct` - an VectorRLWE struct
    ///
    /// # Output
    /// * DimensionError - if the ciphertexts have incompatible dimensions
    /// * PolynomialSizeError - if the ciphertexts have incompatible polynomial size
    /// * PaddingError - if the ciphertexts ave incompatible paddings
    /// * NotEnoughPaddingError - if there is no padding
    /// * DeltaError - if the ciphertexts have incompatile deltas
    pub fn add_with_padding(
        &self,
        ct: &crate::VectorRLWE,
    ) -> PyResult<crate::VectorRLWE> {
        let data = translate_error!(self.data.add_with_padding(&ct.data))?;
        Ok(VectorRLWE{ data })
    }

    /// Compute an addition between two VectorRLWE ciphertexts by eating one bit of padding
    ///
    /// # Argument
    /// * `ct` - an VectorRLWE struct
    ///
    /// # Output
    /// * a new VectorRLWE
    /// * DimensionError - if the ciphertexts have incompatible dimensions
    /// * PolynomialSizeError - if the ciphertexts have incompatible polynomial size
    /// * PaddingError - if the ciphertexts ave incompatible paddings
    /// * NotEnoughPaddingError - if there is no padding
    /// * DeltaError - if the ciphertexts have incompatile deltas
    pub fn add_with_padding_inplace(
        &mut self,
        ct: &crate::VectorRLWE,
    ) -> PyResult<()> {
        translate_error!(self.data.add_with_padding_inplace(&ct.data))
    }

    /// Compute an addition between two VectorRLWE ciphertexts by eating one bit of padding
    ///
    /// # Argument
    /// * `ct` - an VectorRLWE struct
    ///
    /// # Output
    /// * a new VectorRLWE
    /// * DimensionError - if the ciphertexts have incompatible dimensions
    /// * PolynomialSizeError - if the ciphertexts have incompatible polynomial size
    /// * PaddingError - if the ciphertexts ave incompatible paddings
    /// * NotEnoughPaddingError - if there is no padding
    /// * DeltaError - if the ciphertexts have incompatile deltas
    /// * InvalidEncoderError - if one of the ciphertext have an invalid encoder
    pub fn sub_with_padding(
        &self,
        ct: &crate::VectorRLWE,
    ) -> PyResult<crate::VectorRLWE> {
        let data = translate_error!(self.data.sub_with_padding(&ct.data))?;
        Ok(VectorRLWE{ data })
    }

    /// Compute an addition between two VectorRLWE ciphertexts by eating one bit of padding
    ///
    /// # Argument
    /// * `ct` - an VectorRLWE struct
    ///
    /// # Output
    /// * DimensionError - if the ciphertexts have incompatible dimensions
    /// * PolynomialSizeError - if the ciphertexts have incompatible polynomial size
    /// * PaddingError - if the ciphertexts ave incompatible paddings
    /// * NotEnoughPaddingError - if there is no padding
    /// * DeltaError - if the ciphertexts have incompatile deltas
    pub fn sub_with_padding_inplace(
        &mut self,
        ct: &crate::VectorRLWE,
    ) -> PyResult<()> {
        translate_error!(self.data.sub_with_padding_inplace(&ct.data))
    }

    /// Multiply VectorRLWE ciphertexts with small integer messages and does not change the encoding but changes the bodies and masks of the ciphertexts
    /// # Argument
    /// * `messages` - a list of integer messages as Torus elements
    pub fn mul_constant_static_encoder_inplace(
        &mut self,
        messages: Vec<i32>,
    ) -> PyResult<()> {
        translate_error!(self.data.mul_constant_static_encoder_inplace(&messages))
    }

    /// Multiply each VectorRLWE ciphertext with a real constant and do change the encoding and the ciphertexts by consuming some bits of padding
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
    pub fn mul_constant_with_padding(
        &self,
        constants: Vec<f64>,
        max_constant: f64,
        nb_bit_padding: usize,
    ) -> PyResult<crate::VectorRLWE> {
        let data = translate_error!(self.data.mul_constant_with_padding(&constants, max_constant, nb_bit_padding))?;
        Ok(VectorRLWE{ data })
    }

    /// Multiply each VectorRLWE ciphertext with a real constant and do change the encoding and the ciphertexts by consuming some bits of padding
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
    /// * NbCTError - if the ciphertext and the constants have not the same number of samples
    /// * ConstantMaximumError - if the absolute value of a coefficient in `constants` is bigger than `max_constant`
    /// * ZeroInIntervalError - if 0 is not in the encoder interval
    /// * NotEnoughPaddingError - if there is not enough padding for the operation
    pub fn mul_constant_with_padding_inplace(
        &mut self,
        constants: Vec<f64>,
        max_constant: f64,
        nb_bit_padding: usize,
    ) -> PyResult<()> {
        translate_error!(self.data.mul_constant_with_padding_inplace(&constants, max_constant, nb_bit_padding))
    }

    /// Return the number of valid encoders (i.e. how many messages are carried in those RLWE ciphertexts)
    pub fn nb_valid(&self) -> usize {
        self.data.nb_valid()
    }

    pub fn get_ciphertext_size(&self) -> usize {
        self.data.polynomial_size * (self.data.dimension + 1)
    }

    pub fn save(&self, path: &str) -> PyResult<()> {
        translate_error!(self.data.save(path))
    }

    #[staticmethod]
    pub fn load(path: &str) -> PyResult<VectorRLWE> {
        let data = translate_error!(concrete::VectorRLWE::load(path))?;
        Ok(VectorRLWE{ data })
    }

    pub fn __repr__(&self) -> String {
        self.data.to_string()
    }
}

pub fn register(_py: Python, m: &PyModule) -> PyResult<()> {
    m.add_class::<VectorRLWE>()?;

    Ok(())
}

