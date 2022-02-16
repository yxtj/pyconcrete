//! vector_lwe ciphertext module

use pyo3::prelude::*;
use pyo3::exceptions::*;
use pyo3::types::{PyList, PyFunction};
use concrete;
use concrete::{Torus};
use super::translate_error;

/// Structure containing a list of LWE ciphertexts.
/// They all have the same dimension (i.e. the length of the LWE mask).
///
/// # Attributes
/// * `ciphertexts` - the concatenation of all the LWE ciphertexts of the list
/// * `variances` - the variances of the noise of each LWE ciphertext of the list
/// * `dimension` - the length the LWE mask
/// * `nb_ciphertexts` - the number of LWE ciphertexts present in the list
/// * `encoders` - the encoders of each LWE ciphertext of the list
#[pyclass]
#[derive(Debug, Clone, PartialEq)]
pub struct VectorLWE {
    // pub ciphertexts: LweList<Vec<Torus>>,
    // pub variances: Vec<f64>,
    // pub dimension: usize,
    // pub nb_ciphertexts: usize,
    // pub encoders: Vec<crate::Encoder>,
    pub data: concrete::VectorLWE,
}

#[pymethods]
impl VectorLWE {

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

    /// Instantiate a new VectorLWE filled with zeros from a dimension and a number of ciphertexts
    /// `nb_ciphertexts` has to be at least 1.
    ///
    /// # Arguments
    /// * `dimension` - the length the LWE mask
    /// * `nb_ciphertexts` - the number of LWE ciphertexts to be stored in the structure
    ///
    /// # Output
    /// * a new instantiation of an VectorLWE
    /// * ZeroCiphertextsInStructureError if we try to create a structure with no ciphertext in it
    ///
    /// # Example
    /// ```rust
    /// use concrete::*;
    ///
    /// // creates a list of 5 empty LWE ciphertexts with a dimension of 630
    /// let empty_ciphertexts = VectorLWE::zero(630, 5).unwrap();
    /// ```
    #[staticmethod]
    pub fn zero(
        dimension: usize,
        nb_ciphertexts: usize,
    ) -> PyResult<crate::VectorLWE> {
        let data = translate_error!(concrete::VectorLWE::zero(dimension, nb_ciphertexts))?;
        Ok(VectorLWE{ data })
    }

    /// Copy one ciphertext from an VectorLWE structure inside the self VectorLWE structure
    /// i.e. copy the ct_index-th LWE ciphertext from ct inside the self_index-th of self
    ///
    /// # Arguments
    /// * `self_index` - the index in self we will paste the ciphertext
    /// * `ct` - the VectorLWE structure we will copy a ciphertext from
    /// * `ct_index` - the index of the ciphertext in ct we will copy
    ///
    /// # Output
    /// * DimensionError if self and ct does not share the same dimension
    /// * IndexError if self_index >= self.nb_ciphertexts
    /// * IndexError if ct_index >= ct.nb_ciphertexts
    ///
    /// # Example
    /// ```rust
    /// use concrete::*;
    /// // creates a list of 5 empty LWE ciphertexts with a dimension of 630
    /// let mut ct1 = VectorLWE::zero(630, 5).unwrap();
    /// // creates a list of 8 empty LWE ciphertexts with a dimension of 630
    /// let ct2 = VectorLWE::zero(630, 8).unwrap();
    ///
    /// // copy the last ciphertext of ct2 at the first position of ct1
    /// ct1.copy_in_nth_nth_inplace(0, &ct2, 7).unwrap();
    /// ```
    pub fn copy_in_nth_nth_inplace(
        &mut self,
        self_index: usize,
        ct: &VectorLWE,
        ct_index: usize,
    ) -> PyResult<()> {
        translate_error!(self.data.copy_in_nth_nth_inplace(self_index, &ct.data, ct_index))
    }

    /// extract the n-th of the LWE ciphertexts from an VectorLWE structure and output a new VectorLWE structure with only a copy of this ciphertext
    ///
    /// # Arguments
    /// * `n` - the index the ciphertext to extract
    ///
    /// # Output
    /// * IndexError if n >= self.nb_ciphertexts
    ///
    /// # Example
    /// ```rust
    /// use concrete::*;
    ///
    /// // creates a list of 6 empty LWE ciphertexts with a dimension of 630
    /// let ct = VectorLWE::zero(630, 6).unwrap();
    ///
    /// // extract the first ciphertext of ct
    /// let ct_extracted = ct.extract_nth(0).unwrap();
    /// ```
    pub fn extract_nth(&self, n: usize) -> PyResult<crate::VectorLWE> {
        let data = translate_error!(self.data.extract_nth(n))?;
        Ok(VectorLWE{ data })
    }

    /// Encrypt plaintexts from a Plaintext with the provided LWEParams
    ///
    /// # Arguments
    /// * `sk` - an LWESecretKey
    /// * `plaintexts` - a Plaintext
    ///
    /// # Output
    /// * VectorLWE structure
    ///
    /// # Example
    /// ```rust
    /// use concrete::*;
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
    /// // create an LWESecretKey
    /// let sk = LWESecretKey::new(&LWE128_630);
    ///
    /// // create a new VectorLWE that encrypts pt
    /// let ct = VectorLWE::encrypt(&sk, &pt);
    /// ```
    #[staticmethod]
    pub fn encrypt(
        sk: &crate::LWESecretKey,
        plaintexts: &crate::Plaintext,
    ) -> PyResult<crate::VectorLWE> {
        let data = translate_error!(concrete::VectorLWE::encrypt(&sk.data, &plaintexts.data))?;
        Ok(VectorLWE{ data })
    }

    /// Encode messages and then directly encrypt the plaintexts into an VectorLWE structure
    ///
    /// # Arguments
    /// * `sk` - an LWE secret key
    /// * `messages` -  a list of messages as u64
    /// * `encoder` - an Encoder
    ///
    /// # Output
    /// an VectorLWE structure
    ///
    /// # Example
    /// ```rust
    /// use concrete::*;
    ///
    /// // encoder
    /// let encoder = Encoder::new(-2., 6., 4, 4).unwrap();
    ///
    /// // generate a secret key
    /// let secret_key = LWESecretKey::new(&LWE128_1024);
    ///
    /// // two lists of messages
    /// let messages: Vec<f64> = vec![-1., 2., 0., 5., -0.5];
    ///
    /// // encode and encrypt
    /// let mut ciphertext = VectorLWE::encode_encrypt(&secret_key, &messages, &encoder).unwrap();
    /// ```
    #[staticmethod]
    pub fn encode_encrypt(
        sk: &crate::LWESecretKey,
        messages: Vec<f64>,
        encoder: &crate::Encoder,
    ) -> PyResult<VectorLWE> {
        let data = translate_error!(concrete::VectorLWE::encode_encrypt(
            &sk.data, &messages, &encoder.data))?;
        Ok(VectorLWE{ data })
    }

    /// Encode messages with a different encoder for each message and encrypt them
    ///
    /// # Arguments
    /// * `sk` - an LWE secret key
    /// * `messages` -  a list of messages as u64
    /// * `encoders` - a list of Encoder elements
    ///
    /// # Output
    /// an VectorLWE structure
    ///
    /// # Example
    /// ```rust
    /// use concrete::*;
    ///
    /// // a list of encoders
    /// let encoders = [
    ///     Encoder::new(-2., 6., 4, 4).unwrap(),
    ///     Encoder::new(0., 3., 3, 2).unwrap(),
    ///     Encoder::new(4., 6., 2, 1).unwrap(),
    ///     Encoder::new(-1., 1., 5, 0).unwrap()];
    ///
    /// // generate a secret key
    /// let secret_key = LWESecretKey::new(&LWE128_1024);
    ///
    /// // two lists of messages
    /// let messages: Vec<f64> = vec![-1., 2., 5., -0.5];
    ///
    /// // encode and encrypt
    /// let mut ciphertext = VectorLWE::encode_encrypt_several_encoders(&secret_key, &messages, &encoders).unwrap();
    /// ```
    // pub fn encode_encrypt_several_encoders(
    //     sk: &crate::LWESecretKey,
    //     messages: &[f64],
    //     encoders: &[crate::Encoder],
    // ) -> PyResult<VectorLWE> {
    #[staticmethod]
    pub fn encode_encrypt_several_encoders(
        sk: &crate::LWESecretKey,
        messages: Vec<f64>,
        encoders: &PyList,
    ) -> PyResult<VectorLWE> {
        let tmp: Vec<concrete::Encoder> = encoders.iter().map(
            |x| x.extract::<crate::Encoder>().unwrap().data).collect();
        let data = translate_error!(concrete::VectorLWE::encode_encrypt_several_encoders(
            &sk.data, &messages, &tmp))?;
        Ok(VectorLWE{ data })
    }

    /// Encrypt plaintexts from a Plaintext with the provided LWEParams
    ///
    /// # Arguments
    /// * `sk` - an LWE secret key
    /// * `plaintexts` - a list of plaintexts
    /// * `params` - LWE parameters
    ///
    /// # Example
    /// ```rust
    /// use concrete::*;
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
    /// // create an LWESecretKey
    /// let sk = LWESecretKey::new(&LWE128_630);
    ///
    /// // create a new VectorLWE that encrypts pt
    /// let mut ct = VectorLWE::zero(sk.dimension, messages.len()).unwrap();
    /// ct.encrypt_inplace(&sk, &pt).unwrap();
    /// ```
    pub fn encrypt_inplace(
        &mut self,
        sk: &crate::LWESecretKey,
        plaintexts: &crate::Plaintext,
    ) -> PyResult<()> {
        translate_error!(self.data.encrypt_inplace(&sk.data, &plaintexts.data))
    }

    /// Encrypt several raw plaintexts (list of Torus element instead of a struct Plaintext) with the provided key and standard deviation
    /// # Arguments
    /// * `sk` - an LWE secret key
    /// * `plaintexts` - a list of plaintexts
    /// * `std_dev` - the standard deviation used for the error normal distribution
    ///
    /// # Example
    /// ```rust
    /// use concrete::*;
    ///
    /// // create an Encoder instance where messages are in the interval [-5, 5[
    /// let encoder = Encoder::new(-5., 5., 8, 0).unwrap();
    ///
    /// // create a list plaintexts
    /// let pt: Vec<u64> = vec![0; 5];
    ///
    /// // create one LWESecretKey
    /// let sk = LWESecretKey::new(&LWE128_630);
    ///
    /// // create a new VectorLWE that encrypts pt
    /// let mut ct = VectorLWE::zero(sk.dimension, pt.len()).unwrap();
    /// ct.encrypt_raw(&sk, &pt).unwrap();
    /// ```
    pub fn encrypt_raw(
        &mut self,
        sk: &crate::LWESecretKey,
        plaintexts: Vec<Torus>,
    ) -> PyResult<()> {
        translate_error!(self.data.encrypt_raw(&sk.data, &plaintexts))
    }

    /// Decrypt the list of ciphertexts, meaning compute the phase and directly decode the output
    ///
    /// # Arguments
    /// * `sk` - an LWE secret key
    /// # Output
    /// * `result` - a list of messages as f64
    /// * DimensionError - if the ciphertext and the key have incompatible dimensions
    /// ```rust
    /// use concrete::*;
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
    /// // create an LWESecretKey
    /// let sk = LWESecretKey::new(&LWE128_630);
    ///
    /// // create a new VectorLWE that encrypts pt
    /// let mut ct = VectorLWE::zero(sk.dimension, messages.len()).unwrap();
    /// ct.encrypt_inplace(&sk, &pt).unwrap();
    ///
    /// let res = ct.decrypt_decode(&sk).unwrap();
    /// ```
    pub fn decrypt_decode(&self, sk: &crate::LWESecretKey) -> PyResult<Vec<f64>> {
        translate_error!(self.data.decrypt_decode(&sk.data))
    }

    /// Decrypt the list of ciphertexts, meaning compute the phase and directly decode the output
    ///
    /// # Arguments
    /// * `sk` - an LWE secret key
    /// # Output
    /// * `result` - a list of messages as f64
    /// * DimensionError - if the ciphertext and the key have incompatible dimensions
    /// ```rust
    /// use concrete::*;
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
    /// // create an LWESecretKey
    /// let sk = LWESecretKey::new(&LWE128_630);
    ///
    /// // create a new VectorLWE that encrypts pt
    /// let mut ct = VectorLWE::zero(sk.dimension, messages.len()).unwrap();
    /// ct.encrypt_inplace(&sk, &pt).unwrap();
    ///
    /// let res = ct.decrypt_raw(&sk).unwrap();
    /// ```
    pub fn decrypt_raw(&self, sk: &crate::LWESecretKey) -> PyResult<Vec<u64>> {
        translate_error!(self.data.decrypt_raw(&sk.data))
    }

    /// Decrypt the list of ciphertexts, meaning compute the phase and directly decode the output as if the encoder was set in round mode
    ///
    /// # Arguments
    /// * `sk` - an LWE secret key
    /// # Output
    /// * `result` - a list of messages as f64
    /// * DimensionError - if the ciphertext and the key have incompatible dimensions
    /// ```rust
    /// use concrete::*;
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
    /// // create an LWESecretKey
    /// let sk = LWESecretKey::new(&LWE128_630);
    ///
    /// // create a new VectorLWE that encrypts pt
    /// let mut ct = VectorLWE::zero(sk.dimension, messages.len()).unwrap();
    /// ct.encrypt_inplace(&sk, &pt).unwrap();
    ///
    /// let res = ct.decrypt_decode(&sk).unwrap();
    /// ```
    pub fn decrypt_decode_round(
        &self,
        sk: &crate::LWESecretKey,
    ) -> PyResult<Vec<f64>> {
        translate_error!(self.data.decrypt_decode_round(&sk.data))
    }

    /// Add small messages to a VectorLWE ciphertext and does not change the encoding but changes the bodies of the ciphertexts
    ///
    /// # Argument
    /// * `messages` - a list of messages as f64
    ///
    /// # Output
    /// * a new VectorLWE
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
    /// let messages_1: Vec<f64> = vec![106.276, 104.3, 100.12, 101.1, 107.78];
    /// let messages_2: Vec<f64> = vec![-4.9, 1.02, 4.6, 5.6, -3.2];
    ///
    /// // encode and encrypt
    /// let plaintext_1 = Plaintext::encode(&messages_1, &encoder).unwrap();
    /// let mut ciphertext = VectorLWE::encrypt(&secret_key, &plaintext_1).unwrap();
    ///
    /// // addition between ciphertext and messages_2
    /// let ct_add = ciphertext.add_constant_static_encoder(&messages_2).unwrap();
    /// ```
    pub fn add_constant_static_encoder(
        &self,
        messages: Vec<f64>,
    ) -> PyResult<crate::VectorLWE> {
        let data = translate_error!(self.data.add_constant_static_encoder(&messages))?;
        Ok(VectorLWE{ data })
    }

    /// Add small messages to a VectorLWE ciphertext and does not change the encoding but changes the bodies of the ciphertexts
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
    /// // two lists of messages
    /// let messages_1: Vec<f64> = vec![106.276, 104.3, 100.12, 101.1, 107.78];
    /// let messages_2: Vec<f64> = vec![-4.9, 1.02, 4.6, 5.6, -3.2];
    ///
    /// // encode and encrypt
    /// let plaintext_1 = Plaintext::encode(&messages_1, &encoder).unwrap();
    /// let mut ciphertext = VectorLWE::encrypt(&secret_key, &plaintext_1).unwrap();
    ///
    /// // addition between ciphertext and messages_2
    /// ciphertext
    ///     .add_constant_static_encoder_inplace(&messages_2)
    ///     .unwrap();
    /// ```
    pub fn add_constant_static_encoder_inplace(
        &mut self,
        messages: Vec<f64>,
    ) -> PyResult<()> {
        translate_error!(self.data.add_constant_static_encoder_inplace(&messages))
    }

    /// Add messages to a VectorLWE ciphertext and translate the interval of a distance equal to the message but does not change either the bodies or the masks of the ciphertexts
    ///
    /// # Argument
    /// * `messages` - a list of messages as f64
    ///
    /// # Output
    /// * a new VectorLWE
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
    /// let messages_1: Vec<f64> = vec![106.276, 104.3, 100.12, 101.1, 107.78];
    /// let messages_2: Vec<f64> = vec![-4.9, 1.02, 4.6, 5.6, -3.2];
    ///
    /// // encode and encrypt
    /// let plaintext_1 = Plaintext::encode(&messages_1, &encoder).unwrap();
    /// let mut ciphertext = VectorLWE::encrypt(&secret_key, &plaintext_1).unwrap();
    ///
    /// // addition between ciphertext and messages_2
    /// let ct = ciphertext
    ///     .add_constant_dynamic_encoder(&messages_2)
    ///     .unwrap();
    /// ```
    pub fn add_constant_dynamic_encoder(
        &self,
        messages: Vec<f64>,
    ) -> PyResult<crate::VectorLWE> {
        let data = translate_error!(self.data.add_constant_dynamic_encoder(&messages))?;
        Ok(VectorLWE{ data })
    }

    /// Add messages to a VectorLWE ciphertext and translate the interval of a distance equal to the message but does not change either the bodies or the masks of the ciphertexts
    ///
    /// # Argument
    /// * `messages` - a list of messages as f64
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
    /// let messages_1: Vec<f64> = vec![106.276, 104.3, 100.12, 101.1, 107.78];
    /// let messages_2: Vec<f64> = vec![-4.9, 1.02, 4.6, 5.6, -3.2];
    ///
    /// // encode and encrypt
    /// let plaintext_1 = Plaintext::encode(&messages_1, &encoder).unwrap();
    /// let mut ciphertext = VectorLWE::encrypt(&secret_key, &plaintext_1).unwrap();
    ///
    /// // addition between ciphertext and messages_2
    /// ciphertext
    ///     .add_constant_dynamic_encoder_inplace(&messages_2)
    ///     .unwrap();
    /// ```
    pub fn add_constant_dynamic_encoder_inplace(
        &mut self,
        messages: Vec<f64>,
    ) -> PyResult<()> {
        translate_error!(self.data.add_constant_dynamic_encoder_inplace(&messages))
    }

    /// Compute an homomorphic addition between two VectorLWE ciphertexts
    ///
    /// # Arguments
    /// * `ct` - an VectorLWE struct
    /// * `new_min` - the min of the interval for the resulting Encoder
    ///
    /// # Output
    /// * a new VectorLWE
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
    /// let messages_1: Vec<f64> = vec![106.276, 104.3, 100.12, 101.1, 107.78];
    /// let messages_2: Vec<f64> = vec![4.9, 3.02, 4.6, 2.6, 3.2];
    ///
    /// // new_min
    /// let new_min: Vec<f64> = vec![103.; messages_1.len()];
    ///
    /// // encode and encrypt
    /// let ciphertext_1 = VectorLWE::encode_encrypt(&secret_key, &messages_1, &encoder_1).unwrap();
    /// let ciphertext_2 = VectorLWE::encode_encrypt(&secret_key, &messages_2, &encoder_2).unwrap();
    ///
    /// // addition between ciphertext_1 and ciphertext_2
    /// let ct_add = ciphertext_1
    ///     .add_with_new_min(&ciphertext_2, &new_min)
    ///     .unwrap();
    /// ```
    pub fn add_with_new_min(
        &self,
        ct: &crate::VectorLWE,
        new_min: Vec<f64>,
    ) -> PyResult<crate::VectorLWE> {
        let data = translate_error!(self.data.add_with_new_min(&ct.data, &new_min))?;
        Ok(VectorLWE{ data })
    }

    /// Compute an homomorphic addition between two VectorLWE ciphertexts
    ///
    /// # Arguments
    /// * `ct` - an VectorLWE struct
    /// * `new_min` - the min of the interval for the resulting Encoder
    ///
    /// # Output
    /// ** DimensionError - if the ciphertexts have incompatible dimensions
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
    /// let messages_1: Vec<f64> = vec![106.276, 104.3, 100.12, 101.1, 107.78];
    /// let messages_2: Vec<f64> = vec![4.9, 3.02, 4.6, 2.6, 3.2];
    ///
    /// // encode and encrypt
    /// let mut ciphertext_1 = VectorLWE::encode_encrypt(&secret_key, &messages_1, &encoder_1).unwrap();
    /// let ciphertext_2 = VectorLWE::encode_encrypt(&secret_key, &messages_2, &encoder_2).unwrap();
    ///
    /// // new_min
    /// let new_min: Vec<f64> = vec![103.; messages_1.len()];
    ///
    /// // addition between ciphertext_1 and ciphertext_2
    /// ciphertext_1
    ///     .add_with_new_min_inplace(&ciphertext_2, &new_min)
    ///     .unwrap();
    /// ```
    pub fn add_with_new_min_inplace(
        &mut self,
        ct: &crate::VectorLWE,
        new_min: Vec<f64>,
    ) -> PyResult<()> {
        translate_error!(self.data.add_with_new_min_inplace(&ct.data, &new_min))
    }

    /// Compute an homomorphic addition between two VectorLWE ciphertexts.
    /// The center of the output Encoder is the sum of the two centers of the input Encoders.
    /// # Arguments
    /// * `ct` - an VectorLWE struct
    ///
    /// # Output
    /// * a new VectorLWE
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
    /// let messages_1: Vec<f64> = vec![106.276, 104.3, 100.12, 101.1, 107.78];
    /// let messages_2: Vec<f64> = vec![4.9, 3.02, 4.6, 2.6, 3.2];
    ///
    /// // encode and encrypt
    /// let ciphertext_1 = VectorLWE::encode_encrypt(&secret_key, &messages_1, &encoder_1).unwrap();
    /// let ciphertext_2 = VectorLWE::encode_encrypt(&secret_key, &messages_2, &encoder_2).unwrap();
    ///
    /// // addition between ciphertext_1 and ciphertext_2
    /// let new_ciphertext = ciphertext_1.add_centered(&ciphertext_2).unwrap();
    /// ```
    pub fn add_centered(&self, ct: &crate::VectorLWE) -> PyResult<crate::VectorLWE> {
        let data = translate_error!(self.data.add_centered(&ct.data))?;
        Ok(VectorLWE{ data })
    }

    /// Compute an homomorphic addition between two VectorLWE ciphertexts.
    /// The center of the output Encoder is the sum of the two centers of the input Encoders
    ///
    /// # Arguments
    /// * `ct` - an VectorLWE struct
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
    /// let messages_1: Vec<f64> = vec![106.276, 104.3, 100.12, 101.1, 107.78];
    /// let messages_2: Vec<f64> = vec![4.9, 3.02, 4.6, 2.6, 3.2];
    ///
    /// // encode and encrypt
    /// let mut ciphertext_1 = VectorLWE::encode_encrypt(&secret_key, &messages_1, &encoder_1).unwrap();
    /// let ciphertext_2 = VectorLWE::encode_encrypt(&secret_key, &messages_2, &encoder_2).unwrap();
    ///
    /// // addition between ciphertext_1 and ciphertext_2
    /// ciphertext_1.add_centered_inplace(&ciphertext_2).unwrap();
    /// ```
    pub fn add_centered_inplace(&mut self, ct: &crate::VectorLWE) -> PyResult<()> {
        translate_error!(self.data.add_centered_inplace(&ct.data))
    }

    /// Compute an addition between two VectorLWE ciphertexts by eating one bit of padding
    ///
    /// # Argument
    /// * `ct` - an VectorLWE struct
    ///
    /// # Output
    /// * a new VectorLWE
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
    /// let messages_1: Vec<f64> = vec![106.276, 104.3, 100.12, 101.1, 107.78];
    /// let messages_2: Vec<f64> = vec![4.9, 3.02, 4.6, 2.6, 3.2];
    ///
    /// // encode and encrypt
    /// let ciphertext_1 = VectorLWE::encode_encrypt(&secret_key, &messages_1, &encoder_1).unwrap();
    /// let ciphertext_2 = VectorLWE::encode_encrypt(&secret_key, &messages_2, &encoder_2).unwrap();
    ///
    /// let ct_add = ciphertext_1.add_with_padding(&ciphertext_2);
    /// ```
    pub fn add_with_padding(
        &self,
        ct: &crate::VectorLWE,
    ) -> PyResult<crate::VectorLWE> {
        let data = translate_error!(self.data.add_with_padding(&ct.data))?;
        Ok(VectorLWE{ data })
    }

    /// Compute an addition between two VectorLWE ciphertexts by eating one bit of padding
    ///
    /// # Argument
    /// * `ct` - an VectorLWE struct
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
    /// let messages_1: Vec<f64> = vec![106.276, 104.3, 100.12, 101.1, 107.78];
    /// let messages_2: Vec<f64> = vec![4.9, 3.02, 4.6, 2.6, 3.2];
    ///
    /// // encode and encrypt
    /// let mut ciphertext_1 = VectorLWE::encode_encrypt(&secret_key, &messages_1, &encoder_1).unwrap();
    /// let ciphertext_2 = VectorLWE::encode_encrypt(&secret_key, &messages_2, &encoder_2).unwrap();
    ///
    /// ciphertext_1.add_with_padding_inplace(&ciphertext_2);
    /// ```
    pub fn add_with_padding_inplace(
        &mut self,
        ct: &crate::VectorLWE,
    ) -> PyResult<()> {
        translate_error!(self.data.add_with_padding_inplace(&ct.data))
    }

    /// Compute an subtraction between two VectorLWE ciphertexts by eating one bit of padding
    ///
    /// # Argument
    /// * `ct` - an VectorLWE struct
    ///
    /// # Output
    /// * a new VectorLWE
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
    /// let messages_1: Vec<f64> = vec![106.276, 104.3, 100.12, 101.1, 107.78];
    /// let messages_2: Vec<f64> = vec![4.9, 3.02, 4.6, 2.6, 3.2];
    ///
    /// // encode and encrypt
    /// let ciphertext_1 = VectorLWE::encode_encrypt(&secret_key, &messages_1, &encoder_1).unwrap();
    /// let ciphertext_2 = VectorLWE::encode_encrypt(&secret_key, &messages_2, &encoder_2).unwrap();
    ///
    /// let ct_sub = ciphertext_1.add_with_padding(&ciphertext_2);
    /// ```
    pub fn sub_with_padding(
        &self,
        ct: &crate::VectorLWE,
    ) -> PyResult<crate::VectorLWE> {
        let data = translate_error!(self.data.sub_with_padding(&ct.data))?;
        Ok(VectorLWE{ data })
    }

    /// Compute an subtraction between two VectorLWE ciphertexts by eating one bit of padding
    ///
    /// # Argument
    /// * `ct` - an VectorLWE struct
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
    /// let messages_1: Vec<f64> = vec![106.276, 104.3, 100.12, 101.1, 107.78];
    /// let messages_2: Vec<f64> = vec![4.9, 3.02, 4.6, 2.6, 3.2];
    ///
    /// // encode and encrypt
    /// let mut ciphertext_1 = VectorLWE::encode_encrypt(&secret_key, &messages_1, &encoder_1).unwrap();
    /// let ciphertext_2 = VectorLWE::encode_encrypt(&secret_key, &messages_2, &encoder_2).unwrap();
    ///
    /// ciphertext_1.sub_with_padding_inplace(&ciphertext_2);
    /// ```
    pub fn sub_with_padding_inplace(
        &mut self,
        ct: &crate::VectorLWE,
    ) -> PyResult<()> {
        translate_error!(self.data.sub_with_padding_inplace(&ct.data))
    }

    /// Multiply VectorLWE ciphertexts with small integer messages and does not change the encoding but changes the bodies and masks of the ciphertexts
    ///
    /// # Argument
    /// * `messages` - a list of integer messages
    ///
    /// # Output
    /// * a new VectorLWE
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
    /// let messages_1: Vec<f64> = vec![6.923, 3.70, 1.80, 0.394, -7.09];
    /// let messages_2: Vec<i32> = vec![2, 3, 5, -2, 0];
    ///
    /// // encode and encrypt
    /// let mut ciphertext = VectorLWE::encode_encrypt(&secret_key, &messages_1, &encoder).unwrap();
    /// let new_ciphertext = ciphertext.mul_constant_static_encoder(&messages_2).unwrap();
    /// ```
    pub fn mul_constant_static_encoder(
        &self,
        messages: Vec<i32>,
    ) -> PyResult<crate::VectorLWE> {
        let data = translate_error!(self.data.mul_constant_static_encoder(&messages))?;
        Ok(VectorLWE{ data })
    }

    /// Multiply VectorLWE ciphertexts with small integer messages and does not change the encoding but changes the bodies and masks of the ciphertexts
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
    /// let messages_1: Vec<f64> = vec![6.923, 3.70, 1.80, 0.394, -7.09];
    /// let messages_2: Vec<i32> = vec![2, 3, 5, -2, 0];
    ///
    /// // encode and encrypt
    /// let mut ciphertext = VectorLWE::encode_encrypt(&secret_key, &messages_1, &encoder).unwrap();
    /// ciphertext
    ///     .mul_constant_static_encoder_inplace(&messages_2)
    ///     .unwrap();
    /// ```
    pub fn mul_constant_static_encoder_inplace(
        &mut self,
        messages: Vec<i32>,
    ) -> PyResult<()> {
        translate_error!(self.data.mul_constant_static_encoder_inplace(&messages))
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
    /// * a new VectorLWE
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
    /// let messages_1: Vec<f64> = vec![-106.276, 104.3, -100.12, 101.1, -107.78];
    /// let messages_2: Vec<f64> = vec![2.432, 3.87, 5.27, -2.13, 0.56];
    /// let b: f64 = 6.;
    ///
    /// // encode and encrypt
    /// let ciphertext = VectorLWE::encode_encrypt(&secret_key, &messages_1, &encoder).unwrap();
    /// let new_ciphertext = ciphertext
    ///     .mul_constant_with_padding(&messages_2, b, precision)
    ///     .unwrap();
    /// ```
    pub fn mul_constant_with_padding(
        &self,
        constants: Vec<f64>,
        max_constant: f64,
        nb_bit_padding: usize,
    ) -> PyResult<crate::VectorLWE> {
        let data = translate_error!(self.data.mul_constant_with_padding(
            &constants, max_constant, nb_bit_padding))?;
        Ok(VectorLWE{ data })
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
    /// let messages_1: Vec<f64> = vec![-106.276, 104.3, -100.12, 101.1, -107.78];
    /// let messages_2: Vec<f64> = vec![2.432, 3.87, 5.27, -2.13, 0.56];
    /// let b: f64 = 6.;
    ///
    /// // encode and encrypt
    /// let mut ciphertext = VectorLWE::encode_encrypt(&secret_key, &messages_1, &encoder).unwrap();
    /// ciphertext
    ///     .mul_constant_with_padding_inplace(&messages_2, b, precision)
    ///     .unwrap();
    /// ```
    pub fn mul_constant_with_padding_inplace(
        &mut self,
        constants: Vec<f64>,
        max_constant: f64,
        nb_bit_padding: usize,
    ) -> PyResult<()> {
        translate_error!(self.data.mul_constant_with_padding_inplace(
            &constants, max_constant, nb_bit_padding))
    }

    /// Compute the opposite of the n-th LWE ciphertext in the structure
    ///
    /// # Argument
    /// * `n` - index of a LWE ciphertext
    ///
    /// # Output
    /// * a new VectorLWE ciphertext
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
    /// let messages_1: Vec<f64> = vec![-106.276, 104.3, -100.12, 101.1, -107.78];
    ///
    /// // encode and encrypt
    /// let ciphertext = VectorLWE::encode_encrypt(&secret_key, &messages_1, &encoder).unwrap();
    ///
    /// let new_ciphertext = ciphertext.opposite_nth(3).unwrap();
    /// ```
    pub fn opposite_nth(&self, n: usize) -> PyResult<crate::VectorLWE> {
        let data = translate_error!(self.data.opposite_nth(n))?;
        Ok(VectorLWE{ data })
    }

    /// Compute the opposite of the n-th LWE ciphertext in the structure
    ///
    /// # Argument
    /// * `n` - index of a LWE ciphertext
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
    /// let messages_1: Vec<f64> = vec![-106.276, 104.3, -100.12, 101.1, -107.78];
    ///
    /// // encode and encrypt
    /// let mut ciphertext = VectorLWE::encode_encrypt(&secret_key, &messages_1, &encoder).unwrap();
    ///
    /// ciphertext.opposite_nth_inplace(3).unwrap();
    /// ```
    pub fn opposite_nth_inplace(&mut self, n: usize) -> PyResult<()> {
        translate_error!(self.data.opposite_nth_inplace(n))
    }

    /// Compute a key switching operation on every ciphertext from the VectorLWE struct self
    ///
    /// # Argument
    /// * `ksk` - the key switching key
    ///
    /// # Output
    /// * a VectorLWE struct
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
    /// let messages: Vec<f64> = vec![-106.276, 104.3, -100.12, 101.1, -107.78];
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
    ///     VectorLWE::encode_encrypt(&secret_key_before, &messages, &encoder).unwrap();
    ///
    /// // key switch
    /// let ciphertext_after = ciphertext_before.keyswitch(&ksk).unwrap();
    /// ```
    pub fn keyswitch(&self, ksk: &crate::LWEKSK) -> PyResult<crate::VectorLWE> {
        let data = translate_error!(self.data.keyswitch(&ksk.data))?;
        Ok(VectorLWE{ data })
    }

    /// Compute a bootstrap on the n-th LWE from the self VectorLWE structure
    ///
    /// # Argument
    /// * `bsk` - the bootstrapping key
    /// * `n` - the index of the ciphertext to bootstrap
    ///
    /// # Output
    /// * a VectorLWE struct
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
    /// // two lists of messages
    /// let messages: Vec<f64> = vec![-106.276, 104.3, -100.12, 101.1, -107.78];
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
    /// // a list of messages that we encrypt
    /// let ciphertext_before =
    ///     VectorLWE::encode_encrypt(&secret_key_before, &messages, &encoder).unwrap();
    ///
    /// let ciphertext_out = ciphertext_before
    ///     .bootstrap_nth(&bootstrapping_key, 2)
    ///     .unwrap();
    /// ```
    pub fn bootstrap_nth(
        &self,
        bsk: &crate::LWEBSK,
        n: usize,
    ) -> PyResult<crate::VectorLWE> {
        let data = translate_error!(self.data.bootstrap_nth(&bsk.data, n))?;
        Ok(VectorLWE{ data })
    }

    /// Compute a bootstrap and apply an arbitrary function to the given VectorLWE ciphertext
    ///
    /// # Argument
    /// * `bsk` - the bootstrapping key
    /// * `f` - the function to apply
    /// * `encoder_output` - a list of output encoders
    /// * `n` - the index of the ciphertext to bootstrap
    ///
    /// # Output
    /// * a VectorLWE struct
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
    /// // a list of messages
    /// let messages: Vec<f64> = vec![-106.276, 104.3, -100.12, 101.1, -107.78];
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
    /// let ciphertext_before =
    ///     VectorLWE::encode_encrypt(&secret_key_before, &messages, &encoder_input).unwrap();
    ///
    /// let ciphertext_out = ciphertext_before
    ///     .bootstrap_nth_with_function(&bootstrapping_key, |x| f64::max(0., x), &encoder_output, 2)
    ///     .unwrap();
    /// ```
    // pub fn bootstrap_nth_with_function<F: Fn(f64) -> f64>(
    //     &self,
    //     bsk: &crate::LWEBSK,
    //     f: F,
    //     encoder_output: &crate::Encoder,
    //     n: usize,
    // ) -> PyResult<crate::VectorLWE> {
    pub fn bootstrap_nth_with_function(
        &self, bsk: &crate::LWEBSK, f: &PyFunction, encoder_output: &crate::Encoder, n: usize,
    ) -> PyResult<crate::VectorLWE> {
        let fun = |x| f.call1((x,)).unwrap().extract::<f64>().unwrap();
        let data = translate_error!(self.data.bootstrap_nth_with_function(
            &bsk.data, fun, &encoder_output.data, n))?;
        Ok(VectorLWE{ data })
    }

    /// Multiply two LWE ciphertexts thanks to two bootstrapping procedures
    /// need to have 2 bits of padding at least
    ///
    /// # Argument
    /// * `ct` - an VectorLWE struct containing the second LWE for the multiplication
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
    /// let messages_1: Vec<f64> = vec![-127., -36.2, 58.7, 161.1, 69.1];
    /// let messages_2: Vec<f64> = vec![72.7, 377., 59.6, 115.5, 286.3];
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
    ///     VectorLWE::encode_encrypt(&secret_key_before, &messages_1, &encoder_1).unwrap();
    ///
    /// let ciphertext_2 =
    ///     VectorLWE::encode_encrypt(&secret_key_before, &messages_2, &encoder_2).unwrap();
    ///
    /// let ciphertext_out = ciphertext_1
    ///     .mul_from_bootstrap_nth(&ciphertext_2, &bootstrapping_key, 2, 3)
    ///     .unwrap();
    /// ```
    pub fn mul_from_bootstrap_nth(
        &self,
        ct: &crate::VectorLWE,
        bsk: &crate::LWEBSK,
        n_self: usize,
        n_ct: usize,
    ) -> PyResult<crate::VectorLWE> {
        let data = translate_error!(self.data.mul_from_bootstrap_nth(
            &ct.data, &bsk.data, n_self, n_ct))?;
        Ok(VectorLWE{ data })
    }

    /// Return the size of one LWE ciphertext with the parameters of self
    ///
    /// # Output
    /// * a usize with the size of a single LWE ciphertext
    pub fn get_ciphertext_size(&self) -> usize {
        self.data.dimension + 1
    }

    pub fn pp(&self) {
        self.data.pp();
    }

    /// Sum all the LWE ciphertexts contained in self into one single ciphertext and output it as a new VectorLWE
    ///
    /// # Output
    /// * A new VectorLWE containing only one ciphertext
    ///
    /// # Example
    /// ```rust
    /// use concrete::*;
    ///
    /// // params
    /// let (min, max): (f64, f64) = (-150., 204.);
    /// let precision = 4;
    /// let padding = 2;
    /// let level: usize = 3;
    /// let base_log: usize = 3;
    ///
    /// // encoder
    /// let encoder = Encoder::new(min, max, precision, padding).unwrap();
    ///
    /// // generate a secret key
    /// let secret_key = LWESecretKey::new(&LWE128_1024);
    ///
    /// // a list of messages
    /// let messages: Vec<f64> = vec![-106.276, 104.3, -100.12, 101.1];
    ///
    /// // generate a secret key
    /// let secret_key = LWESecretKey::new(&LWE128_1024);
    ///
    /// // a list of messages that we encrypt
    /// let ciphertext = VectorLWE::encode_encrypt(&secret_key, &messages, &encoder).unwrap();
    ///
    /// // sum
    /// let ciphertext_sum = ciphertext.sum_with_padding().unwrap();
    /// ```
    pub fn sum_with_padding(&self) -> PyResult<crate::VectorLWE> {
        let data = translate_error!(self.data.sum_with_padding())?;
        Ok(VectorLWE{ data })
    }

    /// Sum all the LWE ciphertexts contained in self into one single ciphertext and output it as a
    /// new VectorLWE. The output ciphertext will have an encoder with the same size so we need to
    /// provide the min of the output interval
    ///
    /// # Input
    /// * `new_min` - an f64 containing the min of the output encoder
    ///
    /// # Output
    /// * A new VectorLWE containing only one ciphertext
    ///
    /// # Example
    /// ```rust
    /// use concrete::*;
    ///
    /// // params
    /// let (min, max): (f64, f64) = (-150., 204.);
    /// let precision = 4;
    /// let padding = 0;
    /// let level: usize = 3;
    /// let base_log: usize = 3;
    ///
    /// // encoder
    /// let encoder = Encoder::new(min, max, precision, padding).unwrap();
    ///
    /// // generate a secret key
    /// let secret_key = LWESecretKey::new(&LWE128_1024);
    ///
    /// // a list of messages
    /// let messages: Vec<f64> = vec![-106.276, 104.3, -100.12, 101.1];
    ///
    /// // generate a secret key
    /// let secret_key = LWESecretKey::new(&LWE128_1024);
    ///
    /// // a list of messages that we encrypt
    /// let ciphertext = VectorLWE::encode_encrypt(&secret_key, &messages, &encoder).unwrap();
    ///
    /// // sum with a new min
    /// let ciphertext_sum = ciphertext.sum_with_new_min(-50.).unwrap();
    /// ```
    pub fn sum_with_new_min(&self, new_min: f64) -> PyResult<crate::VectorLWE> {
        let data = translate_error!(self.data.sum_with_new_min(new_min))?;
        Ok(VectorLWE{ data })
    }
    
    pub fn save(&self, path: &str) -> PyResult<()> {
        translate_error!(self.data.save(path))
    }

    #[staticmethod]
    pub fn load(path: &str) -> PyResult<VectorLWE> {
        let data = translate_error!(concrete::VectorLWE::load(path))?;
        Ok(VectorLWE{ data })
    }

    pub fn __repr__(&self) -> String {
        self.data.to_string()
    }
}

pub fn register(_py: Python, m: &PyModule) -> PyResult<()> {
    m.add_class::<VectorLWE>()?;

    Ok(())
}

