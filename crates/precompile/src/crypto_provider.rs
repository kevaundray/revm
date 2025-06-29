//! Crypto provider abstraction for REVM precompiles
//!
//! This module provides a trait-based abstraction for cryptographic operations
//! used in Ethereum precompiles, allowing downstream users to plug in their own
//! implementations of certain functions - particularly useful for zkVM guest
//! program implementers who might want to add custom precompiles.

use core::fmt;
use primitives::{alloy_primitives::B512, Bytes, B256};

cfg_if::cfg_if! {
    if #[cfg(feature = "c-kzg")] {
        use c_kzg::{Bytes32, Bytes48};
    } else if #[cfg(feature = "kzg-rs")] {
        use kzg_rs::{Bytes32, Bytes48};
    }
}

/// Error returned when attempting to set a crypto provider when one is already set.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CryptoProviderAlreadySetError;

impl fmt::Display for CryptoProviderAlreadySetError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("crypto provider already set")
    }
}

#[cfg(feature = "std")]
impl std::error::Error for CryptoProviderAlreadySetError {}

/// Trait for providing cryptographic operations to REVM precompiles.
///
/// This trait abstracts the core cryptographic operations used across
/// Ethereum precompiles, allowing for custom implementations that can
/// be swapped in at runtime.
pub trait CryptoProvider: Send + Sync + 'static {
    /// Recover the address from an ECDSA signature using secp256k1.
    ///
    /// # Arguments
    /// * `sig` - The 64-byte signature (r + s)
    /// * `recid` - Recovery ID (0 or 1)
    /// * `msg` - The 32-byte message hash
    ///
    /// # Returns
    /// The recovered address as a 20-byte array, or None if recovery fails
    fn ecrecover(&self, sig: &B512, recid: u8, msg: &B256) -> Option<[u8; 20]>;

    /// Compute SHA-256 hash of input data.
    ///
    /// # Arguments
    /// * `input` - Input data to hash
    ///
    /// # Returns
    /// 32-byte SHA-256 hash
    fn sha256(&self, input: &[u8]) -> [u8; 32];

    /// Compute RIPEMD-160 hash of input data.
    ///
    /// # Arguments
    /// * `input` - Input data to hash
    ///
    /// # Returns
    /// 20-byte RIPEMD-160 hash
    fn ripemd160(&self, input: &[u8]) -> [u8; 20];

    /// Compute Blake2f compression function.
    ///
    /// # Arguments
    /// * `rounds` - Number of rounds
    /// * `h` - 8x8 state matrix
    /// * `m` - 16x8 message block
    /// * `t` - 2x8 offset counters
    /// * `f` - Final block indicator flag
    ///
    /// # Returns
    /// Updated 8x8 state matrix
    fn blake2f(
        &self,
        rounds: u32,
        h: [u64; 8],
        m: [u64; 16],
        t: [u64; 2],
        f: bool,
    ) -> [u64; 8];

    /// Verify a KZG proof.
    ///
    /// # Arguments
    /// * `commitment` - 48-byte commitment
    /// * `z` - 32-byte evaluation point
    /// * `y` - 32-byte claimed evaluation
    /// * `proof` - 48-byte KZG proof
    ///
    /// # Returns
    /// true if proof is valid, false otherwise
    fn verify_kzg_proof(
        &self,
        commitment: &[u8; 48],
        z: &[u8; 32],
        y: &[u8; 32],
        proof: &[u8; 48],
    ) -> bool;

    /// Perform BN128 elliptic curve addition.
    ///
    /// # Arguments
    /// * `point1` - First G1 point as 64 bytes (x1, y1)
    /// * `point2` - Second G1 point as 64 bytes (x2, y2)
    ///
    /// # Returns
    /// 64 bytes representing the sum point (x, y), or None if invalid
    fn bn128_add(&self, point1: &[u8; 64], point2: &[u8; 64]) -> Option<[u8; 64]>;

    /// Perform BN128 elliptic curve scalar multiplication.
    ///
    /// # Arguments
    /// * `point` - G1 point as 64 bytes (x, y)
    /// * `scalar` - 32-byte scalar k
    ///
    /// # Returns
    /// 64 bytes representing the result point (x, y), or None if invalid
    fn bn128_mul(&self, point: &[u8; 64], scalar: &[u8; 32]) -> Option<[u8; 64]>;

    /// Perform BN128 pairing check.
    ///
    /// # Arguments
    /// * `pairs` - Slice of (G1, G2) point pairs where G1 is 64 bytes and G2 is 128 bytes
    ///
    /// # Returns
    /// true if pairing check passes, false otherwise, or None if invalid input
    fn bn128_pairing(&self, pairs: &[([u8; 64], [u8; 128])]) -> Option<bool>;

    /// Perform secp256r1 signature verification.
    ///
    /// # Arguments
    /// * `message_hash` - 32-byte message hash
    /// * `r` - 32-byte signature component r
    /// * `s` - 32-byte signature component s
    /// * `public_key_x` - 32-byte public key x coordinate
    /// * `public_key_y` - 32-byte public key y coordinate
    ///
    /// # Returns
    /// true if signature is valid, false otherwise
    fn secp256r1_verify(
        &self,
        message_hash: &[u8; 32],
        r: &[u8; 32],
        s: &[u8; 32],
        public_key_x: &[u8; 32],
        public_key_y: &[u8; 32],
    ) -> bool;

    /// Perform modular exponentiation.
    ///
    /// # Arguments
    /// * `base_len` - Length of base in bytes
    /// * `exp_len` - Length of exponent in bytes  
    /// * `mod_len` - Length of modulus in bytes
    /// * `input` - Concatenated base, exponent, and modulus
    ///
    /// # Returns
    /// Result of (base^exp) mod modulus, or None if invalid
    fn modexp(
        &self,
        base_len: usize,
        exp_len: usize,
        mod_len: usize,
        input: &[u8],
    ) -> Option<Bytes>;

    /// BLS12-381 G1 point addition.
    ///
    /// # Arguments
    /// * `point1` - First G1 point as 128 bytes
    /// * `point2` - Second G1 point as 128 bytes
    ///
    /// # Returns
    /// 128 bytes representing the sum point, or None if invalid
    #[cfg(feature = "blst")]
    fn bls12_381_g1_add(&self, point1: &[u8; 128], point2: &[u8; 128]) -> Option<[u8; 128]>;

    /// BLS12-381 G1 scalar multiplication.
    ///
    /// # Arguments
    /// * `point` - G1 point as 128 bytes
    /// * `scalar` - 32-byte scalar
    ///
    /// # Returns
    /// 128 bytes representing the result point, or None if invalid
    #[cfg(feature = "blst")]
    fn bls12_381_g1_mul(&self, point: &[u8; 128], scalar: &[u8; 32]) -> Option<[u8; 128]>;

    /// BLS12-381 G1 multi-scalar multiplication.
    ///
    /// # Arguments
    /// * `points_and_scalars` - Slice of (G1 point, scalar) pairs where G1 point is 128 bytes and scalar is 32 bytes
    ///
    /// # Returns
    /// 128 bytes representing the result point, or None if invalid
    #[cfg(feature = "blst")]
    fn bls12_381_g1_msm(&self, points_and_scalars: &[([u8; 128], [u8; 32])]) -> Option<[u8; 128]>;

    /// BLS12-381 G2 point addition.
    ///
    /// # Arguments
    /// * `point1` - First G2 point as 256 bytes
    /// * `point2` - Second G2 point as 256 bytes
    ///
    /// # Returns
    /// 256 bytes representing the sum point, or None if invalid
    #[cfg(feature = "blst")]
    fn bls12_381_g2_add(&self, point1: &[u8; 256], point2: &[u8; 256]) -> Option<[u8; 256]>;

    /// BLS12-381 G2 scalar multiplication.
    ///
    /// # Arguments
    /// * `point` - G2 point as 256 bytes
    /// * `scalar` - 32-byte scalar
    ///
    /// # Returns
    /// 256 bytes representing the result point, or None if invalid
    #[cfg(feature = "blst")]
    fn bls12_381_g2_mul(&self, point: &[u8; 256], scalar: &[u8; 32]) -> Option<[u8; 256]>;

    /// BLS12-381 G2 multi-scalar multiplication.
    ///
    /// # Arguments
    /// * `points_and_scalars` - Slice of (G2 point, scalar) pairs where G2 point is 256 bytes and scalar is 32 bytes
    ///
    /// # Returns
    /// 256 bytes representing the result point, or None if invalid
    #[cfg(feature = "blst")]
    fn bls12_381_g2_msm(&self, points_and_scalars: &[([u8; 256], [u8; 32])]) -> Option<[u8; 256]>;

    /// BLS12-381 pairing check.
    ///
    /// # Arguments
    /// * `pairs` - Slice of (G1, G2) point pairs where G1 is 128 bytes and G2 is 256 bytes
    ///
    /// # Returns
    /// true if pairing check passes, false otherwise, or None if invalid input
    #[cfg(feature = "blst")]
    fn bls12_381_pairing(&self, pairs: &[([u8; 128], [u8; 256])]) -> Option<bool>;

    /// BLS12-381 map field element to G1 point.
    ///
    /// # Arguments
    /// * `field_element` - 64-byte field element
    ///
    /// # Returns
    /// 128 bytes representing the mapped G1 point, or None if invalid
    #[cfg(feature = "blst")]
    fn bls12_381_map_fp_to_g1(&self, field_element: &[u8; 64]) -> Option<[u8; 128]>;

    /// BLS12-381 map field element to G2 point.
    ///
    /// # Arguments
    /// * `field_element` - 128-byte field element (Fp2)
    ///
    /// # Returns
    /// 256 bytes representing the mapped G2 point, or None if invalid
    #[cfg(feature = "blst")]
    fn bls12_381_map_fp2_to_g2(&self, field_element: &[u8; 128]) -> Option<[u8; 256]>;
}

/// Global crypto provider instance
static CRYPTO_PROVIDER: std::sync::OnceLock<Box<dyn CryptoProvider>> = std::sync::OnceLock::new();

/// Install a custom crypto provider.
///
/// This function allows setting a custom crypto provider that will be used
/// by all precompiles. It can only be called once - subsequent calls will
/// return an error.
///
/// # Arguments
/// * `provider` - The crypto provider to install
///
/// # Returns
/// * `Ok(())` if the provider was installed successfully
/// * `Err(CryptoProviderAlreadySetError)` if a provider was already set
///
/// # Example
/// ```rust,ignore
/// struct CustomCryptoProvider;
/// impl CryptoProvider for CustomCryptoProvider {
///     // implement required methods...
/// }
/// 
/// install_crypto_provider(Box::new(CustomCryptoProvider))?;
/// ```
pub fn install_crypto_provider(
    provider: Box<dyn CryptoProvider>,
) -> Result<(), CryptoProviderAlreadySetError> {
    CRYPTO_PROVIDER
        .set(provider)
        .map_err(|_| CryptoProviderAlreadySetError)
}

/// Get the current crypto provider.
///
/// If no custom provider has been installed, this will return the default
/// provider that maintains compatibility with the current REVM behavior.
pub fn get_crypto_provider() -> &'static dyn CryptoProvider {
    CRYPTO_PROVIDER.get().map(|p| p.as_ref()).unwrap_or(&DEFAULT_CRYPTO_PROVIDER)
}

/// Default crypto provider that maintains current REVM behavior
static DEFAULT_CRYPTO_PROVIDER: DefaultCryptoProvider = DefaultCryptoProvider;

/// Default implementation of CryptoProvider that maintains current REVM behavior.
///
/// This provider uses the same crypto libraries and implementations as the
/// current REVM precompiles, ensuring full backward compatibility.
pub struct DefaultCryptoProvider;

impl CryptoProvider for DefaultCryptoProvider {
    fn ecrecover(&self, sig: &B512, recid: u8, msg: &B256) -> Option<[u8; 20]> {
        cfg_if::cfg_if! {
            if #[cfg(feature = "secp256k1")] {
                let result = crate::secp256k1::bitcoin_secp256k1::ecrecover(sig, recid, msg);
            } else if #[cfg(feature = "libsecp256k1")] {
                let result = crate::secp256k1::parity_libsecp256k1::ecrecover(sig, recid, msg);
            } else {
                let result = crate::secp256k1::k256::ecrecover(sig, recid, msg);
            }
        }
        
        // Convert Result<B256, Error> to Option<[u8; 20]>
        // The address is the last 20 bytes of the 32-byte result
        result.ok().map(|addr| {
            let mut address = [0u8; 20];
            address.copy_from_slice(&addr[12..]);
            address
        })
    }

    fn sha256(&self, input: &[u8]) -> [u8; 32] {
        use sha2::Digest;
        sha2::Sha256::digest(input).into()
    }

    fn ripemd160(&self, input: &[u8]) -> [u8; 20] {
        use ripemd::Digest;
        let mut hasher = ripemd::Ripemd160::new();
        hasher.update(input);
        hasher.finalize().into()
    }

    fn blake2f(
        &self,
        rounds: u32,
        h: [u64; 8],
        m: [u64; 16],
        t: [u64; 2],
        f: bool,
    ) -> [u64; 8] {
        let mut h_mut = h;
        crate::blake2::algo::compress(rounds as usize, &mut h_mut, m, t, f);
        h_mut
    }

    fn verify_kzg_proof(
        &self,
        commitment: &[u8; 48],
        z: &[u8; 32],
        y: &[u8; 32],
        proof: &[u8; 48],
    ) -> bool {
        cfg_if::cfg_if! {
            if #[cfg(feature = "c-kzg")] {
                use c_kzg::{Bytes32, Bytes48};
                // SAFETY: `#[repr(C)] Bytes48([u8; 48])` and `#[repr(C)] Bytes32([u8; 32])`
                let commitment_bytes = unsafe { &*(commitment.as_ptr().cast::<Bytes48>()) };
                let z_bytes = unsafe { &*(z.as_ptr().cast::<Bytes32>()) };
                let y_bytes = unsafe { &*(y.as_ptr().cast::<Bytes32>()) };
                let proof_bytes = unsafe { &*(proof.as_ptr().cast::<Bytes48>()) };
                crate::kzg_point_evaluation::verify_kzg_proof(commitment_bytes, z_bytes, y_bytes, proof_bytes)
            } else if #[cfg(feature = "kzg-rs")] {
                use kzg_rs::{Bytes32, Bytes48};
                // SAFETY: `#[repr(C)] Bytes48([u8; 48])` and `#[repr(C)] Bytes32([u8; 32])`
                let commitment_bytes = unsafe { &*(commitment.as_ptr().cast::<Bytes48>()) };
                let z_bytes = unsafe { &*(z.as_ptr().cast::<Bytes32>()) };
                let y_bytes = unsafe { &*(y.as_ptr().cast::<Bytes32>()) };
                let proof_bytes = unsafe { &*(proof.as_ptr().cast::<Bytes48>()) };
                crate::kzg_point_evaluation::verify_kzg_proof(commitment_bytes, z_bytes, y_bytes, proof_bytes)
            } else {
                // No KZG backend available, always return false
                false
            }
        }
    }

    fn bn128_add(&self, point1: &[u8; 64], point2: &[u8; 64]) -> Option<[u8; 64]> {
        // Combine points into the expected input format for the existing implementation
        let mut input = [0u8; 128];
        input[..64].copy_from_slice(point1);
        input[64..].copy_from_slice(point2);
        
        // Use the run_add function which handles the full precompile logic
        match crate::bn128::run_add(&input, 0, u64::MAX) {
            Ok(output) => {
                if output.bytes.len() == 64 {
                    let mut result = [0u8; 64];
                    result.copy_from_slice(&output.bytes);
                    Some(result)
                } else {
                    None
                }
            }
            Err(_) => None,
        }
    }

    fn bn128_mul(&self, point: &[u8; 64], scalar: &[u8; 32]) -> Option<[u8; 64]> {
        // Combine point and scalar into the expected input format
        let mut input = [0u8; 96];
        input[..64].copy_from_slice(point);
        input[64..].copy_from_slice(scalar);
        
        // Use the run_mul function which handles the full precompile logic
        match crate::bn128::run_mul(&input, 0, u64::MAX) {
            Ok(output) => {
                if output.bytes.len() == 64 {
                    let mut result = [0u8; 64];
                    result.copy_from_slice(&output.bytes);
                    Some(result)
                } else {
                    None
                }
            }
            Err(_) => None,
        }
    }

    fn bn128_pairing(&self, pairs: &[([u8; 64], [u8; 128])]) -> Option<bool> {
        // Convert pairs into the expected input format
        let mut input = Vec::with_capacity(pairs.len() * 192); // 64 + 128 = 192 bytes per pair
        for (g1, g2) in pairs {
            input.extend_from_slice(g1);
            input.extend_from_slice(g2);
        }
        
        // Use the run_pair function which handles the full precompile logic
        match crate::bn128::run_pair(&input, 0, 0, u64::MAX) {
            Ok(output) => {
                // Check if result indicates success (should be 32 bytes with 1 or 0)
                if output.bytes.len() == 32 {
                    // Last byte should be 1 for success, 0 for failure
                    let result_bytes: [u8; 32] = output.bytes.as_ref().try_into().ok()?;
                    Some(result_bytes[31] == 1)
                } else {
                    None
                }
            }
            Err(_) => None,
        }
    }

    fn secp256r1_verify(
        &self,
        message_hash: &[u8; 32],
        r: &[u8; 32],
        s: &[u8; 32],
        public_key_x: &[u8; 32],
        public_key_y: &[u8; 32],
    ) -> bool {
        // Combine inputs into the expected format for the existing implementation
        let mut input = [0u8; 160];
        input[..32].copy_from_slice(message_hash);
        input[32..64].copy_from_slice(r);
        input[64..96].copy_from_slice(s);
        input[96..128].copy_from_slice(public_key_x);
        input[128..160].copy_from_slice(public_key_y);
        
        crate::secp256r1::verify_impl(&input).is_some()
    }

    fn modexp(
        &self,
        base_len: usize,
        exp_len: usize,
        mod_len: usize,
        input: &[u8],
    ) -> Option<Bytes> {
        // Use the berlin_run function which is the current implementation
        // Construct the input format expected by modexp: base_len + exp_len + mod_len + data
        let mut full_input = Vec::new();
        full_input.extend_from_slice(&(base_len as u32).to_be_bytes()[..]);
        full_input.extend_from_slice(&(exp_len as u32).to_be_bytes()[..]);
        full_input.extend_from_slice(&(mod_len as u32).to_be_bytes()[..]);
        full_input.extend_from_slice(input);
        
        match crate::modexp::berlin_run(&full_input, u64::MAX) {
            Ok(output) => Some(output.bytes),
            Err(_) => None,
        }
    }

    #[cfg(feature = "blst")]
    fn bls12_381_g1_add(&self, point1: &[u8; 128], point2: &[u8; 128]) -> Option<[u8; 128]> {
        // Combine points into the expected input format for the existing implementation
        let mut input = [0u8; 256];
        input[..128].copy_from_slice(point1);
        input[128..].copy_from_slice(point2);
        
        match crate::bls12_381::g1_add::g1_add(&input, u64::MAX) {
            Ok(output) => {
                if output.bytes.len() == 128 {
                    let mut result = [0u8; 128];
                    result.copy_from_slice(&output.bytes);
                    Some(result)
                } else {
                    None
                }
            }
            Err(_) => None,
        }
    }

    #[cfg(feature = "blst")]
    fn bls12_381_g1_mul(&self, point: &[u8; 128], scalar: &[u8; 32]) -> Option<[u8; 128]> {
        // Combine point and scalar into the expected input format
        let mut input = [0u8; 160];
        input[..128].copy_from_slice(point);
        input[128..].copy_from_slice(scalar);
        
        match crate::bls12_381::g1_msm::g1_msm(&input, u64::MAX) {
            Ok(output) => {
                if output.bytes.len() == 128 {
                    let mut result = [0u8; 128];
                    result.copy_from_slice(&output.bytes);
                    Some(result)
                } else {
                    None
                }
            }
            Err(_) => None,
        }
    }

    #[cfg(feature = "blst")]
    fn bls12_381_g1_msm(&self, points_and_scalars: &[([u8; 128], [u8; 32])]) -> Option<[u8; 128]> {
        // Convert pairs into the expected input format
        let mut input = Vec::with_capacity(points_and_scalars.len() * 160); // 128 + 32 = 160 bytes per pair
        for (point, scalar) in points_and_scalars {
            input.extend_from_slice(point);
            input.extend_from_slice(scalar);
        }
        
        match crate::bls12_381::g1_msm::g1_msm(&input, u64::MAX) {
            Ok(output) => {
                if output.bytes.len() == 128 {
                    let mut result = [0u8; 128];
                    result.copy_from_slice(&output.bytes);
                    Some(result)
                } else {
                    None
                }
            }
            Err(_) => None,
        }
    }

    #[cfg(feature = "blst")]
    fn bls12_381_g2_add(&self, point1: &[u8; 256], point2: &[u8; 256]) -> Option<[u8; 256]> {
        // Combine points into the expected input format for the existing implementation
        let mut input = [0u8; 512];
        input[..256].copy_from_slice(point1);
        input[256..].copy_from_slice(point2);
        
        match crate::bls12_381::g2_add::g2_add(&input, u64::MAX) {
            Ok(output) => {
                if output.bytes.len() == 256 {
                    let mut result = [0u8; 256];
                    result.copy_from_slice(&output.bytes);
                    Some(result)
                } else {
                    None
                }
            }
            Err(_) => None,
        }
    }

    #[cfg(feature = "blst")]
    fn bls12_381_g2_mul(&self, point: &[u8; 256], scalar: &[u8; 32]) -> Option<[u8; 256]> {
        // Combine point and scalar into the expected input format
        let mut input = [0u8; 288];
        input[..256].copy_from_slice(point);
        input[256..].copy_from_slice(scalar);
        
        match crate::bls12_381::g2_msm::g2_msm(&input, u64::MAX) {
            Ok(output) => {
                if output.bytes.len() == 256 {
                    let mut result = [0u8; 256];
                    result.copy_from_slice(&output.bytes);
                    Some(result)
                } else {
                    None
                }
            }
            Err(_) => None,
        }
    }

    #[cfg(feature = "blst")]
    fn bls12_381_g2_msm(&self, points_and_scalars: &[([u8; 256], [u8; 32])]) -> Option<[u8; 256]> {
        // Convert pairs into the expected input format
        let mut input = Vec::with_capacity(points_and_scalars.len() * 288); // 256 + 32 = 288 bytes per pair
        for (point, scalar) in points_and_scalars {
            input.extend_from_slice(point);
            input.extend_from_slice(scalar);
        }
        
        match crate::bls12_381::g2_msm::g2_msm(&input, u64::MAX) {
            Ok(output) => {
                if output.bytes.len() == 256 {
                    let mut result = [0u8; 256];
                    result.copy_from_slice(&output.bytes);
                    Some(result)
                } else {
                    None
                }
            }
            Err(_) => None,
        }
    }

    #[cfg(feature = "blst")]
    fn bls12_381_pairing(&self, pairs: &[([u8; 128], [u8; 256])]) -> Option<bool> {
        // Convert pairs into the expected input format
        let mut input = Vec::with_capacity(pairs.len() * 384); // 128 + 256 = 384 bytes per pair
        for (g1, g2) in pairs {
            input.extend_from_slice(g1);
            input.extend_from_slice(g2);
        }
        
        match crate::bls12_381::pairing::pairing(&input, u64::MAX) {
            Ok(output) => {
                if output.bytes.len() == 32 {
                    // Last byte should be 1 for success, 0 for failure
                    let result_bytes: [u8; 32] = output.bytes.as_ref().try_into().ok()?;
                    Some(result_bytes[31] == 1)
                } else {
                    None
                }
            }
            Err(_) => None,
        }
    }

    #[cfg(feature = "blst")]
    fn bls12_381_map_fp_to_g1(&self, field_element: &[u8; 64]) -> Option<[u8; 128]> {
        match crate::bls12_381::map_fp_to_g1::map_fp_to_g1(field_element, u64::MAX) {
            Ok(output) => {
                if output.bytes.len() == 128 {
                    let mut result = [0u8; 128];
                    result.copy_from_slice(&output.bytes);
                    Some(result)
                } else {
                    None
                }
            }
            Err(_) => None,
        }
    }

    #[cfg(feature = "blst")]
    fn bls12_381_map_fp2_to_g2(&self, field_element: &[u8; 128]) -> Option<[u8; 256]> {
        match crate::bls12_381::map_fp2_to_g2::map_fp2_to_g2(field_element, u64::MAX) {
            Ok(output) => {
                if output.bytes.len() == 256 {
                    let mut result = [0u8; 256];
                    result.copy_from_slice(&output.bytes);
                    Some(result)
                } else {
                    None
                }
            }
            Err(_) => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_provider_singleton() {
        // Test that we can get the default provider
        let provider = get_crypto_provider();
        
        // Test basic functionality with default provider
        let hash = provider.sha256(b"hello world");
        assert_eq!(hash.len(), 32);
    }

    #[test]
    fn test_provider_already_set_error() {
        // This test can't actually install a provider because of the global state,
        // but we can test the error type
        let err = CryptoProviderAlreadySetError;
        assert_eq!(format!("{}", err), "crypto provider already set");
    }
}