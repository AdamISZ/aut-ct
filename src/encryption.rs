//A modified copy of : https://github.com/NiiightmareXD/simple_crypt
// 
// I decided to copy this library since it's a single , small module
// and I'm excising the folder stuff and the logging.
//

use std::fs;
use std::path::Path;

use aes_gcm_siv::{
    aead::{generic_array::GenericArray, rand_core::RngCore, Aead, OsRng},
    Aes256GcmSiv, KeyInit, Nonce,
};
use anyhow::{anyhow, Context, Result};
use argon2::Config;
use serde_derive::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
struct PrecryptorFile {
    data: Vec<u8>,
    nonce: [u8; 12],
    salt: [u8; 32],
}

/// Encrypts some data and returns the result
///
/// let encrypted_data = encrypt(b"example text", b"example password").expect("Failed to encrypt");
/// // and now you can write it to a file:
/// // fs::write("encrypted_text.txt", encrypted_data).expect("Failed to write to file");
/// ```
///
pub fn encrypt(data: &[u8], password: &[u8]) -> Result<Vec<u8>> {
    let mut salt = [0u8; 32];
    OsRng.fill_bytes(&mut salt);
    let config = Config {
        hash_length: 32,
        ..Default::default()
    };

    let password = argon2::hash_raw(password, &salt, &config)
        .with_context(|| "Failed to generate key from password")?;

    let key = GenericArray::from_slice(&password);
    let cipher = Aes256GcmSiv::new(key);

    let mut nonce_rand = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_rand);
    let nonce = Nonce::from_slice(&nonce_rand);

    let ciphertext = match cipher.encrypt(nonce, data.as_ref()) {
        Ok(ciphertext) => ciphertext,
        Err(_) => return Err(anyhow!("Failed to encrypt data -> invalid password")),
    };

    let file = PrecryptorFile {
        data: ciphertext,
        nonce: nonce_rand,
        salt,
    };

    let encoded: Vec<u8> = bincode::serialize(&file).with_context(|| "Failed to decode data")?;

    Ok(encoded)
}

/// Decrypts some data and returns the result
///
/// # Examples
///
///
/// let encrypted_data = encrypt(b"example text", b"example password").expect("Failed to encrypt");
///
/// let data = decrypt(&encrypted_data, b"example passowrd").expect("Failed to decrypt");
/// // and now you can print it to stdout:
/// // println!("data: {}", String::from_utf8(data.clone()).expect("Data is not a utf8 string"));
/// // or you can write it to a file:
/// // fs::write("text.txt", data).expect("Failed to write to file");
/// ```
///
pub fn decrypt(data: &[u8], password: &[u8]) -> Result<Vec<u8>> {
    let decoded: PrecryptorFile =
        bincode::deserialize(data).with_context(|| "Failed to decode data")?;

    let config = Config {
        hash_length: 32,
        ..Default::default()
    };

    let password = argon2::hash_raw(password, &decoded.salt, &config)
        .with_context(|| "Failed to generate key from password")?;

    let key = GenericArray::from_slice(&password);
    let cipher = Aes256GcmSiv::new(key);
    let nonce = Nonce::from_slice(&decoded.nonce);

    let text = match cipher.decrypt(nonce, decoded.data.as_ref()) {
        Ok(ciphertext) => ciphertext,
        Err(_) => return Err(anyhow!("Failed to encrypt data -> invalid password")),
    };

    Ok(text)
}

/// Encrypts file data and outputs it to the specified output file
///
/// # Example
///
/// encrypt_file(Path::new("example.txt"), Path::new("encrypted_example.txt"), b"example passwprd").expect("Failed to encrypt the file");
///
pub fn encrypt_file(path: &Path, output_path: &Path, password: &[u8]) -> Result<()> {
    let data = fs::read(path).with_context(|| "Failed to read the file")?;
    let encrypted_data = encrypt(&data, password).with_context(|| "Failed to encrypt data")?;
    fs::write(output_path, encrypted_data).with_context(|| "Failed to write to file")?;
    Ok(())
}

/// Decrypts file data and output it to the specified output file
///
/// # Example
///
/// decrypt_file(Path::new("encrypted_example.txt"), Path::new("example.txt"), b"example passwprd").expect("Failed to decrypt the file");
///
pub fn decrypt_file(path: &Path, output_path: &Path, password: &[u8]) -> Result<()> {
    let encrypted_data = fs::read(path).with_context(|| "Failed to read the file")?;
    let data = decrypt(&encrypted_data, password).with_context(|| "Failed to decrypt data")?;
    fs::write(output_path, data).with_context(|| "Failed to write to file")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn data() {
        // TODO add some more edge cases
        let encrypted_data = encrypt(b"test", b"test").expect("Failed to encrypt");
        let data = decrypt(&encrypted_data, b"test").expect("Failed to decrypt");
        assert_eq!(data, b"test");
    }

    #[test]
    fn file() {
        // TODO add some more edge cases
        fs::write("test.txt", "test").expect("Failed to write to file");
        encrypt_file(Path::new("test.txt"), Path::new("test.txt"), b"test")
            .expect("Failed to encrypt the file");
        decrypt_file(Path::new("test.txt"), Path::new("test.txt"), b"test")
            .expect("Failed to decrypt the file");
        let data = fs::read("test.txt").expect("Failed to read file");
        assert_eq!(data, b"test");
        fs::remove_file("test.txt").expect("Failed to remove the test file");
    }

}