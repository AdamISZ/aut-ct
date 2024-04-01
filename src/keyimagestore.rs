use std::fmt;
use std::path::{Path, PathBuf};
use std::io::Error;

use ark_ff::PrimeField;
use ark_serialize::{ CanonicalDeserialize, CanonicalSerialize,
    Compress, Read, SerializationError, Valid, Write,};

use ark_ec::AffineRepr;
use ark_ec::short_weierstrass::{Affine, SWCurveConfig};

use crate::config::AutctConfig;
use crate::utils::{APP_DOMAIN_LABEL,
    get_generators, write_file_string2};

pub const KEYIMAGE_FILE_EXTENSION: &[u8] = b".aki";

#[derive(Clone, Debug)]
pub struct KeyImageStore<C: AffineRepr>  {
    file_suffix: Option<String>,
    name: String,
    context_label: String,
    basepoint: Option<C>,
    keylen: usize,
    keys: Vec<C>,
    // the full filename depends on:
    // 1. the name that is set (currently using APP_DOMAIN_LABEL)
    // 2. the context label as defined in the config
    // 3. the file suffix as defined in the config
    // 4. the file extension which is a constant in this module
    pub full_file_loc: Option<PathBuf>,
}

impl<C: AffineRepr> KeyImageStore<C> {
    pub fn new(file_suffix: Option<String>, name: String, context_label: String, basepoint: Option<C>) -> Self {
        let mut ks = KeyImageStore {
            file_suffix,
            name,
            context_label,
            basepoint,
            keylen: usize::try_from(0u64).unwrap(),
            keys: Vec::new(),
            full_file_loc: None,
        };
        // a KeyImageStore object is always instantiated with enough
        // information to set the full filename/location:
        let mut str1 = ks.name.clone();
        str1.push_str(&ks.context_label.clone());
        str1.push_str(ks.file_suffix.as_mut().unwrap());
        ks.full_file_loc = Some(PathBuf::from(str1 + &String::from_utf8(KEYIMAGE_FILE_EXTENSION.to_vec()).unwrap()));
        ks
    }

    pub fn is_key_in_store
    (&self, key_to_check: C) -> bool {
        match self.keys.iter().position(|&x| x  == key_to_check) {
            None => false,
            Some(_key) => true
        }
    }
    pub fn add_key(&mut self, key_to_add: C) -> Result<(), Error> {
        self.keys.push(key_to_add);
        self.keylen = self.keylen + 1;
        // it's clearly logically required to persist
        // any change, so that updates are not forgotten
        // in quits and crashes.
        // *If* we use threads, we would also require
        // some kind of lock here (but not simple asynchronous)
        self.persist()
    }

    pub fn persist(&mut self) -> Result<(), Error>{
        //let filename = &self.get_filename();
        let mut buf = Vec::with_capacity(self.serialized_size(Compress::Yes));
        self.serialize_with_mode(&mut buf, Compress::Yes).expect(
            "Failed to serialize the KeyImageStore");
        write_file_string2(self.full_file_loc.clone().unwrap(), buf)
    }

}

impl<C: AffineRepr> Valid for KeyImageStore<C> {
    // TODO; currently just a no-op
    fn check(&self) -> Result<(), SerializationError> {
        Ok(())
    }
}

impl<C: AffineRepr> CanonicalSerialize for KeyImageStore<C> {
    // Returns the size in bytes required to serialize
    // We are just always using compressed for now, this may change.
    fn serialized_size(&self, _mode: Compress) -> usize {
        let keys_size = self.keys.len() * 33;
        let headers_size = APP_DOMAIN_LABEL.len() + 8 +
        self.context_label.len() + 33 + self.keylen.to_be_bytes().len();
        keys_size + headers_size
    }

    /// Serializes the proof into a byte array of 4 32/33-byte elements.
    fn serialize_with_mode<W: Write>(
        &self,
        mut writer: W,
        compress: Compress,
    ) -> Result<(), SerializationError> {
        // headers first:
        writer.write(APP_DOMAIN_LABEL)?;
        writer.write(&self.context_label.len().to_be_bytes())?;
        writer.write(self.context_label.as_bytes())?;
        self.basepoint.unwrap().serialize_with_mode(&mut writer, compress)?;
        // length of keylist makes deserializing easier
        writer.write(&self.keys.len().to_be_bytes())?;
        for k in &self.keys {
            k.serialize_with_mode(&mut writer, compress)?;
        }
        Ok(())
    }
}

impl<C: AffineRepr> CanonicalDeserialize for KeyImageStore<C> {
    fn deserialize_with_mode<R: Read>(
        mut reader: R,
        compress: Compress,
        validate: ark_serialize::Validate,
    ) -> Result<Self, SerializationError> {
        let mut buf1 = [0; APP_DOMAIN_LABEL.len()];
        reader.read(&mut buf1)?;
        if buf1 != APP_DOMAIN_LABEL {
            // TODO replace the panic with an error,
            // because conceivably you might need to try a file
            // and then reject it, not crash.
            panic!("Invalid app domain for keyimagestore");
        }
        // read the length of the context label, then the context label,
        // then sanity check that it fits our config:
        let mut bufcllen = [0; 8];
        reader.read(&mut bufcllen)?;
        let cllen = usize::from_be_bytes(bufcllen);
        let mut bufcl = vec![0; cllen];
        reader.read(&mut bufcl)?;
        let basepoint = C::deserialize_with_mode(&mut reader, compress, validate)?;
        let mut b = Vec::new();
        basepoint.serialize_compressed(&mut b).expect("Failed to serialize point");
        let mut buf2 = [0; 8];
        reader.read(&mut buf2)?;
        let keylen = u64::from_be_bytes(buf2);
        let mut keys_in: Vec<C> = Vec::new();
        // there should be a syntax for this without looping?
        for _ in 0..keylen {
            keys_in.push(C::deserialize_with_mode(&mut reader, compress, validate)?);
        }
        Ok(Self {
            name: String::from_utf8(APP_DOMAIN_LABEL.to_vec()).unwrap(),
            context_label: String::from_utf8(bufcl).unwrap(),
            // note that the deserialize method is making an object in-mem
            // from persistence, so it doesn't (sometimes)
            // care about filepaths:
            file_suffix: None,
            basepoint: Some(basepoint),
            keylen: usize::from_be_bytes(buf2),
            keys: keys_in,
            full_file_loc: None,

        })
    }
}

pub struct KeyImageStoreExistsError{
    filename: PathBuf,
}

impl fmt::Display for KeyImageStoreExistsError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "The key image store file already exists: {:?}", self.filename)
    }
}

impl fmt::Debug for KeyImageStoreExistsError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{{ file: {}, line: {} }}", file!(), line!())
    }
}
// this function must handle the possibility
// that the file already exists; then we should return
// an Error indicating this, so the caller can
// instead call .deserialize..() and decide whether
// they want to overwrite.
pub fn create_new_store<
    F: PrimeField,
    P0: SWCurveConfig<BaseField = F> + Copy,>
    (autctcfg: AutctConfig) -> Result<KeyImageStore<Affine<P0>>, KeyImageStoreExistsError> {
    let name = APP_DOMAIN_LABEL;
    // get the J value from the config
    println!("Using cofig: {:?}", autctcfg.context_label.clone().unwrap());
    let J = get_generators::<F, P0>(&autctcfg.context_label.clone().unwrap().into_bytes());
    // is there a less ugly way to go from &[u8] to String?
    let mut ks = KeyImageStore::<Affine<P0>>::new(
        Some(autctcfg.keyimage_filename_suffix.unwrap()),
        String::from_utf8(name.to_vec()).unwrap(),
        autctcfg.context_label.unwrap(),
         Some(J));
    println!("Got ffl: {:?}", &ks.full_file_loc.clone().unwrap());
    if Path::exists(&ks.full_file_loc.clone().unwrap()) {
        Err(KeyImageStoreExistsError { filename: ks.full_file_loc.unwrap()})
    }
    else {
    let mut buf2 = Vec::with_capacity(ks.serialized_size(Compress::Yes));
    let _ = ks.serialize_compressed(&mut buf2);
        ks.persist().expect("Failed to create new keystore file");
        Ok(ks)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::affine_from_bytes_tai;
    extern crate hex;
    use rand::Rng;
    extern crate ark_secp256k1;
    use ark_ec::AffineRepr;
    use ark_secp256k1::Config as SecpConfig;
    use ark_serialize::Validate;
    use std::fs;
    use std::io::Cursor;

    // test strategy:
    // 1. Create an empty key store using test context name
    // 2. create a vector of random secp points
    // 3. Add each point one-by-one to the store
    // 4. Deserialize from the derived filename and check the length
    //    is the expected length.
    // 5. Call is_key_in_store for keys that are and are not from the store.
    #[test]
    fn run_test_cases() {
        type F = <ark_secp256k1::Affine as AffineRepr>::BaseField;
        let mut cfg = AutctConfig::default();
        cfg.context_label = Some("keyimagestore-tests-001".to_string());
        let mut ks = create_new_store::<F, SecpConfig>(cfg).unwrap();
        let mut rng = rand::thread_rng();
        let mut x: Vec<Affine<SecpConfig>> = Vec::with_capacity(100);
        for _ in 1..101 {
            let random_bytes = rng.gen::<[u8; 32]>();
            x.push(affine_from_bytes_tai(&random_bytes));
        }
        for pt in x {
            // note that every call will persist to the file:
            ks.add_key(pt).unwrap();
        }
        let file_contents = fs::read(ks.full_file_loc.clone().unwrap()).unwrap();
        let cursor = Cursor::new(file_contents);
        let new_ks = KeyImageStore::<Affine<SecpConfig>>::deserialize_with_mode(cursor,
            Compress::Yes, Validate::No).unwrap();
        // remove file for next test
        fs::remove_file(ks.full_file_loc.unwrap()).unwrap();
        // TODO: can we apply some derive "equals" trait so we can directly compare that the objects are identical?
        // in any case, let's do some random comparisons:
        let rand_sample_indices = [0, 2, 7, 4, 8, 99];
        for i in rand_sample_indices {
            assert_eq!(ks.keys[i], new_ks.keys[i]);
            assert_eq!(new_ks.is_key_in_store(ks.keys[i]), true)
        };
        // Check that keys that aren't in the store are reported as such
        let mut y: Vec<Affine<SecpConfig>> = Vec::with_capacity(100);
        for _ in 1..101 {
            let random_bytes = rng.gen::<[u8; 32]>();
            y.push(affine_from_bytes_tai(&random_bytes));
        }
        for k in y {
            assert_eq!(new_ks.is_key_in_store(k), false);
        }
    }
}



