#![allow(non_snake_case)]
use aes_gcm_siv::aead::{Aead, NewAead};
use aes_gcm_siv::{Aes256GcmSiv, Key, Nonce}; // Or `Aes128GcmSiv`
use hmac::{Hmac, Mac, NewMac};
use keyex_rand_core::OsRng;
use serde::{Deserialize, Serialize};
use sha3::Sha3_256;
use x25519_dalek::{PublicKey, StaticSecret};
type HmacSha256 = Hmac<Sha3_256>;
#[path = "varint.rs"]
mod varint;
/// Double ratchet without header encryption.
#[derive(Serialize, Deserialize)]
pub struct State {
    DHs: StaticSecret,
    DHr: Option<PublicKey>,
    RK: Vec<u8>,
    CKs: Vec<u8>,
    CKr: Option<Vec<u8>>,
    Ns: u32,
    Nr: u32,
    PN: u32,
    MKSKIPPED: Vec<SkippedKey>,
}
/// Double ratchet with header encryption.
#[derive(Serialize, Deserialize)]
pub struct StateHE {
    DHRs: StaticSecret,
    DHRr: Option<PublicKey>,
    RK: Vec<u8>,
    CKs: Vec<u8>,
    CKr: Option<Vec<u8>>,
    Ns: u32,
    Nr: u32,
    PN: u32,
    MKSKIPPED: Vec<SkippedKeyHE>,
    HKs: Vec<u8>,
    HKr: Vec<u8>,
    NHKs: Vec<u8>,
    NHKr: Vec<u8>,
}
#[derive(Clone, Serialize, Deserialize)]
pub struct SkippedKey {
    dh: Vec<u8>,
    n: u32,
    mk: Vec<u8>,
}
#[derive(Clone, Serialize, Deserialize)]
pub struct SkippedKeyHE {
    hk: Vec<u8>,
    n: u32,
    mk: Vec<u8>,
}
#[derive(Clone)]
pub struct Header {
    dh: Vec<u8>,
    pn: u32,
    n: u32,
}
/// Double ratchet with header encryption.
impl StateHE {
    /// Alice's function to initialize the ratchet from a secret key, Bob's ECDH key and 2 secret header keys.
    pub fn RatchetInitAliceHE(
        SK: Vec<u8>,
        bob_dh_public_key: PublicKey,
        shared_hka: Vec<u8>,
        shared_nhkb: Vec<u8>,
    ) -> Self {
        let DHs = StaticSecret::new(OsRng);
        let DHr = bob_dh_public_key;
        let (RK, CKs, NHKs) = Self::KDF_RK_HE(
            SK.clone(),
            DHs.clone().diffie_hellman(&DHr.clone()).as_bytes().to_vec(),
        );
        let (CKr, HKr) = Self::KDF_INIT_SECRET(SK);
        let Ns = 0;
        let Nr = 0;
        let PN = 0;
        let MKSKIPPED = vec![];
        let state = Self {
            DHRs: DHs,
            DHRr: Some(DHr),
            RK: RK,
            CKs: CKs,
            CKr: Some(CKr),
            Ns: Ns,
            Nr: Nr,
            PN: PN,
            MKSKIPPED: MKSKIPPED,
            HKs: shared_hka,
            NHKs: NHKs,
            HKr: HKr,
            NHKr: shared_nhkb,
        };
        return state;
    }
    /// Bob's function to initialize the ratchet from a secret key, Bob's result from an ECDH exchange with Alice and 2 secret header keys.
    pub fn RatchetInitBobHE(
        SK: Vec<u8>,
        bob_dh_key_pair: StaticSecret,
        shared_hka: Vec<u8>,
        shared_nhkb: Vec<u8>,
    ) -> Self {
        let DHs = bob_dh_key_pair;
        let DHr: Option<PublicKey> = None;
        let RK = SK.clone();
        let (CKs, HKs) = Self::KDF_INIT_SECRET(SK);
        let CKr = Some(vec![]);
        let Ns = 0;
        let Nr = 0;
        let PN = 0;
        let MKSKIPPED = vec![];
        let state = Self {
            DHRs: DHs,
            DHRr: DHr,
            RK: RK,
            CKs: CKs,
            CKr: CKr,
            Ns: Ns,
            Nr: Nr,
            PN: PN,
            MKSKIPPED: MKSKIPPED,
            HKs: HKs,
            NHKs: shared_nhkb,
            HKr: vec![],
            NHKr: shared_hka,
        };
        return state;
    }
    /// Generate a new root key, chain key and header key from the previous root key and some key material from an ECDH exchange.
    fn KDF_RK_HE(rk: Vec<u8>, dh_out: Vec<u8>) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
        let mut mac = HmacSha256::new_from_slice(&rk).unwrap();
        mac.update(&dh_out);
        let rk = mac.finalize().into_bytes().to_vec();
        let mut mac = HmacSha256::new_from_slice(&rk).unwrap();
        mac.update(&[0x01]);
        let he = mac.finalize().into_bytes().to_vec();
        let ck = sha3_256(rk.clone());
        return (rk, ck, he);
    }
    /// Generate the initial header key and message key for Bob to be able to send messages first
    fn KDF_INIT_SECRET(rk: Vec<u8>) -> (Vec<u8>, Vec<u8>) {
        let mut mac = HmacSha256::new_from_slice(&rk).unwrap();
        mac.update(&[0x00, 0x05, 0x10]);
        let ck = mac.finalize().into_bytes().to_vec();
        let mut mac = HmacSha256::new_from_slice(&rk).unwrap();
        mac.update(&[0x00, 0x10, 0x10]);
        let hk = mac.finalize().into_bytes().to_vec();
        return (ck, hk);
    }
    /// Generate a new chain key and message key from the previous chain key.
    fn KDF_CK(ck: Vec<u8>) -> (Vec<u8>, Vec<u8>) {
        let mut mac = HmacSha256::new_from_slice(&ck).unwrap();
        mac.update(&[0x01]);
        let nck = mac.finalize().into_bytes().to_vec();
        let mut mac = HmacSha256::new_from_slice(&ck).unwrap();
        mac.update(&[0x02]);
        let mk = mac.finalize().into_bytes().to_vec();
        //let rk = sha3_256(ck.clone());
        return (nck, mk);
    }
    /// Perform double-ratchet message encryption on plaintext and associated data.
    pub fn RatchetEncryptHE(&mut self, plaintext: Vec<u8>, AD: Vec<u8>) -> Vec<u8> {
        let (CKs, mk) = Self::KDF_CK(self.CKs.clone());
        self.CKs = CKs;
        let DHsPub = PublicKey::from(&self.DHRs.clone());
        let header = Self::HEADER(DHsPub.to_bytes().to_vec(), self.PN, self.Ns);
        let enc_header = Self::HENCRYPT(self.HKs.clone(), header);
        //let enc_header = varint::VarInt::write_varint_prefixed_bytearray(enc_header);
        self.Ns += 1;
        let mut ad = vec![];
        ad.append(&mut AD.clone());
        ad.append(&mut enc_header.clone());
        let enc_header = varint::VarInt::write_varint_prefixed_bytearray(enc_header);
        let ciphertext = Self::ENCRYPT(mk, plaintext, ad);
        let mut vec = vec![];
        vec.append(&mut enc_header.clone());
        vec.append(&mut ciphertext.clone());
        return vec;
    }
    /// Perform double-ratchet decryption on an encrypted message and associated data.
    pub fn RatchetDecryptHE(
        &mut self,
        enc_header: Vec<u8>,
        AD: Vec<u8>,
    ) -> Result<Vec<u8>, String> {
        let (enc_header, ciphertext) = Self::DeserializeHEADERHE(enc_header);
        let plaintext =
            Self::TrySkippedMessageKeysHE(self, enc_header.clone(), ciphertext.clone(), AD.clone());
        if !plaintext.is_none() {
            return Ok(plaintext.unwrap());
        }

        let (header, dh_ratchet) = self.DecryptHeader(enc_header.clone());
        if dh_ratchet {
            Self::SkipMessageKeysHE(self, header.pn);
            self.DHRatchetHE(header.clone());
        }

        Self::SkipMessageKeysHE(self, header.n);
        let (CKr, mk) = Self::KDF_CK(self.CKr.as_ref().unwrap().clone());
        self.CKr = Some(CKr);
        self.Nr += 1;

        let mut ad = vec![];
        ad.append(&mut AD.clone());
        ad.append(&mut enc_header.clone());
        let plaintext = Self::DECRYPT(mk, ciphertext, ad);
        return plaintext;
    }
    /// Attempt to decrypt message header.
    fn DecryptHeader(&mut self, enc_header: Vec<u8>) -> (Header, bool) {
        let header = Self::HDECRYPT(self.HKr.clone(), enc_header.clone());
        if header != None {
            let header = header.unwrap();
            let header = Self::DeserializeHEADER(header);
            return (header, false);
        }
        let header = Self::HDECRYPT(self.NHKr.clone(), enc_header.clone());
        if header != None {
            let header = header.unwrap();
            let header = Self::DeserializeHEADER(header);
            return (header, true);
        }
        panic!("Header decryption failed!");
    }
    /// Perform a Diffie-Hellman ratchet step.
    fn DHRatchetHE(&mut self, header: Header) {
        self.PN = self.Ns;
        self.Ns = 0;
        self.Nr = 0;
        self.HKs = self.NHKs.clone();
        self.HKr = self.NHKr.clone();
        let mut dh = [0; 32];
        for i in 0..32 {
            dh[i] = header.dh[i];
        }
        self.DHRr = Some(PublicKey::from(dh));
        let (RK, CKr, NHKr) = Self::KDF_RK_HE(
            self.RK.clone(),
            self.DHRs
                .clone()
                .diffie_hellman(&self.DHRr.unwrap())
                .to_bytes()
                .to_vec(),
        );
        self.RK = RK;
        self.CKr = Some(CKr);
        self.NHKr = NHKr;
        self.DHRs = StaticSecret::new(OsRng);
        let (RK, CKs, NHKs) = Self::KDF_RK_HE(
            self.RK.clone(),
            self.DHRs
                .clone()
                .diffie_hellman(&self.DHRr.unwrap())
                .to_bytes()
                .to_vec(),
        );
        self.RK = RK;
        self.CKs = CKs;
        self.NHKs = NHKs;
    }
    /// Encrypt the header from a header key and plaintext.
    fn HENCRYPT(hk: Vec<u8>, plaintext: Vec<u8>) -> Vec<u8> {
        use aes::Aes256;
        use block_modes::block_padding::Pkcs7;
        use block_modes::{BlockMode, Cbc};
        use chacha20poly1305::aead::{Aead, NewAead};
        use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
        use keyex_rand_core::RngCore;
        use std::io::Read;
        type Aes256Cbc = Cbc<Aes256, Pkcs7>;
        let key = Key::from_slice(&hk);
        let cipher = XChaCha20Poly1305::new(key);
        let mut noncebytes = vec![0; 24];
        OsRng.fill_bytes(&mut noncebytes);
        let nonce = XNonce::from_slice(&noncebytes);
        let ciphertext = cipher.encrypt(nonce, plaintext.as_ref()).unwrap();
        let mut output = vec![];
        output.append(&mut noncebytes);
        output.append(&mut ciphertext.clone());
        return output;
    }
    /// Decrypt the header from a header key and ciphertext.
    fn HDECRYPT(hk: Vec<u8>, mut ciphertext: Vec<u8>) -> Option<Vec<u8>> {
        use chacha20poly1305::aead::{Aead, NewAead};
        use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
        if hk.len() < 32 {
            return None;
        }
        let key = Key::from_slice(&hk);
        let cipher = XChaCha20Poly1305::new(key);
        let mut noncebytes = vec![];
        for i in 0..24 {
            noncebytes.push(ciphertext.remove(0));
        }
        let nonce = XNonce::from_slice(&noncebytes);
        let plaintext = cipher.decrypt(nonce, ciphertext.as_ref());
        if plaintext.is_err() {
            return None;
        }
        let plaintext = plaintext.unwrap();
        let mut output = vec![];
        output.append(&mut plaintext.clone());
        return Some(output);
    }
    /// Perform encryption using a one-time-use message key, the plaintext and associated data.
    fn ENCRYPT(mk: Vec<u8>, plaintext: Vec<u8>, AD: Vec<u8>) -> Vec<u8> {
        use aes::Aes256;
        use block_modes::block_padding::Pkcs7;
        use block_modes::{BlockMode, Cbc};
        use std::io::Read;
        type Aes256Cbc = Cbc<Aes256, Pkcs7>;
        let h = hkdf::Hkdf::<Sha3_256>::new(Some(&[0; 32]), &mk);
        let mut okm = vec![0; 80];
        h.expand(b"RATCHETENCRYPT", &mut okm).unwrap();
        let mut okm = std::io::Cursor::new(okm);
        let mut encryption = vec![0; 32];
        okm.read_exact(&mut encryption).unwrap();
        let mut authentication = vec![0; 32];
        okm.read_exact(&mut authentication).unwrap();
        let mut iv = vec![0; 16];
        okm.read_exact(&mut iv).unwrap();
        let cipher = Aes256Cbc::new_from_slices(&encryption, &iv).unwrap();
        let mut output = plaintext;
        let output = cipher.encrypt_vec(&mut output);
        let mut mac = HmacSha256::new_from_slice(&authentication).unwrap();
        mac.update(&AD);
        mac.update(&output);
        let mac = mac.finalize().into_bytes().to_vec();
        let mut output2 = vec![];
        output2.append(&mut output.clone());
        output2.append(&mut mac.clone());
        return output2;
    }
    // Perform decryption using a one-time message key, the ciphertext and associated data.
    fn DECRYPT(mk: Vec<u8>, ciphertext: Vec<u8>, AD: Vec<u8>) -> Result<Vec<u8>, String> {
        use aes::Aes256;
        use block_modes::block_padding::Pkcs7;
        use block_modes::{BlockMode, Cbc};
        use std::io::Read;
        type Aes256Cbc = Cbc<Aes256, Pkcs7>;
        let h = hkdf::Hkdf::<Sha3_256>::new(Some(&[0; 32]), &mk);
        let mut okm = vec![0; 80];
        h.expand(b"RATCHETENCRYPT", &mut okm).unwrap();
        let mut okm = std::io::Cursor::new(okm);
        let mut encryption = vec![0; 32];
        okm.read_exact(&mut encryption).unwrap();
        let mut authentication = vec![0; 32];
        okm.read_exact(&mut authentication).unwrap();
        let mut iv = vec![0; 16];
        okm.read_exact(&mut iv).unwrap();
        let cipher = Aes256Cbc::new_from_slices(&encryption, &iv).unwrap();
        let mut plaintext = ciphertext;
        plaintext.reverse();
        let mut plaintext = std::io::Cursor::new(plaintext);
        let mut macthem = vec![0; 32];
        plaintext.read_exact(&mut macthem).unwrap();
        let mut output = vec![];
        plaintext.read_to_end(&mut output).unwrap();
        output.reverse();
        macthem.reverse();
        let mut mac = HmacSha256::new_from_slice(&authentication).unwrap();
        mac.update(&AD);
        mac.update(&output);
        //let mac = mac.finalize().into_bytes().to_vec();
        if !mac.verify(&macthem).is_ok() {
            return Err("MAC failure!".to_string());
        }
        let output = cipher.decrypt(&mut output).unwrap().to_vec();
        let mut output2 = vec![];
        output2.append(&mut output.clone());
        return Ok(output2);
    }
    /// Skip missed message keys.
    fn SkipMessageKeysHE(&mut self, until: u32) {
        if self.Nr + 1000 < until {
            panic!("AHH IM PANICKING");
        }
        if self.CKr != None {
            while self.Nr < until {
                let (CKr, mk) = Self::KDF_CK(self.CKr.as_ref().unwrap().clone());
                self.CKr = Some(CKr);
                let skippedkey: SkippedKeyHE = SkippedKeyHE {
                    hk: self.HKr.clone().to_vec(),
                    n: self.Nr.clone(),
                    mk: mk,
                };
                self.MKSKIPPED.push(skippedkey);
                self.Nr += 1;
            }
        }
    }
    /// Try skipped message keys.
    fn TrySkippedMessageKeysHE(
        &mut self,
        enc_header: Vec<u8>,
        ciphertext: Vec<u8>,
        AD: Vec<u8>,
    ) -> Option<Vec<u8>> {
        let mut iter = 0;
        for skippedkey in self.MKSKIPPED.clone() {
            let header = Self::HDECRYPT(skippedkey.hk, enc_header.clone());
            if header.is_none() {
                continue;
            }
            let header = header.unwrap();
            let header = Self::DeserializeHEADER(header);
            if header.n == skippedkey.n {
                self.MKSKIPPED.remove(iter);
                let mut ad = vec![];
                ad.append(&mut AD.clone());
                ad.append(&mut enc_header.clone());
                let plaintext = Self::DECRYPT(skippedkey.mk, ciphertext, ad).unwrap();
                return Some(plaintext);
            }
            iter += 1;
        }
        return None;
    }
    /// Serialize a header.
    pub fn HEADER(dh_pair: Vec<u8>, pn: u32, n: u32) -> Vec<u8> {
        let mut header = vec![];
        header.append(&mut varint::VarInt::new_as_bytes(dh_pair.len() as u32));
        header.append(&mut dh_pair.clone());
        header.append(&mut varint::VarInt::write_u32(pn));
        header.append(&mut varint::VarInt::write_u32(n));
        return header;
    }
    /// Deserialize a header.
    pub fn DeserializeHEADERHE(serialized: Vec<u8>) -> (Vec<u8>, Vec<u8>) {
        use std::io::Read;
        let mut serialized = std::io::Cursor::new(serialized);
        let mut dh_pair_len = varint::VarInt::new_u32_from_bytes(&mut serialized)
            .unwrap()
            .number;
        let mut dh_pair = vec![0; dh_pair_len as usize];
        serialized.read_exact(&mut dh_pair).unwrap();
        let header = dh_pair;
        let mut ciphertext = vec![];
        serialized.read_to_end(&mut ciphertext).unwrap();
        return (header, ciphertext);
    }
    pub fn DeserializeHEADER(serialized: Vec<u8>) -> Header {
        use std::io::Read;
        let mut serialized = std::io::Cursor::new(serialized);
        let dh_pair_len = varint::VarInt::new_u32_from_bytes(&mut serialized)
            .unwrap()
            .number;
        let mut dh_pair = vec![0; dh_pair_len as usize];
        serialized.read_exact(&mut dh_pair).unwrap();
        let pn = varint::VarInt::read_u32(&mut serialized);
        let n = varint::VarInt::read_u32(&mut serialized);
        let header = Header {
            dh: dh_pair,
            pn: pn,
            n: n,
        };
        return header;
    }
}
/// Double ratchet without header encryption.
impl State {
    pub fn RatchetInitAlice(SK: Vec<u8>, bob_dh_public_key: PublicKey) -> Self {
        //let mut state: State;
        let DHs = StaticSecret::new(OsRng);
        let DHr = bob_dh_public_key;
        let (RK, CKs) = Self::KDF_RK(
            SK,
            DHs.clone().diffie_hellman(&DHr.clone()).as_bytes().to_vec(),
        );
        let CKr = Some(vec![]);
        let Ns = 0;
        let Nr = 0;
        let PN = 0;
        let MKSKIPPED = vec![];
        let state = Self {
            DHs: DHs,
            DHr: Some(DHr),
            RK: RK,
            CKs: CKs,
            CKr: CKr,
            Ns: Ns,
            Nr: Nr,
            PN: PN,
            MKSKIPPED: MKSKIPPED,
        };
        return state;
    }
    pub fn RatchetInitBob(SK: Vec<u8>, bob_dh_key_pair: StaticSecret) -> Self {
        let DHs = bob_dh_key_pair;
        let DHr: Option<PublicKey> = None;
        let RK = SK;
        let CKs = vec![];
        let CKr = Some(vec![]);
        let Ns = 0;
        let Nr = 0;
        let PN = 0;
        let MKSKIPPED = vec![];
        let state = Self {
            DHs: DHs,
            DHr: DHr,
            RK: RK,
            CKs: CKs,
            CKr: CKr,
            Ns: Ns,
            Nr: Nr,
            PN: PN,
            MKSKIPPED: MKSKIPPED,
        };
        return state;
    }
    fn KDF_RK(rk: Vec<u8>, dh_out: Vec<u8>) -> (Vec<u8>, Vec<u8>) {
        let mut mac = HmacSha256::new_from_slice(&rk).unwrap();
        mac.update(&dh_out);
        let rk = mac.finalize().into_bytes().to_vec();
        let ck = sha3_256(rk.clone());
        return (rk, ck);
    }
    fn KDF_CK(ck: Vec<u8>) -> (Vec<u8>, Vec<u8>) {
        let mut mac = HmacSha256::new_from_slice(&ck).unwrap();
        mac.update(&[0x01]);
        let nck = mac.finalize().into_bytes().to_vec();
        let mut mac = HmacSha256::new_from_slice(&ck).unwrap();
        mac.update(&[0x02]);
        let mk = mac.finalize().into_bytes().to_vec();
        let rk = sha3_256(ck.clone());
        return (nck, mk);
    }
    pub fn RatchetEncrypt(&mut self, plaintext: Vec<u8>, AD: Vec<u8>) -> (Vec<u8>, Vec<u8>) {
        let (CKs, mk) = Self::KDF_CK(self.CKs.clone());
        self.CKs = CKs;
        let DHsPub = PublicKey::from(&self.DHs.clone());
        let header = Self::HEADER(DHsPub.to_bytes().to_vec(), self.PN, self.Ns);
        self.Ns += 1;
        let mut ad = vec![];
        ad.append(&mut AD.clone());
        ad.append(&mut header.clone());
        //println!("Key: {:?}", mk);
        //println!("AD: {:?}", ad);
        //let key = Key::from_slice(&mk);
        //let cipher = Aes256GcmSiv::new(key);
        //let mut nonce = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];
        //let nonce = Nonce::from_slice(&nonce);
        //let ciphertext = cipher.encrypt(nonce, payload).unwrap();
        let ciphertext = Self::ENCRYPT(mk, plaintext, ad);
        return (header, ciphertext);
    }
    pub fn RatchetDecrypt(&mut self, header: Header, ciphertext: Vec<u8>, AD: Vec<u8>) -> Vec<u8> {
        let mut plaintext =
            Self::TrySkippedMessageKeys(self, header.clone(), ciphertext.clone(), AD.clone());
        if !plaintext.is_none() {
            return plaintext.unwrap();
        }
        if self.DHr.is_none() || header.dh != self.DHr.unwrap().clone().to_bytes().to_vec() {
            Self::SkipMessageKeys(self, header.pn);
            Self::DHRatchet(self, header.clone());
        }
        Self::SkipMessageKeys(self, header.n);
        let (CKr, mk) = Self::KDF_CK(self.CKr.as_ref().unwrap().clone());
        self.CKr = Some(CKr);
        self.Nr += 1;
        //println!("Key: {:?}", mk);
        /*         let key = Key::from_slice(&mk);
        let cipher = Aes256GcmSiv::new(key);
        let mut nonce = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];
        let nonce = Nonce::from_slice(&nonce); */
        let mut ad = vec![];
        //ad.append(&mut AD.clone());
        ad.append(&mut Self::HEADER(header.dh.clone(), header.pn, header.n).clone());
        /*         //println!("AD: {:?}", ad);
        let payload = Payload {
            msg: &ciphertext,
            aad: &ad,
        };
        //let plaintext = cipher.decrypt(nonce, payload).unwrap(); */
        let plaintext = Self::DECRYPT(mk, ciphertext, ad).unwrap();
        return plaintext;
    }
    fn DHRatchet(&mut self, header: Header) {
        self.PN = self.Ns;
        self.Ns = 0;
        self.Nr = 0;
        let mut dh = [0; 32];
        for i in 0..32 {
            dh[i] = header.dh[i];
        }
        self.DHr = Some(PublicKey::from(dh));
        let (RK, CKr) = Self::KDF_RK(
            self.RK.clone(),
            self.DHs
                .clone()
                .diffie_hellman(&self.DHr.unwrap())
                .to_bytes()
                .to_vec(),
        );
        self.RK = RK;
        self.CKr = Some(CKr);
        self.DHs = StaticSecret::new(OsRng);
        let (RK, CKs) = Self::KDF_RK(
            self.RK.clone(),
            self.DHs
                .clone()
                .diffie_hellman(&self.DHr.unwrap())
                .to_bytes()
                .to_vec(),
        );
        self.RK = RK;
        self.CKs = CKs;
    }
    fn ENCRYPT(mk: Vec<u8>, plaintext: Vec<u8>, AD: Vec<u8>) -> Vec<u8> {
        use aes::Aes256;
        use block_modes::block_padding::Pkcs7;
        use block_modes::{BlockMode, Cbc};
        use std::io::Read;
        type Aes256Cbc = Cbc<Aes256, Pkcs7>;
        let h = hkdf::Hkdf::<Sha3_256>::new(Some(&[0; 32]), &mk);
        let mut okm = vec![0; 80];
        h.expand(b"RATCHETENCRYPT", &mut okm).unwrap();
        let mut okm = std::io::Cursor::new(okm);
        let mut encryption = vec![0; 32];
        okm.read_exact(&mut encryption);
        let mut authentication = vec![0; 32];
        okm.read_exact(&mut authentication);
        let mut iv = vec![0; 16];
        okm.read_exact(&mut iv);
        let cipher = Aes256Cbc::new_from_slices(&encryption, &iv).unwrap();
        let mut output = plaintext;
        //let mut len = output.len() - 1;
        let mut output = cipher.encrypt_vec(&mut output);
        //println!("Ciphertext: {:?}", output);
        let mut mac = HmacSha256::new_from_slice(&authentication).unwrap();
        mac.update(&AD);
        mac.update(&output);
        let mac = mac.finalize().into_bytes().to_vec();
        let mut output2 = vec![];
        output2.append(&mut output.clone());
        output2.append(&mut mac.clone());
        return output2;
    }
    fn DECRYPT(mk: Vec<u8>, plaintext: Vec<u8>, AD: Vec<u8>) -> Result<Vec<u8>, String> {
        use aes::Aes256;
        use block_modes::block_padding::Pkcs7;
        use block_modes::{BlockMode, Cbc};
        use std::io::Read;
        type Aes256Cbc = Cbc<Aes256, Pkcs7>;
        let h = hkdf::Hkdf::<Sha3_256>::new(Some(&[0; 32]), &mk);
        let mut okm = vec![0; 80];
        h.expand(b"RATCHETENCRYPT", &mut okm).unwrap();
        let mut okm = std::io::Cursor::new(okm);
        let mut encryption = vec![0; 32];
        okm.read_exact(&mut encryption);
        let mut authentication = vec![0; 32];
        okm.read_exact(&mut authentication);
        let mut iv = vec![0; 16];
        okm.read_exact(&mut iv);
        let cipher = Aes256Cbc::new_from_slices(&encryption, &iv).unwrap();
        let mut plaintext = plaintext;
        plaintext.reverse();
        let mut plaintext = std::io::Cursor::new(plaintext);
        let mut macthem = vec![0; 32];
        plaintext.read_exact(&mut macthem);
        let mut output = vec![];
        plaintext.read_to_end(&mut output);
        output.reverse();
        macthem.reverse();
        //let mut output = (&plaintext[..plaintext.len() - 32]).to_vec();
        //let mut macthem = (&plaintext[plaintext.len() - 32..]).to_vec();
        let mut mac = HmacSha256::new_from_slice(&authentication).unwrap();
        mac.update(&AD);
        mac.update(&output);
        //let mac = mac.finalize().into_bytes().to_vec();
        if !mac.verify(&macthem).is_ok() {
            return Err("MAC failure!".to_string());
        }
        let mut len = output.len();
        //println!("Ciphertext: {:?}", output);
        let mut output = cipher.decrypt(&mut output).unwrap().to_vec();
        let mut output2 = vec![];
        output2.append(&mut output.clone());
        //output2.append(&mut mac.clone());
        return Ok(output2);
    }
    fn SkipMessageKeys(&mut self, until: u32) {
        if self.Nr + 100 < until {
            panic!("AHH IM PANICKING");
        }
        if self.CKr != None {
            while self.Nr < until {
                let (CKr, mk) = Self::KDF_CK(self.CKr.as_ref().unwrap().clone());
                self.CKr = Some(CKr);
                let skippedkey: SkippedKey = SkippedKey {
                    dh: self.DHr.as_ref().unwrap().clone().to_bytes().to_vec(),
                    n: self.Nr.clone(),
                    mk: mk,
                };
                self.MKSKIPPED.push(skippedkey);
                self.Nr += 1;
            }
        }
    }
    fn TrySkippedMessageKeys(
        &mut self,
        header: Header,
        ciphertext: Vec<u8>,
        AD: Vec<u8>,
    ) -> Option<Vec<u8>> {
        let mut iter = 0;
        for skippedkey in self.MKSKIPPED.clone() {
            if skippedkey.dh == header.dh.clone() && skippedkey.n == header.n {
                let mk = skippedkey.mk;
                self.MKSKIPPED.remove(iter);
                /*                 let key = Key::from_slice(&mk);
                let cipher = Aes256GcmSiv::new(key);
                let mut nonce = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];
                let nonce = Nonce::from_slice(&nonce); */
                let mut ad = vec![];
                ad.append(&mut AD.clone());
                ad.append(&mut Self::HEADER(header.dh.clone(), header.pn, header.n).clone());
                /*                 let payload = Payload {
                    msg: &ciphertext,
                    aad: &ad,
                };
                let plaintext = cipher.decrypt(nonce, payload).unwrap(); */
                let plaintext = Self::DECRYPT(mk, ciphertext, ad).unwrap();
                return Some(plaintext);
            }
            iter += 1;
        }
        return None;
    }
    pub fn HEADER(dh_pair: Vec<u8>, pn: u32, n: u32) -> Vec<u8> {
        let mut header = vec![];
        header.append(&mut varint::VarInt::new_as_bytes(dh_pair.len() as u32));
        header.append(&mut dh_pair.clone());
        header.append(&mut varint::VarInt::write_u32(pn));
        header.append(&mut varint::VarInt::write_u32(n));
        return header;
    }
    pub fn DeserializeHEADER(serialized: Vec<u8>) -> (Header, Vec<u8>) {
        use std::io::Read;
        let mut serialized = std::io::Cursor::new(serialized);
        let mut dh_pair_len = varint::VarInt::new_u32_from_bytes(&mut serialized)
            .unwrap()
            .number;
        let mut dh_pair = vec![0; dh_pair_len as usize];
        serialized.read_exact(&mut dh_pair);
        let mut pn = varint::VarInt::read_u32(&mut serialized);
        let mut n = varint::VarInt::read_u32(&mut serialized);
        let header = Header {
            dh: dh_pair,
            pn: pn,
            n: n,
        };
        let mut ciphertext = vec![];
        serialized.read_to_end(&mut ciphertext);
        return (header, ciphertext);
    }
}
fn sha3_256(input: Vec<u8>) -> Vec<u8> {
    use sha3::{Digest, Sha3_256};
    let mut hasher = Sha3_256::new();
    hasher.update(input);
    return hasher.finalize().to_vec();
}
