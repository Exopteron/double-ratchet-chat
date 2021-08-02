#[cfg(test)]
mod tests {
    use keyex_rand_core::OsRng;
    use exoclichat::doubleratchet;
use x25519_dalek::{EphemeralSecret, PublicKey, StaticSecret};
    #[test]
    fn init_ratchet_alice() {
        let mut key1 = EphemeralSecret::new(OsRng);
        let mut key1public = PublicKey::from(&key1);
        let ratchet = doubleratchet::StateHE::RatchetInitAliceHE(vec![0; 32], key1public, vec![0; 32], vec![0; 32]);
    }
    #[test]
    fn init_ratchet_bob() {
        let mut key1 = StaticSecret::new(OsRng);
        let ratchet = doubleratchet::StateHE::RatchetInitBobHE(vec![0; 32], key1, vec![0; 32], vec![0; 32]);
    }
    #[test]
    fn bob_message_first() {
        let mut key1 = StaticSecret::new(OsRng);
        let mut key1public = PublicKey::from(&key1);
        let mut alice = doubleratchet::StateHE::RatchetInitAliceHE(vec![0; 32], key1public, vec![0; 32], vec![0; 32]);
        let mut bob = doubleratchet::StateHE::RatchetInitBobHE(vec![0; 32], key1, vec![0; 32], vec![0; 32]);
        let message = bob.RatchetEncryptHE(b"Hello World".to_vec(), vec![]);
        let message = alice.RatchetDecryptHE(message.to_vec(), vec![]).unwrap();
        if message != b"Hello World".to_vec() {
            panic!("Fail");
        }
    }
    #[test]
    fn alice_message_first() {
        let mut key1 = StaticSecret::new(OsRng);
        let mut key1public = PublicKey::from(&key1);
        let mut alice = doubleratchet::StateHE::RatchetInitAliceHE(vec![0; 32], key1public, vec![0; 32], vec![0; 32]);
        let mut bob = doubleratchet::StateHE::RatchetInitBobHE(vec![0; 32], key1, vec![0; 32], vec![0; 32]);
        let message = alice.RatchetEncryptHE(b"Hello World".to_vec(), vec![]);
        let message = bob.RatchetDecryptHE(message.to_vec(), vec![]).unwrap();
        if message != b"Hello World".to_vec() {
            panic!("Fail");
        }
    }
    #[test]
    #[should_panic(expected = "MAC failure!")]
    fn failed_mac_to_bob() {
        let mut key1 = StaticSecret::new(OsRng);
        let mut key1public = PublicKey::from(&key1);
        let mut alice = doubleratchet::StateHE::RatchetInitAliceHE(vec![0; 32], key1public, vec![0; 32], vec![0; 32]);
        let mut bob = doubleratchet::StateHE::RatchetInitBobHE(vec![0; 32], key1, vec![0; 32], vec![0; 32]);
        let mut message = alice.RatchetEncryptHE(b"Hello World".to_vec(), vec![]);
        let len = message.len();
        message[len - 1] += 1;
        let message = bob.RatchetDecryptHE(message.to_vec(), vec![]).unwrap();
    }
    #[test]
    #[should_panic(expected = "MAC failure!")]
    fn failed_mac_to_alice() {
        let mut key1 = StaticSecret::new(OsRng);
        let mut key1public = PublicKey::from(&key1);
        let mut alice = doubleratchet::StateHE::RatchetInitAliceHE(vec![0; 32], key1public, vec![0; 32], vec![0; 32]);
        let mut bob = doubleratchet::StateHE::RatchetInitBobHE(vec![0; 32], key1, vec![0; 32], vec![0; 32]);
        let mut message = bob.RatchetEncryptHE(b"Hello World".to_vec(), vec![]);
        let len = message.len();
        message[len - 1] += 1;
        let message = alice.RatchetDecryptHE(message.to_vec(), vec![]).unwrap();
    }
    #[test]
    fn alice_message_100() {
        let mut key1 = StaticSecret::new(OsRng);
        let mut key1public = PublicKey::from(&key1);
        let mut alice = doubleratchet::StateHE::RatchetInitAliceHE(vec![0; 32], key1public, vec![0; 32], vec![0; 32]);
        let mut bob = doubleratchet::StateHE::RatchetInitBobHE(vec![0; 32], key1, vec![0; 32], vec![0; 32]);
        for _ in 0..100 {
            let message = alice.RatchetEncryptHE(b"Hello World".to_vec(), vec![]);
            let message = bob.RatchetDecryptHE(message.to_vec(), vec![]).unwrap();
            if message != b"Hello World".to_vec() {
                panic!("Fail");
            }
        }
    }
    #[test]
    fn bob_message_100() {
        let mut key1 = StaticSecret::new(OsRng);
        let mut key1public = PublicKey::from(&key1);
        let mut alice = doubleratchet::StateHE::RatchetInitAliceHE(vec![0; 32], key1public, vec![0; 32], vec![0; 32]);
        let mut bob = doubleratchet::StateHE::RatchetInitBobHE(vec![0; 32], key1, vec![0; 32], vec![0; 32]);
        for _ in 0..100 {
            let message = bob.RatchetEncryptHE(b"Hello World".to_vec(), vec![]);
            let message = alice.RatchetDecryptHE(message.to_vec(), vec![]).unwrap();
            if message != b"Hello World".to_vec() {
                panic!("Fail");
            }
        }
    }
    #[test]
    #[should_panic(expected = "MAC failure!")]
    fn failed_mac_to_bob_ad() {
        let mut key1 = StaticSecret::new(OsRng);
        let mut key1public = PublicKey::from(&key1);
        let mut alice = doubleratchet::StateHE::RatchetInitAliceHE(vec![0; 32], key1public, vec![0; 32], vec![0; 32]);
        let mut bob = doubleratchet::StateHE::RatchetInitBobHE(vec![0; 32], key1, vec![0; 32], vec![0; 32]);
        let mut message = alice.RatchetEncryptHE(b"Hello World".to_vec(), vec![1]);
        let message = bob.RatchetDecryptHE(message.to_vec(), vec![2]).unwrap();
    }
    #[test]
    #[should_panic(expected = "MAC failure!")]
    fn failed_mac_to_alice_ad() {
        let mut key1 = StaticSecret::new(OsRng);
        let mut key1public = PublicKey::from(&key1);
        let mut alice = doubleratchet::StateHE::RatchetInitAliceHE(vec![0; 32], key1public, vec![0; 32], vec![0; 32]);
        let mut bob = doubleratchet::StateHE::RatchetInitBobHE(vec![0; 32], key1, vec![0; 32], vec![0; 32]);
        let mut message = bob.RatchetEncryptHE(b"Hello World".to_vec(), vec![1]);
        let message = alice.RatchetDecryptHE(message.to_vec(), vec![2]).unwrap();
    }
    #[test]
    #[should_panic]
    fn bob_message_first_wrong_sk() {
        let mut key1 = StaticSecret::new(OsRng);
        let mut key1public = PublicKey::from(&key1);
        let mut alice = doubleratchet::StateHE::RatchetInitAliceHE(vec![1; 32], key1public, vec![0; 32], vec![0; 32]);
        let mut bob = doubleratchet::StateHE::RatchetInitBobHE(vec![0; 32], key1, vec![0; 32], vec![0; 32]);
        let message = bob.RatchetEncryptHE(b"Hello World".to_vec(), vec![]);
        let message = alice.RatchetDecryptHE(message.to_vec(), vec![]).unwrap();
        if message != b"Hello World".to_vec() {
            panic!("Fail");
        }
    }
    #[test]
    #[should_panic]
    fn alice_message_first_wrong_sk() {
        let mut key1 = StaticSecret::new(OsRng);
        let mut key1public = PublicKey::from(&key1);
        let mut alice = doubleratchet::StateHE::RatchetInitAliceHE(vec![1; 32], key1public, vec![0; 32], vec![0; 32]);
        let mut bob = doubleratchet::StateHE::RatchetInitBobHE(vec![0; 32], key1, vec![0; 32], vec![0; 32]);
        let message = alice.RatchetEncryptHE(b"Hello World".to_vec(), vec![]);
        let message = bob.RatchetDecryptHE(message.to_vec(), vec![]).unwrap();
        if message != b"Hello World".to_vec() {
            panic!("Fail");
        }
    }
    #[test]
    #[should_panic]
    fn alice_message_first_wrong_hka() {
        let mut key1 = StaticSecret::new(OsRng);
        let mut key1public = PublicKey::from(&key1);
        let mut alice = doubleratchet::StateHE::RatchetInitAliceHE(vec![0; 32], key1public, vec![1; 32], vec![0; 32]);
        let mut bob = doubleratchet::StateHE::RatchetInitBobHE(vec![0; 32], key1, vec![0; 32], vec![0; 32]);
        let message = alice.RatchetEncryptHE(b"Hello World".to_vec(), vec![]);
        let message = bob.RatchetDecryptHE(message.to_vec(), vec![]).unwrap();
        if message != b"Hello World".to_vec() {
            panic!("Fail");
        }
    }
    #[test]
    #[should_panic]
    fn alice_message_herself() {
        let mut key1 = StaticSecret::new(OsRng);
        let mut key1public = PublicKey::from(&key1);
        let mut alice = doubleratchet::StateHE::RatchetInitAliceHE(vec![0; 32], key1public, vec![0; 32], vec![0; 32]);
        let message = alice.RatchetEncryptHE(b"Hello World".to_vec(), vec![]);
        let message = alice.RatchetDecryptHE(message.to_vec(), vec![]).unwrap();
    }
    #[test]
    #[should_panic]
    fn bob_message_himself() {
        let mut key1 = StaticSecret::new(OsRng);
        let mut bob = doubleratchet::StateHE::RatchetInitBobHE(vec![0; 32], key1, vec![0; 32], vec![0; 32]);
        let message = bob.RatchetEncryptHE(b"Hello World".to_vec(), vec![]);
        let message = bob.RatchetDecryptHE(message.to_vec(), vec![]).unwrap();
    }
    #[test]
    #[should_panic]
    fn replay_attack_on_bob() {
        let mut key1 = StaticSecret::new(OsRng);
        let mut key1public = PublicKey::from(&key1);
        let mut alice = doubleratchet::StateHE::RatchetInitAliceHE(vec![0; 32], key1public, vec![0; 32], vec![0; 32]);
        let mut bob = doubleratchet::StateHE::RatchetInitBobHE(vec![0; 32], key1, vec![0; 32], vec![0; 32]);
        let mut message = alice.RatchetEncryptHE(b"Hello World".to_vec(), vec![]);
        let m = bob.RatchetDecryptHE(message.to_vec(), vec![]).unwrap();
        let m = bob.RatchetDecryptHE(message.to_vec(), vec![]).unwrap();
    }
    #[test]
    #[should_panic]
    fn replay_attack_on_alice() {
        let mut key1 = StaticSecret::new(OsRng);
        let mut key1public = PublicKey::from(&key1);
        let mut alice = doubleratchet::StateHE::RatchetInitAliceHE(vec![0; 32], key1public, vec![0; 32], vec![0; 32]);
        let mut bob = doubleratchet::StateHE::RatchetInitBobHE(vec![0; 32], key1, vec![0; 32], vec![0; 32]);
        let mut message = bob.RatchetEncryptHE(b"Hello World".to_vec(), vec![]);
        let m = alice.RatchetDecryptHE(message.to_vec(), vec![]).unwrap();
        let m = alice.RatchetDecryptHE(message.to_vec(), vec![]).unwrap();
    }
}

