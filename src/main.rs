use double_ratchet_lib as doubleratchet;
mod varint;
use keyex_rand_core::OsRng;
use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256, Sha3_512};
use x25519_dalek::{EphemeralSecret, PublicKey, StaticSecret};
use std::io::Read;
use std::env::args;
use hmac::{Hmac, Mac, NewMac};
type HmacSha256 = Hmac<Sha3_256>;
fn main() {
    let mut args: Vec<String> = args().collect();
    if args.len() > 1 {
        let mut json = std::fs::read_to_string(&args[1]).unwrap();
        let mut ratchet: doubleratchet::StateHE = serde_json::from_str(&json).unwrap();
        loop {
            println!("Enc or dec? (enc/dec)");
            let mut line = String::new();
            std::io::stdin().read_line(&mut line);
            let mut line = line.trim().to_string();
            if line == "enc" {
                println!("Text?\n");
                let mut line = String::new();
                std::io::stdin().read_line(&mut line);
                let mut line = line.trim().to_string();
                let header = ratchet.RatchetEncryptHE(line.as_bytes().to_vec(), vec![]);
                let mut json = serde_json::to_string_pretty(&ratchet).unwrap();
                std::fs::write(&args[1], json);
                let mut ciphertext = base64::encode(&header);
                println!("-------BEGIN ENCRYPTED-------\n\n{}\n\n-------END ENCRYPTED-------\n", ciphertext);
            } else {
                println!("Encrypted text?");
                let mut line = String::new();
                std::io::stdin().read_line(&mut line);
                let mut line = line.trim().to_string();
                let mut line = base64::decode(line);
                if line.is_err() {
                    println!("Invalid base64.");
                    continue;
                }
                let mut line = line.unwrap();
                let plaintext = ratchet.RatchetDecryptHE(line.to_vec(), vec![]);
                if plaintext.is_err() {
                    println!("Error decrypting message.");
                    continue;
                }
                let plaintext = plaintext.unwrap();
                let mut json = serde_json::to_string_pretty(&ratchet).unwrap();
                std::fs::write(&args[1], json);
                let mut plaintext = String::from_utf8_lossy(&plaintext).to_string();
                println!("-------BEGIN DECRYPTED-------\n\n{}\n\n-------END DECRYPTED-------\n", plaintext);
            }
        }
    }
    println!("Hello, world! Are you listening or wanting to start a communication? (y/n)");
    let mut line = String::new();
    std::io::stdin().read_line(&mut line);
    let mut line = line.trim().to_string();
    if line == "y" {
        println!("You are Alice.");
        println!("Type in a password. This will be used for authenticating keys!");
        let mut line = String::new();
        std::io::stdin().read_line(&mut line);
        let mut line = line.trim().to_string();
        use argon2::{
            password_hash::{PasswordHasher, Salt, SaltString},
            Argon2,
        };
        use std::convert::TryFrom;
        let params = argon2::Params {
            m_cost: 37000,
            t_cost: 2,
            p_cost: 1,
            output_size: 32,
            version: argon2::Version::default(),
        };
        let argon2 = Argon2::default();
        let salt = SaltString::new(&base64::encode(base64::encode("GoodSalt").as_bytes().to_vec())).unwrap();
        let hash = argon2
        .hash_password(
            &line.as_bytes(),
            None,
            params,
            Salt::try_from(salt.as_ref()).unwrap(),
        )
        .unwrap();
        let passwordsigningkey = hash.hash.unwrap().as_bytes().to_vec();
        //println!("Listening!");
        println!("Send your recipient's message!");
        let mut line = String::new();
        std::io::stdin().read_line(&mut line);
        let mut line = line.trim().to_string();
        let mut line2 = base64::decode(&line);
        let mut packet = vec![];
        loop {
            if !line2.is_err() {
                break;
            } else {
                println!("Invalid base64. Try again:");
                let mut line = String::new();
                std::io::stdin().read_line(&mut line);
                let mut line = line.trim().to_string();
                line2 = base64::decode(line);
            }
        }
        packet = line2.unwrap();
        let mut packet = std::io::Cursor::new(packet);
        let (packetid, mut packet) = varint::VarInt::read_packet(&mut packet).unwrap();
        if packetid == 0x01 {
            let mut packet = std::io::Cursor::new(packet);
            let mut rkkey = varint::VarInt::read_varint_prefixed_bytearray(&mut packet);
            let mut ratchetkey = varint::VarInt::read_varint_prefixed_bytearray(&mut packet);    
            let mut hmac = varint::VarInt::read_varint_prefixed_bytearray(&mut packet);
            let mut mac = HmacSha256::new_from_slice(&passwordsigningkey).unwrap();
            mac.update(&rkkey.clone());
            mac.update(&ratchetkey.clone());
            let mac = mac.verify(&hmac);
            if !mac.is_ok() {
                eprintln!("Recieved keys are not correctly verified!");
                std::process::exit(1);
            }
            let mut key1 = EphemeralSecret::new(OsRng);
            let mut key1public = PublicKey::from(&key1);
            let mut packet = vec![];
            //println!("RKKey: {:?}", key1public);
            packet.append(&mut varint::VarInt::write_varint_prefixed_bytearray(key1public.as_bytes().to_vec().clone()));
            let mut mac = HmacSha256::new_from_slice(&passwordsigningkey).unwrap();
            mac.update(&key1public.as_bytes().to_vec().clone());
            let mut mac = mac.finalize().into_bytes().to_vec();
            packet.append(&mut varint::VarInt::write_varint_prefixed_bytearray(mac));
            let mut packet = varint::VarInt::galax_write_packet(packet, 0x02);
            let mut packet = base64::encode(packet);
            println!("\nSend this to the recipient:\n\n\n{}\n\n", packet);
            let mut newrkkey = [0; 32];
            for i in 0..32 {
                newrkkey[i] = rkkey[i];
            }
            let mut rkkey = PublicKey::from(newrkkey);
            let mut sharedsecret = key1.diffie_hellman(&rkkey).as_bytes().to_vec();
            //println!("Shared secret: {:?}", sharedsecret);
            let h = hkdf::Hkdf::<Sha3_256>::new(Some(&[0; 32]), &sharedsecret);
            let mut output = vec![0; 96];
            h.expand(b"RATCHETSETUP", &mut output).unwrap();
            let mut output = std::io::Cursor::new(output);
            let mut key1 = vec![0; 32];
            output.read_exact(&mut key1);
            let mut key2 = vec![0; 32];
            output.read_exact(&mut key2);
            let mut key3 = vec![0; 32];
            output.read_exact(&mut key3);
            let mut newratchetkey = [0; 32];
            for i in 0..32 {
                newratchetkey[i] = ratchetkey[i];
            }
            let mut newhash = vec![];
            newhash.append(&mut key1.clone());
            newhash.append(&mut key2.clone());
            newhash.append(&mut key3.clone());
            newhash.append(&mut newratchetkey.clone().to_vec());
            let mut hash = sha3_256(newhash);
            let mut hash = hex::encode(hash);
            println!("Fingerprint: {:?}", hash);
            let mut ratchetkey = PublicKey::from(newratchetkey);
            let mut ratchet = doubleratchet::StateHE::RatchetInitAliceHE(key1, ratchetkey, key2, key3);
            let mut json = serde_json::to_string_pretty(&ratchet).unwrap();
            std::fs::write("alicepub.key", json);
            println!("\n\n");
            loop {
                println!("Enc or dec? (enc/dec)");
                let mut line = String::new();
                std::io::stdin().read_line(&mut line);
                let mut line = line.trim().to_string();
                if line == "enc" {
                    println!("Text?");
                    let mut line = String::new();
                    std::io::stdin().read_line(&mut line);
                    let mut line = line.trim().to_string();
                    let header = ratchet.RatchetEncryptHE(line.as_bytes().to_vec(), vec![]);
                    let mut json = serde_json::to_string_pretty(&ratchet).unwrap();
                    std::fs::write("alicepub.key", json);
                    let mut ciphertext = base64::encode(&header);
                    println!("-------BEGIN ENCRYPTED-------\n\n{}\n\n-------END ENCRYPTED-------\n", ciphertext);
                } else {
                    println!("Encrypted text?");
                    let mut line = String::new();
                    std::io::stdin().read_line(&mut line);
                    let mut line = line.trim().to_string();
                    let mut line = base64::decode(line);
                    if line.is_err() {
                        println!("Invalid base64.");
                        continue;
                    }
                    let mut line = line.unwrap();
                    let plaintext = ratchet.RatchetDecryptHE(line.to_vec(), vec![]);
                    if plaintext.is_err() {
                        println!("Error decrypting message.");
                        continue;
                    }
                    let plaintext = plaintext.unwrap();
                    let mut json = serde_json::to_string_pretty(&ratchet).unwrap();
                    std::fs::write("alicepub.key", json);
                    let mut plaintext = String::from_utf8_lossy(&plaintext).to_string();
                    println!("-------BEGIN DECRYPTED-------\n\n{}\n\n-------END DECRYPTED-------\n", plaintext);
                }
            }
        } else {
            eprintln!("Incorrect/malformed packet.");
        }
    } else {
        println!("You are Bob.");
        println!("Type in a password. This will be used for authenticating keys!");
        let mut line = String::new();
        std::io::stdin().read_line(&mut line);
        let mut line = line.trim().to_string();
        use argon2::{
            password_hash::{PasswordHasher, Salt, SaltString},
            Argon2,
        };
        use std::convert::TryFrom;
        let params = argon2::Params {
            m_cost: 37000,
            t_cost: 2,
            p_cost: 1,
            output_size: 32,
            version: argon2::Version::default(),
        };
        let argon2 = Argon2::default();
        let salt = SaltString::new(&base64::encode(base64::encode("GoodSalt").as_bytes().to_vec())).unwrap();
        let hash = argon2
        .hash_password(
            &line.as_bytes(),
            None,
            params,
            Salt::try_from(salt.as_ref()).unwrap(),
        )
        .unwrap();
        let passwordsigningkey = hash.hash.unwrap().as_bytes().to_vec();
        let mut key1 = EphemeralSecret::new(OsRng);
        let mut key1public = PublicKey::from(&key1);
        let mut key2 = StaticSecret::new(OsRng);
        let mut key2public = PublicKey::from(&key2);
        let mut packet = vec![];
        packet.append(&mut varint::VarInt::write_varint_prefixed_bytearray(key1public.as_bytes().to_vec()));
        packet.append(&mut varint::VarInt::write_varint_prefixed_bytearray(key2public.as_bytes().to_vec()));
        let mut mac = HmacSha256::new_from_slice(&passwordsigningkey).unwrap();
        mac.update(&key1public.as_bytes().to_vec());
        mac.update(&key2public.as_bytes().to_vec());
        let mut mac = mac.finalize().into_bytes();
        packet.append(&mut varint::VarInt::write_varint_prefixed_bytearray(mac.to_vec()));
        let mut packet = varint::VarInt::galax_write_packet(packet, 0x01);
        let mut packet = base64::encode(&packet);
        println!("Send this to the recipient:\n\n\n{}\n\n", packet);
        println!("Send your recipient's response!");
        let mut line = String::new();
        std::io::stdin().read_line(&mut line);
        let mut line = line.trim().to_string();
        let mut line2 = base64::decode(&line);
        let mut packet = vec![];
        loop {
            if !line2.is_err() {
                break;
            } else {
                println!("Invalid base64. Try again:");
                let mut line = String::new();
                std::io::stdin().read_line(&mut line);
                let mut line = line.trim().to_string();
                line2 = base64::decode(line);
            }
        }
        packet = line2.unwrap();
        let mut packet = std::io::Cursor::new(packet);
        let (packetid, mut packet) = varint::VarInt::read_packet(&mut packet).unwrap();
        if packetid == 0x02 {
            //println!("Packet: {:?}", packet);
            let mut packet = std::io::Cursor::new(packet);
            let mut rkkey = varint::VarInt::read_varint_prefixed_bytearray(&mut packet);
            let mut hmac = varint::VarInt::read_varint_prefixed_bytearray(&mut packet);
            let mut mac = HmacSha256::new_from_slice(&passwordsigningkey).unwrap();
            mac.update(&rkkey);
            let mac = mac.verify(&hmac);
            if !mac.is_ok() {
                eprintln!("Recieved keys are not correctly verified!");
                std::process::exit(1);
            }
            //println!("RKKey: {:?}", rkkey);
            let mut newrkkey = [0; 32];
            for i in 0..32 {
                newrkkey[i] = rkkey[i];
            }
            let rkkey = newrkkey;
            //println!("RKKey: {:?}", rkkey);
            let mut rkkey = PublicKey::from(newrkkey);
            let mut sharedsecret = key1.diffie_hellman(&rkkey).as_bytes().to_vec();
            //println!("Shared secret: {:?}", sharedsecret);
            let h = hkdf::Hkdf::<Sha3_256>::new(Some(&[0; 32]), &sharedsecret);
            let mut output = vec![0; 96];
            h.expand(b"RATCHETSETUP", &mut output).unwrap();
            let mut output = std::io::Cursor::new(output);
            let mut key1 = vec![0; 32];
            output.read_exact(&mut key1);
            let mut key2sym = vec![0; 32];
            output.read_exact(&mut key2sym);
            let mut key3 = vec![0; 32];
            output.read_exact(&mut key3);
            let mut newratchetkey = [0; 32];
            for i in 0..32 {
                newratchetkey[i] = key2public.as_bytes().to_vec()[i];
            }
            let mut newhash = vec![];
            newhash.append(&mut key1.clone());
            newhash.append(&mut key2sym.clone());
            newhash.append(&mut key3.clone());
            newhash.append(&mut newratchetkey.clone().to_vec());
            let mut hash = sha3_256(newhash);
            let mut hash = hex::encode(hash);
            println!("Fingerprint: {:?}", hash);
            let mut ratchetkey = PublicKey::from(newratchetkey);
            let mut ratchet = doubleratchet::StateHE::RatchetInitBobHE(key1, key2, key2sym, key3);
            let mut json = serde_json::to_string_pretty(&ratchet).unwrap();
            std::fs::write("bobpub.key", json);
/*             println!("\n\n\nRatchets have not been initialized. Please give a message from the other party to begin.");
            let mut line = String::new();
            std::io::stdin().read_line(&mut line);
            let mut line = line.trim().to_string();
            let mut line2 = base64::decode(line);
            let mut line = vec![];
            loop {
                if !line2.is_err() {
                break;
                } else {
                    println!("Invalid base64. Try again:");
                    let mut line = String::new();
                    std::io::stdin().read_line(&mut line);
                    let mut line = line.trim().to_string();
                    line2 = base64::decode(line);
                }
            }
            line = line2.unwrap();
            let plaintext = ratchet.RatchetDecryptHE(line.to_vec(), vec![]);
            let mut json = serde_json::to_string_pretty(&ratchet).unwrap();
            std::fs::write("bobpub.key", json);
            if plaintext.is_err() {
                println!("Error decrypting message.");
                std::process::exit(1);
            }
            let plaintext = plaintext.unwrap();
            let mut plaintext = String::from_utf8_lossy(&plaintext).to_string();
            println!("-------BEGIN DECRYPTED-------\n\n{}\n\n-------END DECRYPTED-------\n", plaintext); */
            loop {
                println!("Enc or dec? (enc/dec)");
                let mut line = String::new();
                std::io::stdin().read_line(&mut line);
                let mut line = line.trim().to_string();
                if line == "enc" {
                    println!("Text?");
                    let mut line = String::new();
                    std::io::stdin().read_line(&mut line);
                    let mut line = line.trim().to_string();
                    let header = ratchet.RatchetEncryptHE(line.as_bytes().to_vec(), vec![]);
                    let mut json = serde_json::to_string_pretty(&ratchet).unwrap();
                    std::fs::write("bobpub.key", json);
                    let mut ciphertext = base64::encode(&header);
                    println!("-------BEGIN ENCRYPTED-------\n\n{}\n\n-------END ENCRYPTED-------\n", ciphertext);
                } else {
                    println!("Encrypted text?");
                    let mut line = String::new();
                    std::io::stdin().read_line(&mut line);
                    let mut line = line.trim().to_string();
                    let mut line = base64::decode(line);
                    if line.is_err() {
                        println!("Invalid base64.");
                        continue;
                    }
                    let mut line = line.unwrap();
                    let plaintext = ratchet.RatchetDecryptHE(line.to_vec(), vec![]);
                    let mut json = serde_json::to_string_pretty(&ratchet).unwrap();
                    if plaintext.is_err() {
                        println!("Error decrypting message.");
                        continue;
                    }
                    std::fs::write("bobpub.key", json);
                    let plaintext = plaintext.unwrap();
                    let mut plaintext = String::from_utf8_lossy(&plaintext).to_string();
                    println!("-------BEGIN DECRYPTED-------\n\n{}\n\n-------END DECRYPTED-------\n", plaintext);
                }
            }
        } else {
            eprintln!("Error.");
        }
    }
}
fn sha3_256(input: Vec<u8>) -> Vec<u8> {
    use sha3::{Digest, Sha3_256};
    let mut hasher = Sha3_256::new();
    hasher.update(input);
    return hasher.finalize().to_vec();
}