use aes::Aes128;
use cfb8::cipher::{AsyncStreamCipher, NewCipher};
use cfb8::Cfb8;
use std::io::Read;
type AesCfb8 = Cfb8<Aes128>;
#[derive(Debug)]
pub struct VarInt {
    pub number: u32,
}
impl VarInt {
    #[allow(dead_code)]
    pub fn new(number: u32) -> VarInt {
        return VarInt { number: number };
    }
    #[allow(dead_code)]
    pub fn new_as_bytes(number: u32) -> Vec<u8> {
        let mut vint = VarInt { number: number };
        return vint.into_bytes();
    }
    #[allow(dead_code)]
    pub fn u32_from_bytes(mut input: &mut Vec<u8>) -> Result<VarInt, String> {
        let vint = VarInt::from_bytes(&mut input);
        return vint;
    }
    pub fn new_u32_from_bytes(mut input: &mut dyn std::io::Read) -> Result<VarInt, String> {
        let vint = VarInt::new_from_bytes(&mut input);
        return vint;
    }
    pub fn enc_new_u32_from_bytes(mut input: &mut dyn std::io::Read, mut cipher: &mut AesCfb8) -> Result<VarInt, String> {
        let vint = VarInt::enc_new_from_bytes(&mut input, cipher);
        return vint;
    }
    pub fn read_string(mut input: &mut dyn std::io::Read) -> String {
        let strlen = VarInt::new_u32_from_bytes(input).unwrap().number;
        let mut string = vec![0; strlen as usize];
        input.read_exact(&mut string);
        let string = String::from_utf8_lossy(&string).to_string();
        return string;
    }
    pub fn read_varint_prefixed_bytearray(mut input: &mut dyn std::io::Read) -> Vec<u8> {
        let strlen = VarInt::new_u32_from_bytes(input).unwrap().number;
        let mut string = vec![0; strlen as usize];
        input.read_exact(&mut string);
/*         let string = String::from_utf8_lossy(&string).to_string(); */
        return string;
    }
    pub fn read_unsigned_short(mut input: &mut dyn std::io::Read) -> usize {
        let mut string = vec![0; 2];
        input.read_exact(&mut string);
        let mut numarray = [0; 2];
        for i in 0..2 {
            numarray[i] = string[i];
        }
        let num: u16 = u16::from_be_bytes(numarray);
        let num: usize = num as usize;
        return num;
    }
    pub fn read_u128(mut input: &mut dyn std::io::Read) -> u128 {
        let mut string = vec![0; 16];
        input.read_exact(&mut string);
        let mut numarray = [0; 16];
        for i in 0..16 {
            numarray[i] = string[i];
        }
        let num: u128 = u128::from_be_bytes(numarray);
        let num: u128 = num as u128;
        return num;
    }
    pub fn read_u32(mut input: &mut dyn std::io::Read) -> u32 {
        let mut string = vec![0; 4];
        input.read_exact(&mut string);
        let mut numarray = [0; 4];
        for i in 0..4 {
            numarray[i] = string[i];
        }
        let num: u32 = u32::from_be_bytes(numarray);
        let num: u32 = num as u32;
        return num;
    }
    pub fn read_short(mut input: &mut dyn std::io::Read) -> isize {
        let mut string = vec![0; 2];
        input.read_exact(&mut string);
        let mut numarray = [0; 2];
        for i in 0..2 {
            numarray[i] = string[i];
        }
        let num: i16 = i16::from_be_bytes(numarray);
        let num: isize = num as isize;
        return num;
    }
    pub fn read_int(mut input: &mut dyn std::io::Read) -> isize {
        let mut string = vec![0; 4];
        input.read_exact(&mut string);
        let mut numarray = [0; 4];
        for i in 0..4 {
            numarray[i] = string[i];
        }
        let num: i32 = i32::from_be_bytes(numarray);
        let num: isize = num as isize;
        return num;
    }
    pub fn read_byte(mut input: &mut dyn std::io::Read) -> u8 {
        let mut string = vec![0; 1];
        input.read_exact(&mut string);
        return string[0];
    }
    pub fn write_short(number: i16) -> Vec<u8> {
        let mut bytes = number.to_be_bytes().to_vec();
        if bytes.len() < 2 {
            for i in 0..2 - bytes.len() {
                bytes.reverse();
                bytes.push(0x00);
                bytes.reverse();
            }
        }
        return bytes;
    }
    pub fn write_int(number: i32) -> Vec<u8> {
        let mut bytes = number.to_be_bytes().to_vec();
        if bytes.len() < 4 {
            for i in 0..4 - bytes.len() {
                bytes.reverse();
                bytes.push(0x00);
                bytes.reverse();
            }
        }
        return bytes;
    }
    pub fn write_unsigned_short(number: u16) -> Vec<u8> {
        let mut bytes = number.to_be_bytes().to_vec();
        if bytes.len() < 2 {
            for i in 0..2 - bytes.len() {
                bytes.reverse();
                bytes.push(0x00);
                bytes.reverse();
            }
        }
        return bytes;
    }
    pub fn write_u128(number: u128) -> Vec<u8> {
        let mut bytes = number.to_be_bytes().to_vec();
        if bytes.len() < 16 {
            for i in 0..16 - bytes.len() {
                bytes.reverse();
                bytes.push(0x00);
                bytes.reverse();
            }
        }
        return bytes;
    }
    pub fn write_u32(number: u32) -> Vec<u8> {
        let mut bytes = number.to_be_bytes().to_vec();
        if bytes.len() < 4 {
            for i in 0..4 - bytes.len() {
                bytes.reverse();
                bytes.push(0x00);
                bytes.reverse();
            }
        }
        return bytes;
    }
    pub fn enc_read_packet(mut input: &mut dyn std::io::Read, mut cipher: &mut AesCfb8) -> Result<(usize, Vec<u8>), String> {
        let length = VarInt::enc_new_u32_from_bytes(input, cipher);
        if length.is_err() {
            return Err("Failed to read.".to_string());
        }
        let length = length.unwrap().number;
        let mut packet = vec![0; length as usize];
        input.read_exact(&mut packet);
        cipher.decrypt(&mut packet);
        let packetid = VarInt::u32_from_bytes(&mut packet).unwrap().number as usize;
        return Ok((packetid, packet));
    }
    pub fn read_packet(mut input: &mut dyn std::io::Read) -> Result<(usize, Vec<u8>), String> {
        let length = VarInt::new_u32_from_bytes(input);
        if length.is_err() {
            return Err("Failed to read.".to_string())
        }
        let length = length.unwrap().number;
        let mut packet = vec![0; length as usize];
        input.read_exact(&mut packet);
        let packetid = VarInt::u32_from_bytes(&mut packet).unwrap().number as usize;
        return Ok((packetid, packet));
    }
    pub fn write_pluginmessage_packet(mut input: Vec<u8>, channel: &str) -> Vec<u8> {
        let mut packet = vec![];
        packet.append(&mut VarInt::write_string(channel.to_string()));
        packet.append(&mut VarInt::write_short(input.len() as i16));
        packet.append(&mut input.clone());
        let packet = VarInt::galax_write_packet(packet, 0x17);
        return packet;
    }
    pub fn galax_write_packet(mut input: Vec<u8>, packetid: usize) -> Vec<u8> {
        let mut packetidvec = vec![];
        packetidvec.append(&mut VarInt::new_as_bytes(packetid as u32));
        let mut packet = vec![];
        packet.append(&mut VarInt::new_as_bytes((packetidvec.len() + input.len()) as u32));
        packet.append(&mut packetidvec);
        packet.append(&mut input);
        return packet;
    }
    pub fn galax_write_packet_2(mut input: Vec<u8>, packetid: usize) -> Vec<u8> {
        let mut packetidvec = vec![];
        packetidvec.append(&mut VarInt::new_as_bytes(packetid as u32));
        let mut packet = vec![];
        packet.append(&mut VarInt::new_as_bytes((packetidvec.len() + input.len() + 1) as u32));
        packet.append(&mut packetidvec);
        packet.append(&mut input);
        return packet;
    }
    pub fn write_packet(mut input: Vec<u8>, packetid: usize) -> Vec<u8> {
        let mut packet = vec![];
        packet.append(&mut VarInt::new_as_bytes(packetid as u32));
        packet.append(&mut input);
        packet.reverse();
        let mut fpacketlen = vec![];
        fpacketlen.append(&mut VarInt::new_as_bytes(packet.len() as u32));
        fpacketlen.reverse();
        packet.append(&mut fpacketlen);
        packet.reverse();
        return packet;
    }
    pub fn write_string(string: String) -> Vec<u8> {
        let mut packet = vec![];
        packet.append(&mut VarInt::new_as_bytes(string.as_bytes().len() as u32));
        packet.append(&mut string.as_bytes().to_vec());
        return packet;
    }
    pub fn write_varint_prefixed_bytearray(string: Vec<u8>) -> Vec<u8> {
        let mut packet = vec![];
        packet.append(&mut VarInt::new_as_bytes(string.len() as u32));
        packet.append(&mut string.to_vec());
        return packet;
    }
    pub fn into_bytes(&mut self) -> Vec<u8> {
        if self.number == 0 {
            return vec![0];
        }
        use integer_encoding::VarInt;
        let mut packetconstruct = vec![];
        let mut varint1 = vec![0; 32];
        self.number.encode_var(&mut varint1);
        for i in 0..varint1.len() {
            if varint1[i] != 0 {
                packetconstruct.push(varint1[i]);
            }
        }
        return packetconstruct;
    }
    pub fn from_bytes(inputvec: &mut Vec<u8>) -> Result<VarInt, String> {
        use std::convert::TryInto;
        let mut inputreader = std::io::Cursor::new(inputvec.clone());
        let mut input = vec![0; 1];
        let result = inputreader.read_exact(&mut input);
        if result.is_err() {
            return Err("Failed to read.".to_string());
        }
        let mut fullbyte: Vec<String> = vec![];
        let mut current = 0;
        let mut bytesstepped = 0;
        let mut largebytestepped = 0;
        for _ in 0..5 {
            bytesstepped += 1;
            let currentbyte = format!("{:b}", input[current]);
            let mut var = currentbyte.chars().rev().collect::<String>();
            for _g in 0..9 - var.chars().count() {
                if var.chars().count() < 8 {
                    var.push_str("0");
                }
            }
            let currentbyte = var.chars().rev().collect::<String>();
            //println!("current byte: {}",currentbyte);
            if currentbyte.chars().nth(0).unwrap() == '1' {
                if currentbyte.len() > 1 {
                    //println!("Pushing: {}",&currentbyte[1..currentbyte.len()]);
                    fullbyte.push(currentbyte[1..currentbyte.len()].to_string());
                    current += 1;
                } else {
                    fullbyte.push(currentbyte);
                    current += 1;
                }
                let mut buf = vec![0; 1];
                // Do appropriate error handling for your situation
                // Maybe it's OK if you didn't read enough bytes?
                inputreader
                    .read_exact(&mut buf)
                    .expect("Didn't read enough");
                input.append(&mut buf.clone());
            } else {
                //println!("Pushing B: {}",&currentbyte[1..currentbyte.len()]);
                fullbyte.push(currentbyte[1..currentbyte.len()].to_string());
                break;
            }
        }
        fullbyte.reverse();
        let mut fullbyte2 = "".to_owned();
        //println!("Full byte: {:?}",fullbyte);
        for i in 0..fullbyte.len() {
            fullbyte2.push_str(&fullbyte[i]);
        }
        let finalen: u32 = isize::from_str_radix(&fullbyte2, 2)
            .unwrap()
            .try_into()
            .unwrap();
        largebytestepped += bytesstepped;
        //largebytestepped+=finalen;
        for _ in 0..largebytestepped {
            inputvec.remove(0);
        }
        return Ok(VarInt { number: finalen });
    }
    pub fn enc_new_from_bytes(inputreader: &mut dyn std::io::Read, mut cipher: &mut AesCfb8) -> Result<VarInt, String> {
        use std::convert::TryInto;
        //let mut inputreader = std::io::Cursor::new(inputvec.clone());
        let mut input = vec![0; 1];
        let g = inputreader.read_exact(&mut input);
        if g.is_err() {
            return Err("Failed to read".to_string());
        }
        cipher.decrypt(&mut input);
        let mut fullbyte: Vec<String> = vec![];
        let mut current = 0;
        let mut bytesstepped = 0;
        let mut largebytestepped = 0;
        for _ in 0..5 {
            bytesstepped += 1;
            let currentbyte = format!("{:b}", input[current]);
            let mut var = currentbyte.chars().rev().collect::<String>();
            for _g in 0..9 - var.chars().count() {
                if var.chars().count() < 8 {
                    var.push_str("0");
                }
            }
            let currentbyte = var.chars().rev().collect::<String>();
            //println!("current byte: {}",currentbyte);
            if currentbyte.chars().nth(0).unwrap() == '1' {
                if currentbyte.len() > 1 {
                    //println!("Pushing: {}",&currentbyte[1..currentbyte.len()]);
                    fullbyte.push(currentbyte[1..currentbyte.len()].to_string());
                    current += 1;
                } else {
                    fullbyte.push(currentbyte);
                    current += 1;
                }
                let mut buf = vec![0; 1];
                // Do appropriate error handling for your situation
                // Maybe it's OK if you didn't read enough bytes?
                inputreader
                    .read_exact(&mut buf)
                    .expect("Didn't read enough");
                cipher.decrypt(&mut buf);
                input.append(&mut buf.clone());
            } else {
                //println!("Pushing B: {}",&currentbyte[1..currentbyte.len()]);
                fullbyte.push(currentbyte[1..currentbyte.len()].to_string());
                break;
            }
        }
        fullbyte.reverse();
        let mut fullbyte2 = "".to_owned();
        //println!("Full byte: {:?}",fullbyte);
        for i in 0..fullbyte.len() {
            fullbyte2.push_str(&fullbyte[i]);
        }
        let finalen: u32 = isize::from_str_radix(&fullbyte2, 2)
            .unwrap()
            .try_into()
            .unwrap();
        largebytestepped += bytesstepped;
        //largebytestepped+=finalen;
        return Ok(VarInt { number: finalen });
    }
    pub fn new_from_bytes(inputreader: &mut dyn std::io::Read) -> Result<VarInt, String> {
        use std::convert::TryInto;
        //let mut inputreader = std::io::Cursor::new(inputvec.clone());
        let mut input = vec![0; 1];
        let g = inputreader.read_exact(&mut input);
        if g.is_err() {
            return Err("Failed to read".to_string())
        }
        let mut fullbyte: Vec<String> = vec![];
        let mut current = 0;
        let mut bytesstepped = 0;
        let mut largebytestepped = 0;
        for _ in 0..5 {
            bytesstepped += 1;
            let currentbyte = format!("{:b}", input[current]);
            let mut var = currentbyte.chars().rev().collect::<String>();
            for _g in 0..9 - var.chars().count() {
                if var.chars().count() < 8 {
                    var.push_str("0");
                }
            }
            let currentbyte = var.chars().rev().collect::<String>();
            //println!("current byte: {}",currentbyte);
            if currentbyte.chars().nth(0).unwrap() == '1' {
                if currentbyte.len() > 1 {
                    //println!("Pushing: {}",&currentbyte[1..currentbyte.len()]);
                    fullbyte.push(currentbyte[1..currentbyte.len()].to_string());
                    current += 1;
                } else {
                    fullbyte.push(currentbyte);
                    current += 1;
                }
                let mut buf = vec![0; 1];
                // Do appropriate error handling for your situation
                // Maybe it's OK if you didn't read enough bytes?
                inputreader
                    .read_exact(&mut buf)
                    .expect("Didn't read enough");
                input.append(&mut buf.clone());
            } else {
                //println!("Pushing B: {}",&currentbyte[1..currentbyte.len()]);
                fullbyte.push(currentbyte[1..currentbyte.len()].to_string());
                break;
            }
        }
        fullbyte.reverse();
        let mut fullbyte2 = "".to_owned();
        //println!("Full byte: {:?}",fullbyte);
        for i in 0..fullbyte.len() {
            fullbyte2.push_str(&fullbyte[i]);
        }
        let finalen: u32 = isize::from_str_radix(&fullbyte2, 2)
            .unwrap()
            .try_into()
            .unwrap();
        largebytestepped += bytesstepped;
        //largebytestepped+=finalen;
        return Ok(VarInt { number: finalen });
    }
}
