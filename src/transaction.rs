// use k256::ecdsa::{Signature, SigningKey, signature::Signer};
// use k256::elliptic_curve::rand_core::OsRng;
// use sha2::{Digest, Sha256};

// type ByteVec = Vec<u8>;

// fn sha256(data: &[u8]) -> ByteVec {
//     Sha256::digest(data).to_vec()
// }

// // トランザクションのフィールドを手動で直列化
// fn serialize_varint(n: usize) -> ByteVec {
//     if n < 0xfd {
//         vec![n as u8]
//     } else {
//         unimplemented!("only short varints implemented");
//     }
// }

// // Taproot用のダミー署名を生成
// fn sign_dummy(message: &[u8], sk: &SigningKey) -> ByteVec {
//     let sig: Signature = sk.sign(message);
//     let mut result = sig.to_der().as_bytes().to_vec();
//     result.push(0x00); // SIGHASH_DEFAULT (0x00)
//     result
// }

// // Input構造体
// struct Input {
//     prev_txid: [u8; 32],
//     vout: u32,
//     sequence: u32,
//     taproot_sk: SigningKey,
// }

// // Output構造体
// struct Output {
//     value: u64,
//     script_pubkey: ByteVec,
// }

// // Witness stack: 個別に定義
// fn build_witness_stack(sig: ByteVec) -> ByteVec {
//     let mut out = ByteVec::new();
//     out.extend(serialize_varint(1)); // 1 stack item
//     out.extend(serialize_varint(sig.len()));
//     out.extend(sig);
//     out
// }

// fn main() {
//     let inputs = vec![
//         Input {
//             prev_txid: [0xaa; 32],
//             vout: 0,
//             sequence: 0xffffffff,
//             taproot_sk: SigningKey::random(&mut OsRng),
//         },
//         Input {
//             prev_txid: [0xbb; 32],
//             vout: 1,
//             sequence: 0xffffffff,
//             taproot_sk: SigningKey::random(&mut OsRng),
//         },
//     ];

//     let outputs = vec![Output {
//         value: 50_000,
//         script_pubkey: vec![0x51], // OP_TRUE (dummy)
//     }];

//     // トランザクション本体（witness除く）
//     let mut tx = ByteVec::new();
//     tx.push(0x02); // version
//     tx.push(0x00); // marker (for segwit)
//     tx.push(0x01); // flag

//     // vin
//     tx.extend(serialize_varint(inputs.len()));
//     for input in &inputs {
//         tx.extend(input.prev_txid.iter().rev()); // txid (LE)
//         tx.extend(&(input.vout.to_le_bytes())); // vout
//         tx.extend(serialize_varint(0)); // scriptSig: empty
//         tx.extend(&input.sequence.to_le_bytes()); // sequence
//     }

//     // vout
//     tx.extend(serialize_varint(outputs.len()));
//     for output in &outputs {
//         tx.extend(&output.value.to_le_bytes());
//         tx.extend(serialize_varint(output.script_pubkey.len()));
//         tx.extend(&output.script_pubkey);
//     }

//     // witness for each input
//     for input in &inputs {
//         // For real Taproot SIGHASH, you would compute message hash here
//         let dummy_msg = b"dummy_sighash_message";
//         let sig = sign_dummy(dummy_msg, &input.taproot_sk);
//         let witness = build_witness_stack(sig);
//         tx.extend(&witness);
//     }

//     tx.extend(&0x00000000u32.to_le_bytes()); // locktime

//     println!("Tx (hex): {}", hex::encode(tx));
// }

// use crate::key::SecretKey;
// use sha2::{Digest, Sha256};

// /// Bitcoin transaction OutPoint.
// #[derive(Clone, Debug)]
// pub struct OutPoint {
//     pub txid: [u8; 32],
//     pub vout: u32,
// }

// /// Bitcoin transaction input.
// #[derive(Clone, Debug)]
// pub struct TxIn {
//     pub previous_output: OutPoint,
//     pub script_sig: Vec<u8>,
//     pub sequence: u32,
//     pub witness: Vec<Vec<u8>>, // segwit witness stack
// }

// /// Bitcoin transaction output.
// #[derive(Clone, Debug)]
// pub struct TxOut {
//     pub value: u64,
//     pub script_pubkey: Vec<u8>,
// }

// /// Bitcoin transaction.
// #[derive(Clone, Debug)]
// pub struct Transaction {
//     pub version: i32,
//     pub inputs: Vec<TxIn>,
//     pub outputs: Vec<TxOut>,
//     pub lock_time: u32,
// }

// #[derive(thiserror::Error, Debug)]
// pub enum SignError {
//     #[error("failed to sign")]
//     FailedSign,
// }

// impl Transaction {
//     pub fn new(version: i32, lock_time: u32) -> Self {
//         Self {
//             version,
//             inputs: Vec::new(),
//             outputs: Vec::new(),
//             lock_time,
//         }
//     }

//     pub fn add_input(&mut self, input: TxIn) {
//         self.inputs.push(input);
//     }

//     pub fn add_output(&mut self, output: TxOut) {
//         self.outputs.push(output);
//     }

//     /// Serialize transaction according to BIP144.
//     pub fn encode(&self) -> Vec<u8> {
//         let has_witness = self.inputs.iter().any(|i| !i.witness.is_empty());
//         let mut buf = Vec::new();
//         buf.extend_from_slice(&self.version.to_le_bytes());
//         if has_witness {
//             buf.extend_from_slice(&[0x00, 0x01]);
//         }
//         write_varint(self.inputs.len() as u64, &mut buf);
//         for txin in &self.inputs {
//             buf.extend_from_slice(&txin.previous_output.txid);
//             buf.extend_from_slice(&txin.previous_output.vout.to_le_bytes());
//             write_varbytes(&txin.script_sig, &mut buf);
//             buf.extend_from_slice(&txin.sequence.to_le_bytes());
//         }
//         write_varint(self.outputs.len() as u64, &mut buf);
//         for txout in &self.outputs {
//             buf.extend_from_slice(&txout.value.to_le_bytes());
//             write_varbytes(&txout.script_pubkey, &mut buf);
//         }
//         if has_witness {
//             for txin in &self.inputs {
//                 write_varint(txin.witness.len() as u64, &mut buf);
//                 for item in &txin.witness {
//                     write_varbytes(item, &mut buf);
//                 }
//             }
//         }
//         buf.extend_from_slice(&self.lock_time.to_le_bytes());
//         buf
//     }

//     /// Decode transaction encoded according to BIP144.
//     pub fn decode(data: &[u8]) -> Option<Self> {
//         let mut idx = 0;

//         let version = read_i32(data, &mut idx)?;
//         let mut has_witness = false;
//         if idx + 2 <= data.len() && data[idx] == 0x00 && data[idx + 1] == 0x01 {
//             has_witness = true;
//             idx += 2;
//         }

//         let input_len = read_varint(data, &mut idx)? as usize;
//         let mut inputs = Vec::with_capacity(input_len);
//         for _ in 0..input_len {
//             let txid = read_array32(data, &mut idx)?;
//             let vout = read_u32(data, &mut idx)?;
//             let script_sig = read_varbytes(data, &mut idx)?;
//             let sequence = read_u32(data, &mut idx)?;
//             inputs.push(TxIn {
//                 previous_output: OutPoint { txid, vout },
//                 script_sig,
//                 sequence,
//                 witness: Vec::new(),
//             });
//         }

//         let output_len = read_varint(data, &mut idx)? as usize;
//         let mut outputs = Vec::with_capacity(output_len);
//         for _ in 0..output_len {
//             let value = read_u64(data, &mut idx)?;
//             let script_pubkey = read_varbytes(data, &mut idx)?;
//             outputs.push(TxOut {
//                 value,
//                 script_pubkey,
//             });
//         }

//         if has_witness {
//             for txin in &mut inputs {
//                 let wit_len = read_varint(data, &mut idx)? as usize;
//                 let mut witness = Vec::with_capacity(wit_len);
//                 for _ in 0..wit_len {
//                     witness.push(read_varbytes(data, &mut idx)?);
//                 }
//                 txin.witness = witness;
//             }
//         }

//         let lock_time = read_u32(data, &mut idx)?;
//         Some(Self {
//             version,
//             inputs,
//             outputs,
//             lock_time,
//         })
//     }

//     /// Transaction id (double SHA256 of the legacy serialization).
//     pub fn txid(&self) -> [u8; 32] {
//         let mut buf = Vec::new();
//         buf.extend_from_slice(&self.version.to_le_bytes());
//         write_varint(self.inputs.len() as u64, &mut buf);
//         for txin in &self.inputs {
//             buf.extend_from_slice(&txin.previous_output.txid);
//             buf.extend_from_slice(&txin.previous_output.vout.to_le_bytes());
//             write_varbytes(&txin.script_sig, &mut buf);
//             buf.extend_from_slice(&txin.sequence.to_le_bytes());
//         }
//         write_varint(self.outputs.len() as u64, &mut buf);
//         for txout in &self.outputs {
//             buf.extend_from_slice(&txout.value.to_le_bytes());
//             write_varbytes(&txout.script_pubkey, &mut buf);
//         }
//         buf.extend_from_slice(&self.lock_time.to_le_bytes());

//         let hash = Sha256::digest(&buf);
//         let hash = Sha256::digest(&hash);
//         let mut result = [0u8; 32];
//         result.copy_from_slice(&hash);
//         result
//     }

//     pub fn sign_all_inputs(&mut self, key: &SecretKey) -> Result<(), SignError> {
//         let hash = self.txid();
//         for txin in &mut self.inputs {
//             let sig = key
//                 .sign_prehashed(&hash)
//                 .ok_or(SignError::FailedSign)?
//                 .to_vec();
//             txin.witness.push(sig);
//         }
//         Ok(())
//     }
// }

// fn write_varint(value: u64, buf: &mut Vec<u8>) {
//     if value < 0xfd {
//         buf.push(value as u8);
//     } else if value <= 0xffff {
//         buf.push(0xfd);
//         buf.extend_from_slice(&(value as u16).to_le_bytes());
//     } else if value <= 0xffff_ffff {
//         buf.push(0xfe);
//         buf.extend_from_slice(&(value as u32).to_le_bytes());
//     } else {
//         buf.push(0xff);
//         buf.extend_from_slice(&value.to_le_bytes());
//     }
// }

// fn write_varbytes(data: &[u8], buf: &mut Vec<u8>) {
//     write_varint(data.len() as u64, buf);
//     buf.extend_from_slice(data);
// }

// fn read_i32(data: &[u8], idx: &mut usize) -> Option<i32> {
//     let bytes = data.get(*idx..*idx + 4)?;
//     *idx += 4;
//     Some(i32::from_le_bytes(bytes.try_into().ok()?))
// }

// fn read_u32(data: &[u8], idx: &mut usize) -> Option<u32> {
//     let bytes = data.get(*idx..*idx + 4)?;
//     *idx += 4;
//     Some(u32::from_le_bytes(bytes.try_into().ok()?))
// }

// fn read_u64(data: &[u8], idx: &mut usize) -> Option<u64> {
//     let bytes = data.get(*idx..*idx + 8)?;
//     *idx += 8;
//     Some(u64::from_le_bytes(bytes.try_into().ok()?))
// }

// fn read_array32(data: &[u8], idx: &mut usize) -> Option<[u8; 32]> {
//     let bytes = data.get(*idx..*idx + 32)?;
//     *idx += 32;
//     Some(bytes.try_into().ok()?)
// }

// fn read_varint(data: &[u8], idx: &mut usize) -> Option<u64> {
//     let first = *data.get(*idx)?;
//     *idx += 1;
//     match first {
//         v @ 0x00..=0xfc => Some(v as u64),
//         0xfd => {
//             let bytes = data.get(*idx..*idx + 2)?;
//             *idx += 2;
//             Some(u16::from_le_bytes(bytes.try_into().ok()?) as u64)
//         }
//         0xfe => {
//             let bytes = data.get(*idx..*idx + 4)?;
//             *idx += 4;
//             Some(u32::from_le_bytes(bytes.try_into().ok()?) as u64)
//         }
//         0xff => {
//             let bytes = data.get(*idx..*idx + 8)?;
//             *idx += 8;
//             Some(u64::from_le_bytes(bytes.try_into().ok()?))
//         }
//     }
// }

// fn read_varbytes(data: &[u8], idx: &mut usize) -> Option<Vec<u8>> {
//     let len = read_varint(data, idx)? as usize;
//     let bytes = data.get(*idx..*idx + len)?;
//     *idx += len;
//     Some(bytes.to_vec())
// }

// #[cfg(test)]
// mod tests {
//     use super::*;
//     use rand_core::OsRng;

//     #[rstest::rstest]
//     fn test_encode_empty() {
//         let tx = Transaction::new(2, 0);
//         assert_eq!(tx.encode(), [2, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
//     }

//     #[rstest::rstest]
//     fn test_sign_all_inputs() {
//         let mut rng = OsRng;
//         let key = SecretKey::random(&mut rng);
//         let mut tx = Transaction::new(2, 0);
//         tx.add_input(TxIn {
//             previous_output: OutPoint {
//                 txid: [0u8; 32],
//                 vout: 0,
//             },
//             script_sig: Vec::new(),
//             sequence: 0xffffffff,
//             witness: Vec::new(),
//         });
//         tx.add_output(TxOut {
//             value: 0,
//             script_pubkey: Vec::new(),
//         });
//         tx.sign_all_inputs(&key).unwrap();
//         assert_eq!(tx.inputs[0].witness.len(), 1);
//         assert_eq!(tx.inputs[0].witness[0].len(), 64);
//     }

//     #[rstest::rstest]
//     fn test_encode_decode_roundtrip() {
//         let mut tx = Transaction::new(2, 0);
//         tx.add_input(TxIn {
//             previous_output: OutPoint {
//                 txid: [1u8; 32],
//                 vout: 0,
//             },
//             script_sig: vec![0x51],
//             sequence: 0xfffffffe,
//             witness: vec![vec![0xaa]],
//         });
//         tx.add_output(TxOut {
//             value: 10,
//             script_pubkey: vec![0xab, 0xcd],
//         });

//         let encoded = tx.encode();
//         let decoded = Transaction::decode(&encoded).unwrap();

//         assert_eq!(decoded.encode(), encoded);
//     }
// }

use sha2::{Digest, Sha256};

#[derive(thiserror::Error, Debug)]
pub enum SignError {
    #[error("failed to sign")]
    FailedSign,
    #[error("incompatible prevout or secret_keys")]
    Length,
}

// TODO: remove redundant code
fn tagged_hash(tag: &str, data: &[u8]) -> [u8; 32] {
    let tag_hash = Sha256::digest(tag.as_bytes());
    let mut hasher = Sha256::new();
    hasher.update(tag_hash);
    hasher.update(tag_hash);
    hasher.update(data);
    hasher.finalize().into()
}

/// Bitcoin transaction OutPoint.
#[derive(Clone, Debug)]
pub struct OutPoint {
    pub txid: [u8; 32],
    pub vout: u32,
}

/// Bitcoin transaction input.
#[derive(Clone, Debug)]
pub struct TxIn {
    pub previous_output: OutPoint,
    pub script_sig: Vec<u8>,
    pub sequence: u32,
    pub witness: Vec<Vec<u8>>, // segwit witness stack
}

/// Bitcoin transaction output.
#[derive(Clone, Debug)]
pub struct TxOut {
    pub value: u64,
    pub script_pubkey: Vec<u8>,
}

/// Bitcoin transaction.
#[derive(Clone, Debug)]
pub struct Transaction {
    pub version: i32,
    pub inputs: Vec<TxIn>,
    pub outputs: Vec<TxOut>,
    pub lock_time: u32,
}

impl Transaction {
    pub fn new(version: i32, lock_time: u32) -> Self {
        Self {
            version,
            inputs: Vec::new(),
            outputs: Vec::new(),
            lock_time,
        }
    }

    pub fn add_input(&mut self, input: TxIn) {
        self.inputs.push(input);
    }

    pub fn add_output(&mut self, output: TxOut) {
        self.outputs.push(output);
    }

    /// Serialize transaction according to BIP144.
    pub fn encode(&self) -> Vec<u8> {
        let has_witness = self.inputs.iter().any(|i| !i.witness.is_empty());
        let mut buf = Vec::new();
        buf.extend_from_slice(&self.version.to_le_bytes());
        if has_witness {
            buf.extend_from_slice(&[0x00, 0x01]);
        }
        write_varint(self.inputs.len() as u64, &mut buf);
        for txin in &self.inputs {
            buf.extend_from_slice(&txin.previous_output.txid);
            buf.extend_from_slice(&txin.previous_output.vout.to_le_bytes());
            write_varbytes(&txin.script_sig, &mut buf);
            buf.extend_from_slice(&txin.sequence.to_le_bytes());
        }
        write_varint(self.outputs.len() as u64, &mut buf);
        for txout in &self.outputs {
            buf.extend_from_slice(&txout.value.to_le_bytes());
            write_varbytes(&txout.script_pubkey, &mut buf);
        }
        if has_witness {
            for txin in &self.inputs {
                write_varint(txin.witness.len() as u64, &mut buf);
                for item in &txin.witness {
                    write_varbytes(item, &mut buf);
                }
            }
        }
        buf.extend_from_slice(&self.lock_time.to_le_bytes());
        buf
    }

    /// Transaction id (double SHA256 of the legacy serialization).
    pub fn txid(&self) -> [u8; 32] {
        let mut buf = Vec::new();
        buf.extend_from_slice(&self.version.to_le_bytes());
        write_varint(self.inputs.len() as u64, &mut buf);
        for txin in &self.inputs {
            buf.extend_from_slice(&txin.previous_output.txid);
            buf.extend_from_slice(&txin.previous_output.vout.to_le_bytes());
            write_varbytes(&txin.script_sig, &mut buf);
            buf.extend_from_slice(&txin.sequence.to_le_bytes());
        }
        write_varint(self.outputs.len() as u64, &mut buf);
        for txout in &self.outputs {
            buf.extend_from_slice(&txout.value.to_le_bytes());
            write_varbytes(&txout.script_pubkey, &mut buf);
        }
        buf.extend_from_slice(&self.lock_time.to_le_bytes());

        let hash = Sha256::digest(&buf);
        let hash = Sha256::digest(&hash);
        let mut result = [0u8; 32];
        result.copy_from_slice(&hash);
        result
    }

    pub fn taproot_sighash(
        &self,
        input_index: usize,
        prevouts: &[TxOut],
        hash_type: u8,
    ) -> [u8; 32] {
        assert_eq!(prevouts.len(), self.inputs.len());

        let mut buf = Vec::new();
        for input in &self.inputs {
            buf.extend_from_slice(&input.previous_output.txid);
            buf.extend_from_slice(&input.previous_output.vout.to_le_bytes());
        }
        let hash_prevouts = Sha256::digest(&buf);

        buf.clear();
        for prev in prevouts {
            buf.extend_from_slice(&prev.value.to_le_bytes());
        }
        let hash_amounts = Sha256::digest(&buf);

        buf.clear();
        for prev in prevouts {
            write_varbytes(&prev.script_pubkey, &mut buf);
        }
        let hash_scriptpubkeys = Sha256::digest(&buf);

        buf.clear();
        for input in &self.inputs {
            buf.extend_from_slice(&input.sequence.to_le_bytes());
        }
        let hash_sequences = Sha256::digest(&buf);

        buf.clear();
        for output in &self.outputs {
            buf.extend_from_slice(&output.value.to_le_bytes());
            write_varbytes(&output.script_pubkey, &mut buf);
        }
        let hash_outputs = Sha256::digest(&buf);

        let mut msg = Vec::new();
        msg.extend_from_slice(&self.version.to_le_bytes());
        msg.extend_from_slice(&self.lock_time.to_le_bytes());
        msg.extend_from_slice(&hash_prevouts);
        msg.extend_from_slice(&hash_amounts);
        msg.extend_from_slice(&hash_scriptpubkeys);
        msg.extend_from_slice(&hash_sequences);
        msg.extend_from_slice(&hash_outputs);
        msg.extend_from_slice(&[0u8; 32]); // annex not supported
        msg.extend_from_slice(&[0u8; 32]); // script path not supported
        msg.extend_from_slice(&(input_index as u32).to_le_bytes());
        msg.push(0); // ext_flag = 0 (key spend only)
        msg.push(0); // key_version = 0
        msg.push(hash_type);

        tagged_hash("TapSighash", &msg)
    }

    pub fn sign_all_inputs(
        &mut self,
        prevouts: &[TxOut],
        secret_keys: &[crate::key::SecretKey],
    ) -> Result<(), SignError> {
        if prevouts.len() != self.inputs.len() {
            return Err(SignError::Length);
        }
        if secret_keys.len() != self.inputs.len() {
            return Err(SignError::Length);
        }
        // for (i, (input, secret_key)) in self.inputs.iter_mut().zip(secret_keys).enumerate() {
        //     let sighash = self.taproot_sighash(i, prevouts, 0);
        //     let sig = sk.sign(&sighash).ok_or(SignError::FailedSign)?;
        //     input.witness = vec![sig.to_vec()];
        // }
        for i in 0..self.inputs.len() {
            let sighash = self.taproot_sighash(i, prevouts, 0);
            let sig = secret_keys[i].sign(&sighash).ok_or(SignError::FailedSign)?;
            self.inputs[i].witness = vec![sig.to_vec()];
        }
        Ok(())
    }
}

fn write_varint(value: u64, buf: &mut Vec<u8>) {
    if value < 0xfd {
        buf.push(value as u8);
    } else if value <= 0xffff {
        buf.push(0xfd);
        buf.extend_from_slice(&(value as u16).to_le_bytes());
    } else if value <= 0xffff_ffff {
        buf.push(0xfe);
        buf.extend_from_slice(&(value as u32).to_le_bytes());
    } else {
        buf.push(0xff);
        buf.extend_from_slice(&value.to_le_bytes());
    }
}

fn write_varbytes(data: &[u8], buf: &mut Vec<u8>) {
    write_varint(data.len() as u64, buf);
    buf.extend_from_slice(data);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::key::{Network, PublicKey, SecretKey};
    use k256::schnorr::{SigningKey, signature::hazmat::PrehashVerifier};

    #[rstest::rstest]
    fn test_encode_empty() {
        let tx = Transaction::new(2, 0);
        assert_eq!(tx.encode(), [2, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
    }

    #[rstest::rstest]
    fn test_sign_taproot() {
        let sk = SecretKey::new(SigningKey::from_bytes(&[1; 32]).unwrap());
        let pk = sk.to_public();
        let addr = pk.to_address(Network::Testnet).unwrap();
        let script_pubkey = addr.script_pubkey();

        let prevout = TxOut {
            value: 10_000,
            script_pubkey: script_pubkey.clone(),
        };
        let outpoint = OutPoint {
            txid: [2; 32],
            vout: 0,
        };
        let mut tx = Transaction::new(2, 0);
        tx.add_input(TxIn {
            previous_output: outpoint,
            script_sig: vec![],
            sequence: 0xfffffffe,
            witness: vec![],
        });
        tx.add_output(TxOut {
            value: 9_500,
            script_pubkey: vec![0x6a],
        });

        tx.sign_all_inputs(&[prevout.clone()], &[sk]).unwrap();

        let sighash = tx.taproot_sighash(0, &[prevout], 0);
        let sig = k256::schnorr::Signature::try_from(&tx.inputs[0].witness[0][..]).unwrap();
        pk.verify_prehash(&sighash, &sig).unwrap();
    }

    #[rstest::rstest]
    fn test_sign_taproot_vector() {
        let sk = SecretKey::new(SigningKey::from_bytes(&[1; 32]).unwrap());
        let pk = sk.to_public();
        let addr = pk.to_address(Network::Testnet).unwrap();
        let script_pubkey = addr.script_pubkey();

        let prevout = TxOut {
            value: 10_000,
            script_pubkey: script_pubkey.clone(),
        };
        let outpoint = OutPoint {
            txid: [2; 32],
            vout: 0,
        };
        let mut tx = Transaction::new(2, 0);
        tx.add_input(TxIn {
            previous_output: outpoint,
            script_sig: vec![],
            sequence: 0xfffffffe,
            witness: vec![],
        });
        tx.add_output(TxOut {
            value: 9_500,
            script_pubkey: vec![0x6a],
        });

        tx.sign_all_inputs(&[prevout.clone()], &[sk]).unwrap();

        let sighash = tx.taproot_sighash(0, &[prevout], 0);
        let sig = k256::schnorr::Signature::try_from(&tx.inputs[0].witness[0][..]).unwrap();
        pk.verify_prehash(&sighash, &sig).unwrap();
    }
}
