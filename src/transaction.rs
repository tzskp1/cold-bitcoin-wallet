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
