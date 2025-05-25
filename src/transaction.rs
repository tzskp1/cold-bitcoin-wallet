// https://github.com/bitcoin/bips/blob/master/bip-0341.mediawiki
use crate::key;
use sha2::{Digest, Sha256};
use std::io::Write;

#[derive(thiserror::Error, Debug)]
pub enum SignError {
    #[error("failed to sign")]
    FailedSign,
    #[error("incompatible prevout or secret_keys")]
    Length,
}

#[derive(Clone, Debug)]
pub struct OutPoint {
    pub txid: [u8; 32],
    pub vout: u32,
}

#[derive(Clone, Debug)]
pub struct TxIn {
    pub previous_output: OutPoint,
    pub script_sig: Vec<u8>,
    pub sequence: u32,
    pub witness: Vec<Vec<u8>>, // segwit witness stack
}

#[derive(Clone, Debug)]
pub struct TxOut {
    pub value: u64,
    pub script_pubkey: Vec<u8>,
}

#[derive(Clone, Debug)]
pub struct Transaction {
    pub version: i32,
    pub inputs: Vec<TxIn>,
    pub outputs: Vec<TxOut>,
    pub lock_time: u32,
}

#[allow(dead_code)]
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
        write_varint(self.inputs.len() as u64, &mut buf).unwrap();
        for txin in &self.inputs {
            buf.extend_from_slice(&txin.previous_output.txid);
            buf.extend_from_slice(&txin.previous_output.vout.to_le_bytes());
            write_varbytes(&txin.script_sig, &mut buf).unwrap();
            buf.extend_from_slice(&txin.sequence.to_le_bytes());
        }
        write_varint(self.outputs.len() as u64, &mut buf).unwrap();
        for txout in &self.outputs {
            buf.extend_from_slice(&txout.value.to_le_bytes());
            write_varbytes(&txout.script_pubkey, &mut buf).unwrap();
        }
        if has_witness {
            for txin in &self.inputs {
                write_varint(txin.witness.len() as u64, &mut buf).unwrap();
                for item in &txin.witness {
                    write_varbytes(item, &mut buf).unwrap();
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
        write_varint(self.inputs.len() as u64, &mut buf).unwrap();
        for txin in &self.inputs {
            buf.extend_from_slice(&txin.previous_output.txid);
            buf.extend_from_slice(&txin.previous_output.vout.to_le_bytes());
            write_varbytes(&txin.script_sig, &mut buf).unwrap();
            buf.extend_from_slice(&txin.sequence.to_le_bytes());
        }
        write_varint(self.outputs.len() as u64, &mut buf).unwrap();
        for txout in &self.outputs {
            buf.extend_from_slice(&txout.value.to_le_bytes());
            write_varbytes(&txout.script_pubkey, &mut buf).unwrap();
        }
        buf.extend_from_slice(&self.lock_time.to_le_bytes());

        let hash = Sha256::digest(&buf);
        let hash = Sha256::digest(hash);
        let mut result = [0u8; 32];
        result.copy_from_slice(&hash);
        result
    }

    pub fn taproot_sighash(&self, input_index: usize, prevouts: &[TxOut]) -> [u8; 32] {
        assert_eq!(prevouts.len(), self.inputs.len());

        let mut hasher = Sha256::new();
        for input in &self.inputs {
            hasher.update(input.previous_output.txid);
            hasher.update(input.previous_output.vout.to_le_bytes());
        }
        let hash_prevouts = hasher.finalize();

        let mut hasher = Sha256::new();
        for prev in prevouts {
            hasher.update(prev.value.to_le_bytes());
        }
        let hash_amounts = hasher.finalize();

        let mut hasher = Sha256::new();
        for prev in prevouts {
            write_varbytes(&prev.script_pubkey, &mut hasher).unwrap();
        }
        let hash_scriptpubkeys = hasher.finalize();

        let mut hasher = Sha256::new();
        for input in &self.inputs {
            hasher.update(input.sequence.to_le_bytes());
        }
        let hash_sequences = hasher.finalize();

        let mut hasher = Sha256::new();
        for output in &self.outputs {
            hasher.update(output.value.to_le_bytes());
            write_varbytes(&output.script_pubkey, &mut hasher).unwrap();
        }
        let hash_outputs = hasher.finalize();

        let mut msg = Vec::new();
        msg.push(0); // epoch
        msg.push(0); // hash type
        msg.extend_from_slice(&self.version.to_le_bytes());
        msg.extend_from_slice(&self.lock_time.to_le_bytes());
        msg.extend_from_slice(&hash_prevouts);
        msg.extend_from_slice(&hash_amounts);
        msg.extend_from_slice(&hash_scriptpubkeys);
        msg.extend_from_slice(&hash_sequences);
        msg.extend_from_slice(&hash_outputs);
        msg.push(0); // annex not supported
        msg.extend_from_slice(&(input_index as u32).to_le_bytes());

        key::tagged_hash("TapSighash", &msg)
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
        for (i, secret_key) in secret_keys.iter().enumerate() {
            let sighash = self.taproot_sighash(i, prevouts);
            let sig = secret_key
                .tweak()
                .and_then(|sk| sk.sign(&sighash))
                .ok_or(SignError::FailedSign)?;
            self.inputs[i].witness = vec![sig.to_vec()];
        }
        Ok(())
    }
}

fn write_varint(value: u64, mut buf: impl Write) -> std::io::Result<()> {
    if value < 0xfd {
        buf.write_all(&[value as u8])?;
    } else if value <= 0xffff {
        buf.write_all(&[0xfd])?;
        buf.write_all(&(value as u16).to_le_bytes())?;
    } else if value <= 0xffff_ffff {
        buf.write_all(&[0xfe])?;
        buf.write_all(&(value as u32).to_le_bytes())?;
    } else {
        buf.write_all(&[0xff])?;
        buf.write_all(&value.to_le_bytes())?;
    }
    Ok(())
}

fn write_varbytes(data: &[u8], mut buf: impl Write) -> std::io::Result<()> {
    write_varint(data.len() as u64, &mut buf)?;
    buf.write_all(data)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::key::{Network, SecretKey};
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
        let script_pubkey = addr.script_pubkey().unwrap();

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

        let sighash = tx.taproot_sighash(0, &[prevout]);
        let sig = k256::schnorr::Signature::try_from(&tx.inputs[0].witness[0][..]).unwrap();
        pk.tweak().unwrap().verify_prehash(&sighash, &sig).unwrap();
    }

    #[rstest::rstest]
    fn test_sign_all_inputs_length_error() {
        let sk = SecretKey::new(SigningKey::from_bytes(&[1; 32]).unwrap());
        let pk = sk.to_public();
        let addr = pk.to_address(Network::Testnet).unwrap();
        let script_pubkey = addr.script_pubkey().unwrap();

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
            previous_output: outpoint.clone(),
            script_sig: vec![],
            sequence: 0xfffffffe,
            witness: vec![],
        });
        tx.add_input(TxIn {
            previous_output: outpoint,
            script_sig: vec![],
            sequence: 0xfffffffe,
            witness: vec![],
        });

        // mismatched prevouts length
        let result = tx.sign_all_inputs(&[prevout.clone()], &[sk]);
        assert!(matches!(result, Err(SignError::Length)));

        // mismatched secret_keys length
        let sk2 = SecretKey::new(SigningKey::from_bytes(&[1; 32]).unwrap());
        let result = tx.sign_all_inputs(&[prevout.clone(), prevout], &[sk2]);
        assert!(matches!(result, Err(SignError::Length)));
    }
}
