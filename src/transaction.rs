use sha2::{Digest, Sha256};

use crate::key;

#[derive(thiserror::Error, Debug)]
pub enum SignError {
    #[error("failed to sign")]
    FailedSign,
    #[error("incompatible prevout or secret_keys")]
    Length,
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
        for i in 0..self.inputs.len() {
            let sighash = self.taproot_sighash(i, prevouts, 0);
            let sig = secret_keys[i]
                .tweak()
                .and_then(|sk| sk.sign(&sighash))
                .ok_or(SignError::FailedSign)?;
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
        use crate::address::taproot;
        use k256::elliptic_curve::{ops::Reduce, point::AffineCoordinates, sec1::ToEncodedPoint};
        use k256::{AffinePoint, ProjectivePoint, Scalar, U256};

        #[derive(Clone)]
        enum Tree<'a> {
            Leaf { script: &'a str, version: u8 },
            Node(Box<Tree<'a>>, Box<Tree<'a>>),
        }

        #[derive(Clone)]
        struct Vector<'a> {
            internal_pubkey: &'a str,
            tree: Option<Tree<'a>>,
            leaf_hashes: &'a [&'a str],
            merkle_root: Option<&'a str>,
            tweak: &'a str,
            tweaked_pubkey: &'a str,
            script_pubkey: &'a str,
            address: &'a str,
            control_blocks: &'a [&'a str],
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

        fn leaf_hash(script_hex: &str, version: u8) -> [u8; 32] {
            let script = hex::decode(script_hex).unwrap();
            let mut enc = Vec::new();
            enc.push(version);
            write_varint(script.len() as u64, &mut enc);
            enc.extend_from_slice(&script);
            key::tagged_hash("TapLeaf", &enc)
        }

        fn branch_hash(a: [u8; 32], b: [u8; 32]) -> [u8; 32] {
            let (l, r) = if a <= b { (a, b) } else { (b, a) };
            let mut enc = Vec::new();
            enc.extend_from_slice(&l);
            enc.extend_from_slice(&r);
            key::tagged_hash("TapBranch", &enc)
        }

        #[derive(Clone)]
        struct LeafInfo {
            hash: [u8; 32],
            version: u8,
            path: Vec<[u8; 32]>,
        }

        fn traverse(tree: &Tree) -> (Vec<LeafInfo>, [u8; 32]) {
            match tree {
                Tree::Leaf { script, version } => {
                    let h = leaf_hash(script, *version);
                    (
                        vec![LeafInfo {
                            hash: h,
                            version: *version,
                            path: Vec::new(),
                        }],
                        h,
                    )
                }
                Tree::Node(l, r) => {
                    let (mut left, lroot) = traverse(l);
                    let (mut right, rroot) = traverse(r);
                    for leaf in &mut left {
                        leaf.path.push(rroot);
                    }
                    for leaf in &mut right {
                        leaf.path.push(lroot);
                    }
                    let mut leaves = left;
                    leaves.extend(right);
                    let root = branch_hash(lroot, rroot);
                    (leaves, root)
                }
            }
        }

        fn tweak_key(
            pk: &k256::schnorr::VerifyingKey,
            merkle: Option<[u8; 32]>,
        ) -> ([u8; 32], ProjectivePoint) {
            let mut data = pk.to_bytes().to_vec();
            if let Some(m) = merkle {
                data.extend_from_slice(&m);
            }
            let tweak = key::tagged_hash("TapTweak", &data);
            let t = U256::from_be_slice(&tweak);
            let t: Scalar = Reduce::reduce(t);
            let p = ProjectivePoint::from(*pk.as_affine()) + AffinePoint::GENERATOR * t;
            (tweak, p)
        }

        fn control_block(
            version: u8,
            int_pk: &[u8; 32],
            parity: bool,
            path: &[[u8; 32]],
        ) -> Vec<u8> {
            let mut v = Vec::new();
            let byte = (version & 0xfe) | (parity as u8);
            v.push(byte);
            v.extend_from_slice(int_pk);
            for p in path {
                v.extend_from_slice(p);
            }
            v
        }

        // Test vectors
        let vectors = [
            Vector {
                internal_pubkey: "d6889cb081036e0faefa3a35157ad71086b123b2b144b649798b494c300a961d",
                tree: None,
                leaf_hashes: &[],
                merkle_root: None,
                tweak: "b86e7be8f39bab32a6f2c0443abbc210f0edac0e2c53d501b36b64437d9c6c70",
                tweaked_pubkey: "53a1f6e454df1aa2776a2814a721372d6258050de330b3c6d10ee8f4e0dda343",
                script_pubkey: "512053a1f6e454df1aa2776a2814a721372d6258050de330b3c6d10ee8f4e0dda343",
                address: "bc1p2wsldez5mud2yam29q22wgfh9439spgduvct83k3pm50fcxa5dps59h4z5",
                control_blocks: &[],
            },
            Vector {
                internal_pubkey: "187791b6f712a8ea41c8ecdd0ee77fab3e85263b37e1ec18a3651926b3a6cf27",
                tree: Some(Tree::Leaf {
                    script: "20d85a959b0290bf19bb89ed43c916be835475d013da4b362117393e25a48229b8ac",
                    version: 192,
                }),
                leaf_hashes: &["5b75adecf53548f3ec6ad7d78383bf84cc57b55a3127c72b9a2481752dd88b21"],
                merkle_root: Some(
                    "5b75adecf53548f3ec6ad7d78383bf84cc57b55a3127c72b9a2481752dd88b21",
                ),
                tweak: "cbd8679ba636c1110ea247542cfbd964131a6be84f873f7f3b62a777528ed001",
                tweaked_pubkey: "147c9c57132f6e7ecddba9800bb0c4449251c92a1e60371ee77557b6620f3ea3",
                script_pubkey: "5120147c9c57132f6e7ecddba9800bb0c4449251c92a1e60371ee77557b6620f3ea3",
                address: "bc1pz37fc4cn9ah8anwm4xqqhvxygjf9rjf2resrw8h8w4tmvcs0863sa2e586",
                control_blocks: &[
                    "c1187791b6f712a8ea41c8ecdd0ee77fab3e85263b37e1ec18a3651926b3a6cf27",
                ],
            },
            Vector {
                internal_pubkey: "93478e9488f956df2396be2ce6c5cced75f900dfa18e7dabd2428aae78451820",
                tree: Some(Tree::Leaf {
                    script: "20b617298552a72ade070667e86ca63b8f5789a9fe8731ef91202a91c9f3459007ac",
                    version: 192,
                }),
                leaf_hashes: &["c525714a7f49c28aedbbba78c005931a81c234b2f6c99a73e4d06082adc8bf2b"],
                merkle_root: Some(
                    "c525714a7f49c28aedbbba78c005931a81c234b2f6c99a73e4d06082adc8bf2b",
                ),
                tweak: "6af9e28dbf9d6aaf027696e2598a5b3d056f5fd2355a7fd5a37a0e5008132d30",
                tweaked_pubkey: "e4d810fd50586274face62b8a807eb9719cef49c04177cc6b76a9a4251d5450e",
                script_pubkey: "5120e4d810fd50586274face62b8a807eb9719cef49c04177cc6b76a9a4251d5450e",
                address: "bc1punvppl2stp38f7kwv2u2spltjuvuaayuqsthe34hd2dyy5w4g58qqfuag5",
                control_blocks: &[
                    "c093478e9488f956df2396be2ce6c5cced75f900dfa18e7dabd2428aae78451820",
                ],
            },
            Vector {
                internal_pubkey: "ee4fe085983462a184015d1f782d6a5f8b9c2b60130aff050ce221ecf3786592",
                tree: Some(Tree::Node(
                    Box::new(Tree::Leaf {
                        script: "20387671353e273264c495656e27e39ba899ea8fee3bb69fb2a680e22093447d48ac",
                        version: 192,
                    }),
                    Box::new(Tree::Leaf {
                        script: "06424950333431",
                        version: 250,
                    }),
                )),
                leaf_hashes: &[
                    "8ad69ec7cf41c2a4001fd1f738bf1e505ce2277acdcaa63fe4765192497f47a7",
                    "f224a923cd0021ab202ab139cc56802ddb92dcfc172b9212261a539df79a112a",
                ],
                merkle_root: Some(
                    "6c2dc106ab816b73f9d07e3cd1ef2c8c1256f519748e0813e4edd2405d277bef",
                ),
                tweak: "9e0517edc8259bb3359255400b23ca9507f2a91cd1e4250ba068b4eafceba4a9",
                tweaked_pubkey: "712447206d7a5238acc7ff53fbe94a3b64539ad291c7cdbc490b7577e4b17df5",
                script_pubkey: "5120712447206d7a5238acc7ff53fbe94a3b64539ad291c7cdbc490b7577e4b17df5",
                address: "bc1pwyjywgrd0ffr3tx8laflh6228dj98xkjj8rum0zfpd6h0e930h6saqxrrm",
                control_blocks: &[
                    "c0ee4fe085983462a184015d1f782d6a5f8b9c2b60130aff050ce221ecf3786592f224a923cd0021ab202ab139cc56802ddb92dcfc172b9212261a539df79a112a",
                    "faee4fe085983462a184015d1f782d6a5f8b9c2b60130aff050ce221ecf37865928ad69ec7cf41c2a4001fd1f738bf1e505ce2277acdcaa63fe4765192497f47a7",
                ],
            },
            Vector {
                internal_pubkey: "f9f400803e683727b14f463836e1e78e1c64417638aa066919291a225f0e8dd8",
                tree: Some(Tree::Node(
                    Box::new(Tree::Leaf {
                        script: "2044b178d64c32c4a05cc4f4d1407268f764c940d20ce97abfd44db5c3592b72fdac",
                        version: 192,
                    }),
                    Box::new(Tree::Leaf {
                        script: "07546170726f6f74",
                        version: 192,
                    }),
                )),
                leaf_hashes: &[
                    "64512fecdb5afa04f98839b50e6f0cb7b1e539bf6f205f67934083cdcc3c8d89",
                    "2cb2b90daa543b544161530c925f285b06196940d6085ca9474d41dc3822c5cb",
                ],
                merkle_root: Some(
                    "ab179431c28d3b68fb798957faf5497d69c883c6fb1e1cd9f81483d87bac90cc",
                ),
                tweak: "639f0281b7ac49e742cd25b7f188657626da1ad169209078e2761cefd91fd65e",
                tweaked_pubkey: "77e30a5522dd9f894c3f8b8bd4c4b2cf82ca7da8a3ea6a239655c39c050ab220",
                script_pubkey: "512077e30a5522dd9f894c3f8b8bd4c4b2cf82ca7da8a3ea6a239655c39c050ab220",
                address: "bc1pwl3s54fzmk0cjnpl3w9af39je7pv5ldg504x5guk2hpecpg2kgsqaqstjq",
                control_blocks: &[
                    "c1f9f400803e683727b14f463836e1e78e1c64417638aa066919291a225f0e8dd82cb2b90daa543b544161530c925f285b06196940d6085ca9474d41dc3822c5cb",
                    "c1f9f400803e683727b14f463836e1e78e1c64417638aa066919291a225f0e8dd864512fecdb5afa04f98839b50e6f0cb7b1e539bf6f205f67934083cdcc3c8d89",
                ],
            },
            Vector {
                internal_pubkey: "e0dfe2300b0dd746a3f8674dfd4525623639042569d829c7f0eed9602d263e6f",
                tree: Some(Tree::Node(
                    Box::new(Tree::Leaf {
                        script: "2072ea6adcf1d371dea8fba1035a09f3d24ed5a059799bae114084130ee5898e69ac",
                        version: 192,
                    }),
                    Box::new(Tree::Node(
                        Box::new(Tree::Leaf {
                            script: "202352d137f2f3ab38d1eaa976758873377fa5ebb817372c71e2c542313d4abda8ac",
                            version: 192,
                        }),
                        Box::new(Tree::Leaf {
                            script: "207337c0dd4253cb86f2c43a2351aadd82cccb12a172cd120452b9bb8324f2186aac",
                            version: 192,
                        }),
                    )),
                )),
                leaf_hashes: &[
                    "2645a02e0aac1fe69d69755733a9b7621b694bb5b5cde2bbfc94066ed62b9817",
                    "ba982a91d4fc552163cb1c0da03676102d5b7a014304c01f0c77b2b8e888de1c",
                    "9e31407bffa15fefbf5090b149d53959ecdf3f62b1246780238c24501d5ceaf6",
                ],
                merkle_root: Some(
                    "ccbd66c6f7e8fdab47b3a486f59d28262be857f30d4773f2d5ea47f7761ce0e2",
                ),
                tweak: "b57bfa183d28eeb6ad688ddaabb265b4a41fbf68e5fed2c72c74de70d5a786f4",
                tweaked_pubkey: "91b64d5324723a985170e4dc5a0f84c041804f2cd12660fa5dec09fc21783605",
                script_pubkey: "512091b64d5324723a985170e4dc5a0f84c041804f2cd12660fa5dec09fc21783605",
                address: "bc1pjxmy65eywgafs5tsunw95ruycpqcqnev6ynxp7jaasylcgtcxczs6n332e",
                control_blocks: &[
                    "c0e0dfe2300b0dd746a3f8674dfd4525623639042569d829c7f0eed9602d263e6fffe578e9ea769027e4f5a3de40732f75a88a6353a09d767ddeb66accef85e553",
                    "c0e0dfe2300b0dd746a3f8674dfd4525623639042569d829c7f0eed9602d263e6f9e31407bffa15fefbf5090b149d53959ecdf3f62b1246780238c24501d5ceaf62645a02e0aac1fe69d69755733a9b7621b694bb5b5cde2bbfc94066ed62b9817",
                    "c0e0dfe2300b0dd746a3f8674dfd4525623639042569d829c7f0eed9602d263e6fba982a91d4fc552163cb1c0da03676102d5b7a014304c01f0c77b2b8e888de1c2645a02e0aac1fe69d69755733a9b7621b694bb5b5cde2bbfc94066ed62b9817",
                ],
            },
            Vector {
                internal_pubkey: "55adf4e8967fbd2e29f20ac896e60c3b0f1d5b0efa9d34941b5958c7b0a0312d",
                tree: Some(Tree::Node(
                    Box::new(Tree::Leaf {
                        script: "2071981521ad9fc9036687364118fb6ccd2035b96a423c59c5430e98310a11abe2ac",
                        version: 192,
                    }),
                    Box::new(Tree::Node(
                        Box::new(Tree::Leaf {
                            script: "20d5094d2dbe9b76e2c245a2b89b6006888952e2faa6a149ae318d69e520617748ac",
                            version: 192,
                        }),
                        Box::new(Tree::Leaf {
                            script: "20c440b462ad48c7a77f94cd4532d8f2119dcebbd7c9764557e62726419b08ad4cac",
                            version: 192,
                        }),
                    )),
                )),
                leaf_hashes: &[
                    "f154e8e8e17c31d3462d7132589ed29353c6fafdb884c5a6e04ea938834f0d9d",
                    "737ed1fe30bc42b8022d717b44f0d93516617af64a64753b7a06bf16b26cd711",
                    "d7485025fceb78b9ed667db36ed8b8dc7b1f0b307ac167fa516fe4352b9f4ef7",
                ],
                merkle_root: Some(
                    "2f6b2c5397b6d68ca18e09a3f05161668ffe93a988582d55c6f07bd5b3329def",
                ),
                tweak: "6579138e7976dc13b6a92f7bfd5a2fc7684f5ea42419d43368301470f3b74ed9",
                tweaked_pubkey: "75169f4001aa68f15bbed28b218df1d0a62cbbcf1188c6665110c293c907b831",
                script_pubkey: "512075169f4001aa68f15bbed28b218df1d0a62cbbcf1188c6665110c293c907b831",
                address: "bc1pw5tf7sqp4f50zka7629jrr036znzew70zxyvvej3zrpf8jg8hqcssyuewe",
                control_blocks: &[
                    "c155adf4e8967fbd2e29f20ac896e60c3b0f1d5b0efa9d34941b5958c7b0a0312d3cd369a528b326bc9d2133cbd2ac21451acb31681a410434672c8e34fe757e91",
                    "c155adf4e8967fbd2e29f20ac896e60c3b0f1d5b0efa9d34941b5958c7b0a0312dd7485025fceb78b9ed667db36ed8b8dc7b1f0b307ac167fa516fe4352b9f4ef7f154e8e8e17c31d3462d7132589ed29353c6fafdb884c5a6e04ea938834f0d9d",
                    "c155adf4e8967fbd2e29f20ac896e60c3b0f1d5b0efa9d34941b5958c7b0a0312d737ed1fe30bc42b8022d717b44f0d93516617af64a64753b7a06bf16b26cd711f154e8e8e17c31d3462d7132589ed29353c6fafdb884c5a6e04ea938834f0d9d",
                ],
            },
        ];

        for vec in &vectors {
            let int_pk_bytes = hex::decode(vec.internal_pubkey).unwrap();
            let int_pk = k256::schnorr::VerifyingKey::from_bytes(&int_pk_bytes).unwrap();
            let int_pk_arr: [u8; 32] = int_pk_bytes.clone().try_into().unwrap();

            let (leaves, merkle_root) = match &vec.tree {
                Some(t) => traverse(t),
                None => (Vec::new(), [0u8; 32]),
            };

            if !vec.leaf_hashes.is_empty() {
                let expected: Vec<[u8; 32]> = vec
                    .leaf_hashes
                    .iter()
                    .map(|h| <[u8; 32]>::try_from(hex::decode(h).unwrap().as_slice()).unwrap())
                    .collect();
                let got: Vec<[u8; 32]> = leaves.iter().map(|l| l.hash).collect();
                assert_eq!(got, expected);
            }

            if let Some(root_hex) = vec.merkle_root {
                assert_eq!(hex::encode(merkle_root), root_hex);
            }

            let merkle_opt = if vec.tree.is_some() {
                Some(merkle_root)
            } else {
                None
            };
            let (tweak_bytes, tweak_point) = tweak_key(&int_pk, merkle_opt);
            assert_eq!(hex::encode(tweak_bytes), vec.tweak);
            let ep = tweak_point.to_affine().to_encoded_point(false);
            let tweak_point_x: [u8; 32] = (*ep.x().unwrap()).into();
            assert_eq!(hex::encode(tweak_point_x), vec.tweaked_pubkey);

            // scriptPubKey and address
            let mut spk = Vec::new();
            spk.push(0x51);
            spk.push(0x20);
            spk.extend_from_slice(&tweak_point_x);
            assert_eq!(hex::encode(&spk), vec.script_pubkey);
            let addr = crate::address::bech32m::Bech32m::new_witver1("bc", &tweak_point_x).unwrap();
            assert_eq!(addr.to_string(), vec.address);

            if !vec.control_blocks.is_empty() {
                let parity = tweak_point.to_affine().y_is_odd().into();
                let calc_blocks: Vec<String> = leaves
                    .iter()
                    .map(|leaf| {
                        hex::encode(control_block(leaf.version, &int_pk_arr, parity, &leaf.path))
                    })
                    .collect();
                let expected: Vec<String> =
                    vec.control_blocks.iter().map(|s| s.to_string()).collect();
                assert_eq!(calc_blocks, expected);
            }
        }
    }
}
