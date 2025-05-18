// https://github.com/bitcoin/bips/blob/master/bip-0350.mediawiki#bech32m
use std::{fmt, str::FromStr};

const BECH32M_CONST: u32 = 0x2bc830a3;
const BECH32M_ALPHABET: &[u8; 32] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";

fn bech32m_polymod(values: &[u8]) -> u32 {
    const GEN: [u32; 5] = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];
    let mut chk: u32 = 1;

    for &v in values {
        let b = chk >> 25;
        chk = (chk & 0x1ffffff) << 5 ^ (v as u32);
        for i in 0..5 {
            if ((b >> i) & 1) == 1 {
                chk ^= GEN[i];
            }
        }
    }
    chk
}

fn bech32m_hrp_expand(s: &str) -> Vec<u8> {
    let mut result = Vec::new();
    result.extend(s.bytes().map(|b| b >> 5));
    result.push(0);
    result.extend(s.bytes().map(|b| b & 0x1f));
    result
}

fn bech32m_verify_checksum(hrp: &str, data: &[u8], checksum: &[u8; 6]) -> bool {
    let mut expanded = bech32m_hrp_expand(hrp);
    expanded.extend_from_slice(data);
    expanded.extend_from_slice(checksum);
    bech32m_polymod(&expanded) == BECH32M_CONST
}

fn split_by_5bits(polymod: u32) -> [u8; 6] {
    let mut result = [0; 6];

    for i in 0..6 {
        result[i] = ((polymod >> (5 * (5 - i))) & 0x1F) as u8;
    }
    result
}

fn bech32m_create_checksum(hrp: &str, data: &[u8]) -> [u8; 6] {
    let mut values = bech32m_hrp_expand(hrp);
    values.extend_from_slice(data);
    values.extend_from_slice(&[0; 6]);
    let polymod = bech32m_polymod(&values) ^ BECH32M_CONST;
    split_by_5bits(polymod)
}

fn base32_encode_variant(data: &[u8]) -> Option<String> {
    data.iter()
        .map(|b| Some(*(BECH32M_ALPHABET.get(*b as usize)?) as char))
        .collect()
}

fn base32_decode_variant(s: &str) -> Option<Vec<u8>> {
    s.chars()
        .map(|c| c.to_ascii_lowercase())
        .map(|c| {
            let index = BECH32M_ALPHABET.iter().position(|&x| x as char == c)?;
            Some(index as u8)
        })
        .collect()
}

fn to_8bits(values: &[u8]) -> Vec<u8> {
    let mut result = Vec::new();
    let mut buffer: u32 = 0;
    let mut bits_left: u8 = 0;

    if let Some((last, values)) = values.split_last() {
        for v in values.iter() {
            buffer |= (*v as u32) << 27;
            bits_left += 5;
            while bits_left >= 8 {
                result.push((buffer >> 24) as u8);
                buffer <<= 8;
                bits_left -= 8;
            }
        }
        // If the total number of bits is not a multiple of 8, any trailing bits are simply dropped.
        buffer |= (*last as u32) << (27 - bits_left);
        result.push((buffer >> 24) as u8);
    }

    result
}

fn to_5bits(values: &[u8], mut result: Vec<u8>) -> Vec<u8> {
    let mut buffer: u32 = 0;
    let mut bits_left: u8 = 0;

    for v in values.iter() {
        buffer |= (*v as u32) << (24 - bits_left);
        bits_left += 8;
        while bits_left >= 5 {
            result.push(((buffer >> 27) & 0x1F) as u8);
            buffer <<= 5;
            bits_left -= 5;
        }
    }

    if bits_left > 0 {
        result.push(((buffer >> 27) & 0x1F) as u8);
    }

    result
}

#[derive(Debug)]
pub struct Bech32m {
    hrp: String,
    data: Vec<u8>,
}

impl Bech32m {
    pub fn new_witver1(hrp: &str, data: &[u8]) -> Option<Self> {
        let hrp = hrp.to_ascii_lowercase();
        if !hrp.chars().all(|c| (33..126).contains(&(c as u8))) {
            return None;
        }
        let mut data = to_5bits(data, vec![0x01]);
        let checksum = bech32m_create_checksum(&hrp, &data);
        data.extend_from_slice(&checksum);
        Some(Self { hrp, data })
    }

    pub fn data(self) -> Vec<u8> {
        // SAFETY: Once this structure is constructed, data will always be larger than 6.
        let (data, _) = self.data.split_last_chunk::<6>().unwrap();
        to_8bits(data)
    }

    pub fn hrp(&self) -> &str {
        &self.hrp
    }
}

impl fmt::Display for Bech32m {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "{}1{}",
            self.hrp,
            base32_encode_variant(&self.data).ok_or(fmt::Error)?
        )
    }
}

#[derive(thiserror::Error, Debug)]
pub enum ParseError {
    #[error("could not find separator")]
    Separator,
    #[error("invalid characters")]
    Decode,
    #[error("invalid length")]
    Length,
    #[error("invalid checksum")]
    Verify,
    #[error("invalid hrp")]
    Hrp,
}

impl FromStr for Bech32m {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (hrp, data) = s.rsplit_once('1').ok_or(ParseError::Separator)?;
        let hrp = hrp.to_ascii_lowercase();
        if !hrp.chars().all(|c| (33..126).contains(&(c as u8))) {
            return Err(ParseError::Hrp);
        }
        let data = base32_decode_variant(data).ok_or(ParseError::Decode)?;
        let (_data, checksum) = data.split_last_chunk().ok_or(ParseError::Length)?;
        if !bech32m_verify_checksum(&hrp, _data, checksum) {
            return Err(ParseError::Verify);
        }
        Ok(Self { hrp, data })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[rstest::rstest]
    fn test_bech32m() {
        let hrp = "bc";
        let data = [1, 2, 3, 4, 5];

        let checksum = bech32m_create_checksum(hrp, &data);

        assert!(bech32m_verify_checksum(hrp, &data, &checksum));
    }

    #[rstest::rstest]
    fn test_bit_converter() {
        assert_eq!(to_8bits(&to_5bits(&vec![0xFF], vec![])), vec![0xFF]);
    }

    #[rstest::rstest]
    #[case("A1LQFN3A")]
    #[case("a1lqfn3a")]
    #[case("abcdef1l7aum6echk45nj3s0wdvt2fg8x9yrzpqzd3ryx")]
    #[case(
        "an83characterlonghumanreadablepartthatcontainsthetheexcludedcharactersbioandnumber11sg7hg6"
    )]
    #[case(
        "11llllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllludsr8"
    )]
    #[case("split1checkupstagehandshakeupstreamerranterredcaperredlc445v")]
    #[case("?1v759aa")]
    #[case("a1lusyc9lx")]
    #[case("abcdef1l7aum6echk45nj3s0wdvt2fg8x9yrzpqzd3ryx")]
    fn test_valid_value(#[case] value: &str) {
        let bech32m: Bech32m = value.parse().unwrap();

        assert_eq!(bech32m.to_string(), value.to_ascii_lowercase());
    }
}
