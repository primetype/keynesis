#[cfg(target_os = "macos")]
mod macos;

use crate::{asn1::ASN1Reader, base64::BASE64, buffer::BufRead};
use anyhow::{ensure, Context as _, Result};
use base64::Engine as _;
use cryptoxide::{digest::Digest as _, sha2::Sha256};
use eccoxide::curve::{
    sec2::p256r1::{self, FieldElement, Point, PointAffine, Scalar},
    Sign,
};
use std::{fmt, str::FromStr};

#[cfg(target_os = "macos")]
pub use self::macos::P256r1PrivateKey;

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct P256r1PublicKey([u8; 65]);

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct P256Signature([u8; 64]);

impl P256Signature {
    pub fn try_from_bytes(bytes: impl AsRef<[u8]>) -> Result<Self> {
        Ok(P256Signature(bytes.as_ref().try_into()?))
    }

    #[cfg(test)]
    pub(crate) fn to_asn1(self) -> anyhow::Result<Vec<u8>> {
        let r = &self.0[0..32];
        let s = &self.0[32..64];

        let mut len = 68;

        let r = if (r[0] & 0b1000_0000u8) == 0b1000_0000u8 {
            // most significant bit is set, so value is negative
            len += 1;
            let mut r_ = vec![0];
            r_.extend_from_slice(r);
            r_
        } else {
            r.to_vec()
        };

        let s = if (s[0] & 0b1000_0000u8) == 0b1000_0000u8 {
            // most significant bit is set, so value is negative
            len += 1;
            let mut s_ = vec![0];
            s_.extend_from_slice(s);
            s_
        } else {
            s.to_vec()
        };

        let mut writer = crate::asn1::ASN1Writer::new();
        writer.sequence(len)?;

        writer.integer(r.as_slice())?;
        writer.integer(s.as_slice())?;

        Ok(writer.finalize())
    }

    pub(crate) fn try_from_asn1(bytes: impl AsRef<[u8]>) -> anyhow::Result<Self> {
        let reader = ASN1Reader::new(bytes.as_ref());
        let reader = reader
            .sequence()
            .context("ASN.1 encoded signature is expected to start with a sequence")?;
        let (reader, r) = reader
            .integer()
            .context("Failed to decode the first integer of the ASN.1 encoded signature")?;
        let (reader, s) = reader
            .integer()
            .context("Failed to decode the second integer of the ASN.1 encoded signature")?;

        ensure!(
            r.len() <= 32 || (r.len() == 33 && r[0] == 0),
            "r: Expecting length of 32 or 33 ({len}) and first bytes to be 0x00 (0x{byte:02x})",
            len = r.len(),
            byte = r[0]
        );
        ensure!(
            s.len() <= 32 || (s.len() == 33 && s[0] == 0),
            "s: Expecting length of 32 or 33 ({len}) and first bytes to be 0x00 (0x{byte:02x})",
            len = s.len(),
            byte = s[0]
        );
        ensure!(reader.is_empty());

        let r = if r.len() == 33 { &r[1..] } else { r };
        let s = if s.len() == 33 { &s[1..] } else { s };
        let r_i = if r.len() < 32 { 32 - r.len() } else { 0 };
        let s_i = if s.len() < 32 { 32 - s.len() } else { 0 };
        let mut signature = [0; 64];
        signature[r_i..32].copy_from_slice(r);
        signature[32 + s_i..].copy_from_slice(s);

        Ok(P256Signature(signature))
    }
}

fn point_to_bytes(point: p256r1::Point) -> [u8; 65] {
    let point = point.to_affine().unwrap();
    let (x, y) = point.to_coordinate();

    let mut pk = [0; 65];
    pk[0] = 0x04;
    pk[1..33].copy_from_slice(&x.to_bytes());
    pk[33..].copy_from_slice(&y.to_bytes());

    pk
}

#[allow(unused)]
fn point_to_bytes_compressed(point: p256r1::Point) -> [u8; 33] {
    let pk = point.to_affine().unwrap();
    let (f, s) = pk.compress();
    let prefix = match s {
        Sign::Positive => 0x02u8,
        Sign::Negative => 0x03u8,
    };

    let mut pk = [0u8; 33];
    pk[0] = prefix;
    pk[1..].copy_from_slice(&f.to_bytes());

    pk
}

impl P256r1PublicKey {
    pub fn to_point(&self) -> anyhow::Result<p256r1::Point> {
        let prefix = self.0[0];

        let x = FieldElement::from_slice(&self.0[1..33])
            .ok_or(anyhow::anyhow!("Invalid Field element for `X`"))?;

        let pa = match prefix {
            0x04u8 => {
                let y = FieldElement::from_slice(&self.0[33..65])
                    .ok_or(anyhow::anyhow!("Invalid uncompressed Field Element y"))?;
                PointAffine::from_coordinate(&x, &y)
                    .ok_or(anyhow::anyhow!("Invalid uncompressed Point"))?
            }
            0x02u8 => PointAffine::decompress(&x, Sign::Positive)
                .ok_or(anyhow::anyhow!("Invalid positive compressed point"))?,
            0x03u8 => PointAffine::decompress(&x, Sign::Negative)
                .ok_or(anyhow::anyhow!("Invalid negative compressed point"))?,
            _ => anyhow::bail!("Unknown prefix 0x{prefix:02x}"),
        };

        Ok(Point::from(pa))
    }

    pub fn to_bytes(&self) -> &[u8] {
        &self.0
    }

    pub(crate) fn from_bytes(public_key: &[u8]) -> anyhow::Result<Self> {
        let prefix = public_key[0];

        let x = FieldElement::from_slice(&public_key[1..33])
            .ok_or(anyhow::anyhow!("Invalid Field element for `X`"))?;

        let pa = match prefix {
            0x04u8 => {
                let y = FieldElement::from_slice(&public_key[33..65])
                    .ok_or(anyhow::anyhow!("Invalid uncompressed Field Element y"))?;
                PointAffine::from_coordinate(&x, &y)
                    .ok_or(anyhow::anyhow!("Invalid uncompressed Point"))?
            }
            0x02u8 => PointAffine::decompress(&x, Sign::Positive)
                .ok_or(anyhow::anyhow!("Invalid positive compressed point"))?,
            0x03u8 => PointAffine::decompress(&x, Sign::Negative)
                .ok_or(anyhow::anyhow!("Invalid negative compressed point"))?,
            _ => anyhow::bail!("Unknown prefix 0x{prefix:02x}"),
        };

        let point = Point::from(pa);

        Ok(Self(point_to_bytes(point)))
    }

    pub fn verify(&self, signature: P256Signature, message: &[u8]) -> bool {
        let point = self
            .to_point()
            .expect("The P256 Key should have been verified already");
        let e = input_to_scalar(message);

        let r = Scalar::from_slice(&signature.0[0..32]);
        let s = Scalar::from_slice(&signature.0[32..64]);
        let r = match r {
            None => return false,
            Some(v) => {
                if v == Scalar::zero() {
                    return false;
                }
                v
            }
        };
        let s = match s {
            None => return false,
            Some(v) => {
                if v == Scalar::zero() {
                    return false;
                }
                v
            }
        };

        let sinv = s.inverse();

        let u1 = &e * &sinv;
        let u2 = &r * sinv;
        let rp = &u1 * &Point::generator() + &u2 * &point;

        match rp.to_affine() {
            None => false,
            Some(rpa) => {
                let (xr, _) = rpa.to_coordinate();
                // XXX println!("{:?} {:?}", xr.to_bytes(), r.to_bytes());
                xr.to_bytes() == r.to_bytes()
            }
        }
    }
}

impl super::PublicKey for P256r1PublicKey {
    const SIZE: usize = 65;

    fn read(input: &mut BufRead) -> anyhow::Result<Self> {
        let mut buf = [0; Self::SIZE];
        if input.remaining() >= Self::SIZE {
            input.read(&mut buf);
            Self::from_bytes(&buf)
        } else {
            anyhow::bail!("Not enough bytes to read a public key")
        }
    }
}

impl AsRef<[u8]> for P256r1PublicKey {
    fn as_ref(&self) -> &[u8] {
        self.to_bytes()
    }
}

impl TryFrom<&[u8]> for P256r1PublicKey {
    type Error = anyhow::Error;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        Self::from_bytes(bytes)
    }
}

impl AsRef<[u8]> for P256Signature {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Display for P256r1PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        BASE64.encode(self.0).fmt(f)
    }
}

impl fmt::Display for P256Signature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        BASE64.encode(self.0).fmt(f)
    }
}

impl FromStr for P256r1PublicKey {
    type Err = anyhow::Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let bytes = BASE64
            .decode(s)
            .context("Failed to decode BASE64 public key")?;
        Self::from_bytes(&bytes)
    }
}

impl fmt::Debug for P256r1PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        hex::encode(self.0).fmt(f)
    }
}

fn input_to_scalar(message: &[u8]) -> Scalar {
    let mut hash = [0u8; 32];
    let mut context = Sha256::new();
    context.input(message);
    context.result(&mut hash);

    Scalar::from_slice(&hash).unwrap()
}

impl FromStr for P256Signature {
    type Err = anyhow::Error;
    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        let bytes = BASE64.decode(s)?;
        let sig = P256Signature::try_from_asn1(bytes)?;
        Ok(sig)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::base64::BASE64;
    use base64::Engine;

    /// public key and signature generated on iPhone 12 Pro, IOs16, secure enclave using `.ecdsaSignatureMessageX962SHA256`
    const PKSTR: &str =
        "BNe8CwkfEsB2m5peB0PQINtep4xMuJvH6zFbkkBgBlwpJ8pQSGFe00s6Of3m7lOCbGEJuo7W8cYEK_kgQx8dPUs";
    const SIGSTR: &str = "MEUCIQCdH-6x6xmFGJ-Py9Qn4a_JGGMMCri6QosXDVYygka_LQIgUTbBhT_kuuzJmBZa9uXofcwIc7WVWDcJBnx9cP07G0o";

    #[test]
    fn pk_from_to_bytes() {
        let pkbytes = BASE64.decode(PKSTR).unwrap();
        let pk = P256r1PublicKey::from_bytes(&pkbytes).unwrap();
        assert_eq!(pk.to_bytes(), pkbytes)
    }

    #[test]
    fn signature_decode_31() {
        const SIG: &str = "3044022100e84c694ba8e5864f152db261091dac062a20358100234ad1c98643b4fee02ff0021f7fdb70746a4c610a78831472493cfc4643597741929c43703dabaa78c3ad26";
        //      R                  00e84c694ba8e5864f152db261091dac062a20358100234ad1c98643b4fee02ff0
        //      S                                                                                        7fdb70746a4c610a78831472493cfc4643597741929c43703dabaa78c3ad26
        let bytes = hex::decode(SIG).unwrap();
        let _sig = P256Signature::try_from_asn1(bytes).unwrap();
    }

    #[test]
    fn signature_asn1_encode_decode() {
        let sigbytes = BASE64.decode(SIGSTR).unwrap();

        let sig = P256Signature::try_from_asn1(&sigbytes).unwrap();
        let encoded = sig.to_asn1().unwrap();

        assert_eq!(sigbytes, encoded)
    }

    #[test]
    fn check_sig_verification() {
        const MSG: &str = "Hello World!";
        let pkbytes = BASE64.decode(PKSTR).unwrap();
        let sigbytes = BASE64.decode(SIGSTR).unwrap();
        let pk = P256r1PublicKey::from_bytes(&pkbytes).unwrap();
        let signature = P256Signature::try_from_asn1(sigbytes).unwrap();

        assert!(pk.verify(signature, MSG.as_bytes()));
    }
}
