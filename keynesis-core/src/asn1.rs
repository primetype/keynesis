use anyhow::{ensure, Context, Result};

#[cfg(test)]
#[derive(Debug, Clone, Default)]
pub struct ASN1Writer(Vec<u8>);

#[derive(Debug, Clone, Copy)]
pub struct ASN1Reader<'a>(&'a [u8]);

#[cfg(test)]
impl ASN1Writer {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn sequence(&mut self, len: u8) -> Result<()> {
        self.0.push(0x30u8);
        self.0.push(len);

        Ok(())
    }

    pub fn integer(&mut self, integer: &[u8]) -> Result<()> {
        ensure!(integer.len() < (u8::MAX as usize));
        self.0.push(0x02u8);
        self.0.push(integer.len() as u8);
        self.0.extend_from_slice(integer);

        Ok(())
    }

    pub fn finalize(self) -> Vec<u8> {
        self.0
    }
}

impl<'a> ASN1Reader<'a> {
    #[inline]
    pub const fn new(bytes: &'a [u8]) -> Self {
        Self(bytes)
    }

    fn not_empty(self) -> Result<Self> {
        ensure!(!self.0.is_empty(), "No more data to read");
        Ok(self)
    }

    #[inline(always)]
    pub fn is_empty(self) -> bool {
        self.0.is_empty()
    }

    pub fn sequence(self) -> Result<Self> {
        self.not_empty().context("Expecting to read a Sequence")?;
        ensure!(self.0[0] == 0x30, "Expecting a sequence code");
        ensure!(self.0.len() >= 2, "Expecting to have a code and a length");
        let remaining_length = self.0[1] as usize;

        let remaining = &self.0[2..];
        ensure!(
            remaining.len() >= remaining_length,
            "The sequence is expected to contains {remaining_length}"
        );

        Ok(Self(remaining))
    }

    pub fn integer(self) -> Result<(Self, &'a [u8])> {
        self.not_empty()
            .context("Expecting to read an integer code")?;
        ensure!(self.0[0] == 0x02, "Expecting to read the integer code");
        ensure!(self.0.len() >= 2, "Expecting to read a code and a length");
        let integer_length = self.0[1] as usize;
        let integer = &self.0[2..(2 + integer_length)];
        let remaining = &self.0[(2 + integer_length)..];

        Ok((Self(remaining), integer))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_signature() {
        let a = &[
            48, 69, 2, 32, 17, 228, 99, 34, 120, 37, 69, 116, 229, 142, 174, 166, 66, 182, 115,
            165, 236, 153, 178, 59, 233, 223, 255, 125, 25, 93, 206, 45, 220, 10, 53, 97, 2, 33, 0,
            241, 1, 246, 203, 223, 101, 49, 70, 12, 167, 176, 90, 118, 217, 115, 61, 23, 200, 214,
            81, 204, 74, 219, 44, 58, 232, 125, 187, 1, 202, 203, 185,
        ];

        let mut writer = ASN1Writer::new();
        writer.sequence(69).unwrap();
        writer
            .integer(&[
                17, 228, 99, 34, 120, 37, 69, 116, 229, 142, 174, 166, 66, 182, 115, 165, 236, 153,
                178, 59, 233, 223, 255, 125, 25, 93, 206, 45, 220, 10, 53, 97,
            ])
            .unwrap();
        writer
            .integer(&[
                0, 241, 1, 246, 203, 223, 101, 49, 70, 12, 167, 176, 90, 118, 217, 115, 61, 23,
                200, 214, 81, 204, 74, 219, 44, 58, 232, 125, 187, 1, 202, 203, 185,
            ])
            .unwrap();

        assert_eq!(a, writer.0.as_slice());
    }

    #[test]
    fn decode_signature() {
        let a = &[
            48, 69, 2, 32, 17, 228, 99, 34, 120, 37, 69, 116, 229, 142, 174, 166, 66, 182, 115,
            165, 236, 153, 178, 59, 233, 223, 255, 125, 25, 93, 206, 45, 220, 10, 53, 97, 2, 33, 0,
            241, 1, 246, 203, 223, 101, 49, 70, 12, 167, 176, 90, 118, 217, 115, 61, 23, 200, 214,
            81, 204, 74, 219, 44, 58, 232, 125, 187, 1, 202, 203, 185,
        ];

        let reader = ASN1Reader(a);
        let reader = reader.sequence().unwrap();
        let (reader, r) = reader.integer().unwrap();
        let (reader, s) = reader.integer().unwrap();

        assert!(reader.is_empty());

        assert_eq!(
            r,
            [
                17, 228, 99, 34, 120, 37, 69, 116, 229, 142, 174, 166, 66, 182, 115, 165, 236, 153,
                178, 59, 233, 223, 255, 125, 25, 93, 206, 45, 220, 10, 53, 97
            ]
        );
        assert_eq!(
            s,
            [
                0, 241, 1, 246, 203, 223, 101, 49, 70, 12, 167, 176, 90, 118, 217, 115, 61, 23,
                200, 214, 81, 204, 74, 219, 44, 58, 232, 125, 187, 1, 202, 203, 185
            ]
        );
    }
}
