pub struct BufRead<'a> {
    bytes: &'a [u8],
}

impl<'a> BufRead<'a> {
    pub fn new(bytes: &'a [u8]) -> Self {
        Self { bytes }
    }

    pub fn read(&mut self, output: &mut [u8]) {
        debug_assert!(self.bytes.len() >= output.len());

        let len = output.len();
        output.copy_from_slice(&self.bytes[..len]);
        self.bytes = &self.bytes[len..];
    }

    pub fn remaining(&self) -> usize {
        self.bytes.len()
    }

    pub fn slice(&self, len: usize) -> &[u8] {
        &self.bytes[..len]
    }

    pub fn advance(&mut self, len: usize) {
        self.bytes = &self.bytes[len..];
    }
}

impl<'a> From<&'a [u8]> for BufRead<'a> {
    fn from(bytes: &'a [u8]) -> Self {
        Self::new(bytes)
    }
}

impl AsRef<[u8]> for BufRead<'_> {
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}
