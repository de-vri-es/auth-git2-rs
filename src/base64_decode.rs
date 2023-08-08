#[derive(Debug, Clone, Eq, PartialEq)]
pub enum Error {
	InvalidBase64Char(u8),
}

impl std::fmt::Display for Error {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		match self {
			Self::InvalidBase64Char(value) => write!(f, "Invalid base64 character: {:?}", char::from_u32(*value as u32).unwrap()),
		}
	}
}

pub fn base64_decode(input: &[u8]) -> Result<Vec<u8>, Error> {
	let input = match input.iter().rposition(|&byte| byte != b'=' && !byte.is_ascii_whitespace()) {
		Some(x) => &input[..=x],
		None => return Ok(Vec::new()),
	};

	let mut output = Vec::with_capacity((input.len() + 3) / 4 * 3);
	let mut decoder = Base64Decoder::new();

	for &byte in input {
		if byte.is_ascii_whitespace() {
			continue;
		}
		if let Some(byte) = decoder.feed(byte)? {
			output.push(byte);
		}
	}

	Ok(output)
}

fn base64_value(byte: u8) -> Result<u8, Error> {
	match byte {
		b'A'..=b'Z' => Ok(byte - b'A'),
		b'a'..=b'z' => Ok(byte - b'a' + 26),
		b'0'..=b'9' => Ok(byte - b'0' + 52),
		b'+' => Ok(62),
		b'/' => Ok(63),
		byte => Err(Error::InvalidBase64Char(byte)),
	}
}

struct Base64Decoder {
	buffer: u16,
	valid_bits: u8,
}

impl Base64Decoder {
	fn new() -> Self {
		Self {
			buffer: 0,
			valid_bits: 0,
		}
	}

	fn feed(&mut self, byte: u8) -> Result<Option<u8>, Error> {
		debug_assert!(self.valid_bits < 8);
		self.buffer |= (base64_value(byte)? as u16) << (10 - self.valid_bits);
		self.valid_bits += 6;
		Ok(self.consume_buffer_front())
	}

	fn consume_buffer_front(&mut self) -> Option<u8> {
		if self.valid_bits >= 8 {
			let value = self.buffer >> 8 & 0xFF;
			self.buffer <<= 8;
			self.valid_bits -= 8;
			Some(value as u8)
		} else {
			None
		}
	}
}

#[cfg(test)]
mod test {
	use super::*;
	use assert2::assert;

	#[test]
	fn test_decode_base64() {
		assert!(let Ok(b"0") = base64_decode(b"MA").as_deref());
		assert!(let Ok(b"0") = base64_decode(b"MA=").as_deref());
		assert!(let Ok(b"0") = base64_decode(b"MA==").as_deref());
		assert!(let Ok(b"aap noot mies") = base64_decode(b"YWFwIG5vb3QgbWllcw").as_deref());
		assert!(let Ok(b"aap noot mies") = base64_decode(b"YWFwIG5vb3QgbWllcw=").as_deref());
		assert!(let Ok(b"aap noot mies") = base64_decode(b"YWFwIG5vb3QgbWllcw==").as_deref());
	}
}
