#[derive(Debug)]
enum Error {
	MultipleWildcards,
	InvalidExclamationMark,
}

#[derive(Debug)]
struct Pattern {
	pattern_data: String,
	pattern: BorrowedPattern,
}

#[derive(Debug)]
enum BorrowedPattern {
	Single(BorrowedSinglePattern),
	List(Vec<BorrowedSinglePattern>),
}

#[derive(Debug)]
struct BorrowedSinglePattern {
	/// If true, the pattern is a negative pattern.
	negative: bool,

	/// The range of the pattern data in the full string.
	///
	/// This includes the leading `!` if present.
	range: std::ops::Range<usize>,

	/// The position of the wildcard within the subrange.
	wildcard: Option<usize>,
}

impl Pattern {
	fn parse(pattern: impl Into<String>) -> Result<Self, Error> {
		let pattern = pattern.into();

		let mut start = 0;
		let mut end = pattern[start..].bytes().position(|byte| byte == b',').unwrap_or(pattern.len());
		let parsed = BorrowedSinglePattern::parse(&pattern[start..end], 0)?;

		// Add + 1 to account for the trailing comma.
		if end + 1 >= pattern.len() {
			return Ok(Self {
				pattern_data: pattern,
				pattern: BorrowedPattern::Single(parsed),
			});
		}

		let mut list = vec![parsed];

		while end + 1 < pattern.len() {
			start = end + 1;
			end = start + pattern[start..].bytes().position(|byte| byte == b',').unwrap_or(pattern[start..].len());
			list.push(BorrowedSinglePattern::parse(&pattern[start..end], start)?);
		}

		Ok(Self {
			pattern_data: pattern,
			pattern: BorrowedPattern::List(list),
		})
	}

	fn matches(&self, input: &str) -> bool {
		match &self.pattern {
			BorrowedPattern::Single(pattern) => !pattern.negative && pattern.matches(&self.pattern_data, input),
			BorrowedPattern::List(patterns) => {
				for pattern in patterns {
					if pattern.matches(&self.pattern_data, input) {
						return pattern.is_positive()
					}
				}
				false
			}
		}
	}
}

impl BorrowedSinglePattern {
	fn parse(input: &str, offset: usize) -> Result<Self, Error> {
		let mut negative = false;
		if input.starts_with('!') {
			negative = true;
		}

		// Check for exclamation marks not at the start of the input.
		let more_exclamation_marks = input.bytes().skip(1).any(|byte| byte == b'!');
		if more_exclamation_marks {
			return Err(Error::InvalidExclamationMark);
		}

		let wildcard = input.bytes().position(|byte| byte == b'*' || byte == b'?');

		// Check for multiple wildcards.
		if let Some(wildcard) = wildcard {
			let more_wildcards = input[wildcard + 1..].bytes().any(|byte| byte == b'*' || byte == b'?');
			if more_wildcards {
				return Err(Error::MultipleWildcards);
			}
		}

		Ok(Self {
			negative,
			range: std::ops::Range {
				start: offset,
				end: offset + input.len(),
			},
			wildcard,
		})
	}

	fn full_pattern_str<'a>(&self, data: &'a str) -> &'a str {
		&data[self.range.clone()]
	}

	fn positive_pattern_str<'a>(&self, data: &'a str) -> &'a str {
		if self.negative {
			&self.full_pattern_str(data)[1..]
		} else {
			self.full_pattern_str(data)
		}
	}

	fn wildcard_in_positive_pattern(&self) -> Option<usize> {
		if self.negative {
			self.wildcard.map(|x| x - 1)
		} else {
			self.wildcard
		}
	}

	fn is_positive(&self) -> bool {
		!self.negative
	}

	fn matches(&self, pattern_data: &str, input: &str) -> bool {
		let pattern = self.positive_pattern_str(pattern_data);
		let wildcard = match self.wildcard_in_positive_pattern() {
			None => return input == pattern,
			Some(x) => x,
		};

		let prefix = &pattern[..wildcard];
		// It's okay to slice with `wildcard + 1`, because the only wildcards we support as ASCII.
		let suffix = &pattern[wildcard + 1..];

		// It's okay to get a byte, because the only wildcards we support as ASCII.
		let wildcard = pattern.as_bytes()[wildcard];

		let input = match input.strip_prefix(prefix) {
			Some(x) => x,
			None => return false,
		};
		let input = match input.strip_suffix(suffix) {
			Some(x) => x,
			None => return false,
		};

		if wildcard == b'*' {
			true
		} else if wildcard == b'?' {
			input.chars().count() == 1
		} else {
			false
		}
	}

}

#[cfg(test)]
mod test {
	use super::*;
	use assert2::{assert, let_assert};

	#[test]
	fn test_host_pattern_parse_empty_string() {
		let_assert!(Ok(parsed) = Pattern::parse(""));
		let_assert!(BorrowedPattern::Single(pattern) = &parsed.pattern);
		assert!(pattern.negative == false);
		assert!(pattern.range.start == 0);
		assert!(pattern.range.end == 0);
		assert!(pattern.wildcard == None);
	}

	#[test]
	fn test_host_pattern_parse_single_fixed() {
		let_assert!(Ok(parsed) = Pattern::parse("aap.noot.mies"));
		let_assert!(BorrowedPattern::Single(pattern) = &parsed.pattern);
		assert!(pattern.negative == false);
		assert!(pattern.range.start == 0);
		assert!(pattern.range.end == 13);
		assert!(pattern.wildcard == None);
	}

	#[test]
	fn test_host_pattern_parse_single_star() {
		let_assert!(Ok(parsed) = Pattern::parse("aap.*.mies"));
		let_assert!(BorrowedPattern::Single(pattern) = &parsed.pattern);
		assert!(pattern.negative == false);
		assert!(pattern.range.start == 0);
		assert!(pattern.range.end == 10);
		assert!(pattern.wildcard == Some(4));
	}

	#[test]
	fn test_host_pattern_parse_negative_single_star() {
		let_assert!(Ok(parsed) = Pattern::parse("!aap.*.mies"));
		let_assert!(BorrowedPattern::Single(pattern) = &parsed.pattern);
		assert!(pattern.negative == true);
		assert!(pattern.range.start == 0);
		assert!(pattern.range.end == 11);
		assert!(pattern.wildcard == Some(5));
	}

	#[test]
	fn test_host_pattern_parse_list() {
		let_assert!(Ok(parsed) = Pattern::parse("!aap.noot.mies,*.noot.mies,aap.*"));
		let_assert!(BorrowedPattern::List(patterns) = &parsed.pattern);
		assert!(patterns.len() == 3);

		assert!(patterns[0].negative == true);
		assert!(patterns[0].range.start == 0);
		assert!(patterns[0].range.end == 14);
		assert!(patterns[0].wildcard == None);

		assert!(patterns[1].negative == false);
		assert!(patterns[1].range.start == 15);
		assert!(patterns[1].range.end == 26);
		assert!(patterns[1].wildcard == Some(0));

		assert!(patterns[2].negative == false);
		assert!(patterns[2].range.start == 27);
		assert!(patterns[2].range.end == 32);
		assert!(patterns[2].wildcard == Some(4));
	}

	#[test]
	fn test_host_pattern_parse_ignores_trailing_comma() {
		let_assert!(Ok(parsed) = Pattern::parse("aap,"));
		assert!(let BorrowedPattern::Single(_) = parsed.pattern);

		let_assert!(Ok(parsed) = Pattern::parse("aap,noot,"));
		let_assert!(BorrowedPattern::List(patterns) = parsed.pattern);
		assert!(patterns.len() == 2);

		let_assert!(Ok(parsed) = Pattern::parse(","));
		assert!(let BorrowedPattern::Single(_) = parsed.pattern);
	}

	#[test]
	fn test_host_pattern_matches_empty_pattern() {
		let_assert!(Ok(parsed) = Pattern::parse(""));
		assert!(parsed.matches("") == true);
		assert!(parsed.matches("a") == false);
		assert!(parsed.matches(".") == false);
		assert!(parsed.matches("*") == false);
		assert!(parsed.matches("aap") == false);
	}

	#[test]
	fn test_host_pattern_matches_single_fixed() {
		let_assert!(Ok(parsed) = Pattern::parse("aap.*.mies"));

		assert!(parsed.matches("aap.noot.mies") == true);
		assert!(parsed.matches("noot.mies") == false);
		assert!(parsed.matches("aap.noot") == false);
		assert!(parsed.matches("aap.noot.mie") == false);
		assert!(parsed.matches("ap.noot.mie") == false);
		assert!(parsed.matches("") == false);

		assert!(parsed.matches("aap.goot.mies") == true);
		assert!(parsed.matches("aap.wim.mies") == true);
		assert!(parsed.matches("aap..mies") == true);
	}

	#[test]
	fn test_host_pattern_matches_single_star() {
		let_assert!(Ok(parsed) = Pattern::parse("aap.*.mies"));

		assert!(parsed.matches("aap.noot.mies") == true);
		assert!(parsed.matches("noot.mies") == false);
		assert!(parsed.matches("aap.noot") == false);
		assert!(parsed.matches("aap.noot.mie") == false);
		assert!(parsed.matches("ap.noot.mie") == false);
		assert!(parsed.matches("") == false);

		assert!(parsed.matches("aap.goot.mies") == true);
		assert!(parsed.matches("aap.wim.mies") == true);
		assert!(parsed.matches("aap..mies") == true);
	}

	#[test]
	fn test_host_pattern_matches_negative_single_star() {
		let_assert!(Ok(parsed) = Pattern::parse("!aap.*.mies"));

		assert!(parsed.matches("aap.noot.mies") == false);
		assert!(parsed.matches("noot.mies") == false);
		assert!(parsed.matches("aap.noot") == false);
		assert!(parsed.matches("aap.noot.mie") == false);
		assert!(parsed.matches("ap.noot.mie") == false);
		assert!(parsed.matches("") == false);

		assert!(parsed.matches("aap.goot.mies") == false);
		assert!(parsed.matches("aap.wim.mies") == false);
		assert!(parsed.matches("aap..mies") == false);
	}

	#[test]
	fn test_host_pattern_matches_all() {
		let_assert!(Ok(parsed) = Pattern::parse("*"));
		assert!(parsed.matches("") == true);
		assert!(parsed.matches("aap") == true);
		assert!(parsed.matches("aap.noot") == true);
	}

	#[test]
	fn test_host_pattern_matches_list() {
		let_assert!(Ok(parsed) = Pattern::parse("!aap.noot.mies,*.noot.mies,aap.*"));
		assert!(parsed.matches("aap.noot.mies") == false);
		assert!(parsed.matches("wim.noot.mies") == true);
		assert!(parsed.matches("ap.noot.mies") == true);
		assert!(parsed.matches("aap.") == true);
		assert!(parsed.matches("aap.wim") == true);
		assert!(parsed.matches("aap.wim.zus") == true);

		let_assert!(Ok(parsed) = Pattern::parse("*,*"));
		assert!(parsed.matches("") == true);
		assert!(parsed.matches("aap") == true);
		assert!(parsed.matches("aap.noot") == true);

		let_assert!(Ok(parsed) = Pattern::parse("!aap,*"));
		assert!(parsed.matches("") == true);
		assert!(parsed.matches("aap") == false);
		assert!(parsed.matches("noot") == true);
		assert!(parsed.matches("aap.noot") == true);

		let_assert!(Ok(parsed) = Pattern::parse("!*,*"));
		assert!(parsed.matches("") == false);
		assert!(parsed.matches("aap") == false);
		assert!(parsed.matches("noot") == false);
		assert!(parsed.matches("aap.noot") == false);

		let_assert!(Ok(parsed) = Pattern::parse("*,!*"));
		assert!(parsed.matches("") == true);
		assert!(parsed.matches("aap") == true);
		assert!(parsed.matches("noot") == true);
		assert!(parsed.matches("aap.noot") == true);
	}
}
