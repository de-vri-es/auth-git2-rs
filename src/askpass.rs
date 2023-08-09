use std::io::Write;
use std::path::{Path, PathBuf};

use crate::PlaintextCredentials;

pub enum Error {
	Command(std::io::Error),
	ExitStatus(ExitStatusError),
	InvalidUtf8(std::string::FromUtf8Error),
	OpenTerminal(std::io::Error),
	ReadWriteTerminal(std::io::Error),
}

pub struct ExitStatusError {
	pub status: std::process::ExitStatus,
	pub stderr: Result<String, std::string::FromUtf8Error>,
}

impl Error {
	pub fn extra_message(&self) -> Option<&str> {
		match self {
			Self::ExitStatus(e) => e.extra_message(),
			_ => None,
		}
	}
}

impl ExitStatusError {
	pub fn extra_message(&self) -> Option<&str> {
		self.stderr.as_deref().ok()
	}
}

pub(crate) fn prompt_credentials(username: Option<&str>, url: &str, git_config: &git2::Config) -> Result<PlaintextCredentials, Error> {
	if let Some(askpass) = askpass_command(git_config) {
		let username = match username {
			Some(x) => x.into(),
			None => askpass_prompt(&askpass, &format!("Username for {url}"))?,
		};
		let password = askpass_prompt(&askpass, &format!("Password for {url}"))?;
		Ok(PlaintextCredentials {
			username,
			password,
		})
	} else {
		let mut terminal = terminal_prompt::Terminal::open()
			.map_err(Error::OpenTerminal)?;
		writeln!(terminal, "Authentication needed for {url}")
			.map_err(Error::ReadWriteTerminal)?;
		let username = match username {
			Some(x) => x.into(),
			None => terminal.prompt("Username: ").map_err(Error::ReadWriteTerminal)?,
		};
		let password = terminal.prompt_sensitive("Password: ")
			.map_err(Error::ReadWriteTerminal)?;
		Ok(PlaintextCredentials {
			username,
			password,
		})
	}
}

pub(crate) fn prompt_ssh_key_password(private_key_path: &Path, git_config: &git2::Config) -> Result<String, Error> {
	if let Some(askpass) = askpass_command(git_config) {
		askpass_prompt(&askpass, &format!("Password for {}", private_key_path.display()))
	} else {
		let mut terminal = terminal_prompt::Terminal::open()
			.map_err(Error::OpenTerminal)?;
		writeln!(terminal, "Password needed for {}", private_key_path.display())
			.map_err(Error::ReadWriteTerminal)?;
		terminal.prompt_sensitive("Password: ").map_err(Error::ReadWriteTerminal)
	}
}

fn askpass_command(git_config: &git2::Config) -> Option<PathBuf> {
	if let Some(command) = std::env::var_os("GIT_ASKPASS") {
		Some(command.into())
	} else if let Ok(command) = git_config.get_path("core.askPass") {
		return Some(command)
	} else if let Some(command) = std::env::var_os("SSH_ASKPASS") {
		return Some(command.into());
	} else {
		None
	}
}

fn askpass_prompt(program: &Path, prompt: &str) -> Result<String, Error> {
	let output = std::process::Command::new(program)
		.arg(prompt)
		.output()
		.map_err(Error::Command)?;
	if output.status.success() {
		let password = String::from_utf8(output.stdout)
			.map_err(Error::InvalidUtf8)?;
		Ok(password)
	} else {
		// Do not keep stdout, it could contain a password D:
		Err(Error::ExitStatus(ExitStatusError {
			status: output.status,
			stderr: String::from_utf8(output.stderr),
		}))
	}
}

impl std::fmt::Display for Error {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		match self {
			Self::Command(e) => write!(f, "Failed to run command: {e}"),
			Self::ExitStatus(e) => write!(f, "{e}"),
			Self::InvalidUtf8(_) => write!(f, "Password contains invalid UTF-8"),
			Self::OpenTerminal(e) => write!(f, "Failed to open terminal: {e}"),
			Self::ReadWriteTerminal(e) => write!(f, "Failed to read/write to terminal: {e}"),
		}
	}
}

impl std::fmt::Display for ExitStatusError {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		write!(f, "program exitted with {}", self.status)
	}
}
