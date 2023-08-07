//! Easy authentication for [`git2`].
//!
//! Authentication with [`git2`] can be quite difficult to implement correctly.
//! This crate aims to make it easy.
//!
//! In the simplest case, you can create a [`GitAuthenticator`] struct and directly use it for authentication.
//! By default, it will enable all supported authentication mechanisms.
//! You can run any git operation that requires authentication using the [`GitAuthenticator::run_operation()`] function.
//!
//! # Features
//!
//! * Minimal dependency tree!
//! * Query the SSH agent.
//! * Get unencrypted SSH keys from files.
//! * Query the git credential helper.
//! * Use provided plain username + password.
//! * Prompt the user for username + password on the terminal.
//!
//! # Example: Clone a repository with authentication
//! ```no_run
//! # fn main() -> Result<(), git2::Error> {
//! use git2_auth::GitAuthenticator;
//! use std::path::Path;
//!
//! let git_config = git2::Config::open_default()?;
//! let repo = GitAuthenticator::default()
//!     .run_operation(&git_config, |credentials| {
//!         let mut remote_callbacks = git2::RemoteCallbacks::new();
//!         remote_callbacks.credentials(credentials);
//!         let mut fetch_options = git2::FetchOptions::new();
//!         fetch_options.remote_callbacks(remote_callbacks);
//!         let mut repo_builder = git2::build::RepoBuilder::new();
//!         repo_builder.fetch_options(fetch_options);
//!
//!         let url = "https://github.com/de-vri-es/git2-auth-rs";
//!         let path = Path::new("/tmp/git2-auth-rs");
//!         repo_builder.clone(url, path)
//!     })?;
//! # Ok(())
//! # }
//! ```

#![warn(missing_docs)]

use std::path::{PathBuf, Path};
use std::io::Write;

/// Configurable authenticator to use with [`git2`].
#[derive(Debug, Clone)]
pub struct GitAuthenticator {
	/// Plaintext credentials to try.
	plaintext_credentials: Vec<PlaintextCredentials>,

	/// Try getting username/password from the git credential helper.
	try_cred_helper: bool,

	/// Number of times to ask the user for a username/password on the terminal.
	try_password_prompt: u32,

	/// Usernames to try for SSH connections if no username was specified.
	usernames: Vec<String>,

	/// Try to use the SSH agent to get a working SSH key.
	try_ssh_agent: bool,

	/// SSH keys to use from file.
	ssh_keys: Vec<PrivateKeyFile>,
}

impl Default for GitAuthenticator {
	fn default() -> Self {
		Self::new()
	}
}

impl GitAuthenticator {
	/// Create a new authenticator with all supported options enabled.
	///
	/// This is equavalent to:
	/// ```
	/// # use git2_auth::GitAuthenticator;
	/// GitAuthenticator::new_empty()
	///     .try_cred_helper(true)
	///     .try_password_prompt(3)
	///     .add_default_username()
	///     .try_ssh_agent(true)
	///     .add_default_ssh_keys()
	/// # ;
	/// ```
	pub fn new() -> Self {
		Self::new_empty()
			.try_cred_helper(true)
			.try_password_prompt(3)
			.add_default_username()
			.try_ssh_agent(true)
			.add_default_ssh_keys()
	}

	/// Create a new authenticator with all authentication options disabled.
	pub fn new_empty() -> Self {
		Self {
			try_ssh_agent: false,
			try_cred_helper: false,
			plaintext_credentials: Vec::new(),
			try_password_prompt: 0,
			usernames: Vec::new(),
			ssh_keys: Vec::new(),
		}
	}

	/// Add a username + password to try for authentication.
	pub fn add_plaintext_credentials(mut self, username: String, password: String) -> Self {
		self.plaintext_credentials.push(PlaintextCredentials {
			username,
			password,
		});
		self
	}

	/// Configure if the git credentials helper should be used.
	///
	/// See the git documentation of the `credential.helper` configuration options for more details.
	pub fn try_cred_helper(mut self, enable: bool) -> Self {
		self.try_cred_helper = enable;
		self
	}

	/// Configure the number of times we should prompt the user for a username/password.
	///
	/// Set to `0` to disable.
	pub fn try_password_prompt(mut self, max_count: u32) -> Self {
		self.try_password_prompt = max_count;
		self
	}

	/// Add a username to try for authentication.
	///
	/// Some authentication mechanisms need a username, but not all valid `git` URLs specify one.
	/// You can add one or more usernames to try in that situation.
	pub fn add_username(mut self, name: String) -> Self {
		self.usernames.push(name);
		self
	}

	/// Add the default username to try.
	///
	/// The default username if read from the `USER` or `USERNAME` environment variable.
	pub fn add_default_username(self) -> Self {
		if let Ok(username) = std::env::var("USER").or_else(|_| std::env::var("USERNAME")) {
			self.add_username(username)
		} else {
			self
		}
	}

	/// Configure if the SSH agent should be user for public key authentication.
	pub fn try_ssh_agent(mut self, enable: bool) -> Self {
		self.try_ssh_agent = enable;
		self
	}

	/// Add a private key to use for public key authentication.
	///
	/// The key will be read from disk by `git2`, so it must still exist when the authentication is performed.
	///
	/// A matching `.pub` file will also be read if it exists.
	/// For example, if you add the private key `"foo/my_ssh_id"`,
	/// then `"foo/my_ssh_id.pub"` will be used too, if it exists.
	pub fn add_ssh_key_from_file(mut self, private_key: PathBuf) -> Self {
		let public_key = get_pub_key_path(&private_key);
		self.ssh_keys.push(PrivateKeyFile {
			private_key,
			public_key,
		});
		self
	}

	/// Add all default SSH keys for public key authentication.
	///
	/// This will add all of the following files, if they exist:
	///
	/// * `"$HOME/.ssh/id_rsa"`
	/// * `"$HOME/.ssh"id_ecdsa,"`
	/// * `"$HOME/.ssh"id_ecdsa_sk"`
	/// * `"$HOME/.ssh"id_ed25519"`
	/// * `"$HOME/.ssh"id_ed25519_sk"`
	/// * `"$HOME/.ssh"id_dsa"`
	pub fn add_default_ssh_keys(mut self) -> Self {
		let ssh_dir = match dirs::home_dir() {
			Some(x) => x.join(".ssh"),
			None => return self,
		};

		let candidates = [
			"id_rsa",
			"id_ecdsa,",
			"id_ecdsa_sk",
			"id_ed25519",
			"id_ed25519_sk",
			"id_dsa",
		];

		for candidate in candidates {
			let private_key = ssh_dir.join(candidate);
			if !private_key.is_file() {
				continue;
			}
			self = self.add_ssh_key_from_file(private_key);
		}

		self
	}

	/// Run a user operation with authentication.
	///
	/// The user operation is a callback that received a [`git2::Credentials`] object (which is technically also a callback).
	/// You should use the provided [`git2::Credentials`] when calling [`git2`] functions.
	///
	/// Note: We may need to call the user operation multiple times to try authentication with different usernames.
	/// You should ensure that the provided callback works correctly when called multiple times.
	///
	/// # Example: Fetch from a remote with authentication
	/// ```no_run
	/// # fn foo(repo: &mut git2::Repository) -> Result<(), git2::Error> {
	/// use git2_auth::GitAuthenticator;
	///
	/// let git_config = repo.config()?;
	/// let mut remote = repo.find_remote("origin")?;
	/// GitAuthenticator::default()
	///     .run_operation(&git_config, |credentials| {
	///         let mut remote_callbacks = git2::RemoteCallbacks::new();
	///         remote_callbacks.credentials(credentials);
	///         let mut fetch_options = git2::FetchOptions::new();
	///         fetch_options.remote_callbacks(remote_callbacks);
	///         remote.fetch(&["main"], Some(&mut fetch_options), None)
	///     })?;
	/// # Ok(())
	/// # }
	/// ```
	pub fn run_operation<F, T>(&self, git_config: &git2::Config, mut user_operation: F) -> Result<T, git2::Error>
	where
		F: FnMut(&mut git2::Credentials<'_>) -> Result<T, git2::Error>,
	{
		let mut need_stage2 = false;
		let result = user_operation(&mut make_stage1_callback(self, git_config, &mut need_stage2));
		if result.is_ok() || ! need_stage2 {
			return result;
		}

		for username in &self.usernames {
			// We should get `USERNAME` first, where we just return our attempt,
			// and then after that we should get `SSH_KEY`. If the first attempt
			// fails we'll get called again, but we don't have another option so
			// we bail out.
			let mut exhausted = false;
			let result = user_operation(&mut make_stage2_callback(self, username, &mut exhausted));
			if result.is_ok() || !exhausted {
				return result;
			}
		}

		Err(git2::Error::from_str("all authentication attempts failed"))
	}
}

fn make_stage1_callback<'a>(
	authenticator: &'a GitAuthenticator,
	git_config: &'a git2::Config,
	need_stage2: &'a mut bool,
) -> impl 'a + FnMut(&str, Option<&str>, git2::CredentialType) -> Result<git2::Cred, git2::Error> {
	let mut plaintext_credentials = authenticator.plaintext_credentials.iter();
	let mut try_cred_helper = authenticator.try_cred_helper;
	let mut try_password_prompt = authenticator.try_password_prompt;
	let mut try_ssh_agent = authenticator.try_ssh_agent;
	let mut ssh_keys = authenticator.ssh_keys.iter();

	move |url: &str, username: Option<&str>, allowed: git2::CredentialType| {
		// If git2 is asking for a username, we got an SSH url without username specified.
		// After we supply a username, it will ask for the real credentials.
		//
		// Sadly, we can not switch usernames during an authentication session,
		// so to try different usernames, we need to retry the git operation multiple times.
		// If this happens, we'll bail and go into stage 2.
		if allowed.contains(git2::CredentialType::USERNAME) {
			*need_stage2 = true;
			return Err(git2::Error::from_str("gonna try usernames later"));
		}

		// Try public key authentication.
		if allowed.contains(git2::CredentialType::SSH_KEY) {
			if let Some(username) = username {
				if try_ssh_agent {
					try_ssh_agent = false;
					if let Ok(credentials) = git2::Cred::ssh_key_from_agent(username) {
						return Ok(credentials)
					}
				}
				#[allow(clippy::while_let_on_iterator)] // Incorrect lint: we're not consuming the iterator.
				while let Some(key) = ssh_keys.next() {
					if let Ok(credentials) = key.to_credentials(username) {
						return Ok(credentials)
					}
				}
			}
		}

		// Sometimes libgit2 will ask for a username/password in plaintext.
		// Let's try git's `credential.helper` support first before bothering the user with a prompt.
		if allowed.contains(git2::CredentialType::USER_PASS_PLAINTEXT) {
			// Try provided plaintext credentials first.
			if let Some(credentials) = plaintext_credentials.next() {
				if let Ok(credentials) = credentials.to_credentials() {
					return Ok(credentials)
				}
			}

			// Try the git credential helper.
			if try_cred_helper {
				try_cred_helper = false;
				if let Ok(credentials) = git2::Cred::credential_helper(git_config, url, username) {
					return Ok(credentials);
				}
			}

			// Prompt the user on the terminal.
			if try_password_prompt > 0 {
				try_password_prompt -= 1;
				if let Ok(credentials) = prompt_credentials(username, url) {
					return Ok(credentials);
				}
			}
		}

		// Whelp, we tried our best
		Err(git2::Error::from_str("all authentication attempts failed"))
	}
}

fn make_stage2_callback<'a>(
	authenticator: &'a GitAuthenticator,
	username: &'a str,
	exhausted: &'a mut bool,
) -> impl 'a + FnMut(&str, Option<&str>, git2::CredentialType) -> Result<git2::Cred, git2::Error> {
	let mut gave_username = false;
	let mut try_ssh_agent = authenticator.try_ssh_agent;
	let mut ssh_keys = authenticator.ssh_keys.iter();

	*exhausted = false;
	move |_url, _username, allowed_auth| {
		if allowed_auth.contains(git2::CredentialType::USERNAME) && !gave_username {
			gave_username = true;
			return git2::Cred::username(username);
		}

		if allowed_auth.contains(git2::CredentialType::SSH_KEY) {
			if try_ssh_agent {
				try_ssh_agent = false;
				if let Ok(credentials) = git2::Cred::ssh_key_from_agent(username) {
					return Ok(credentials)
				}
			}

			#[allow(clippy::while_let_on_iterator)] // Incorrect lint: we're not consuming the iterator.
			while let Some(key) = ssh_keys.next() {
				if let Ok(credentials) = key.to_credentials(username) {
					return Ok(credentials)
				}
			}
		}

		*exhausted = true;
		Err(git2::Error::from_str("no working authentication available"))
	}
}

#[derive(Debug, Clone)]
struct PrivateKeyFile {
	private_key: PathBuf,
	public_key: Option<PathBuf>,
}

impl PrivateKeyFile {
	fn to_credentials(&self, username: &str) -> Result<git2::Cred, git2::Error> {
		// TODO: determine if we need to prompt for a password.
		git2::Cred::ssh_key(username, self.public_key.as_deref(), &self.private_key, None)
	}
}

#[derive(Debug, Clone)]
struct PlaintextCredentials {
	username: String,
	password: String,
}

impl PlaintextCredentials {
	fn to_credentials(&self) -> Result<git2::Cred, git2::Error> {
		git2::Cred::userpass_plaintext(&self.username, &self.password)
	}
}

fn prompt_credentials(username: Option<&str>, url: &str) -> Result<git2::Cred, git2::Error> {
	let mut terminal = terminal_prompt::Terminal::open()
		.map_err(io_to_git_error)?;
	writeln!(terminal, "Authentication needed for git: {url}")
		.map_err(io_to_git_error)?;
	if let Some(username) = username {
		let password = terminal.prompt_sensitive("Password: ")
			.map_err(io_to_git_error)?;
		git2::Cred::userpass_plaintext(username, &password)
	} else {
		let username = terminal.prompt("Username: ")
			.map_err(io_to_git_error)?;
		let password = terminal.prompt_sensitive("Password: ")
			.map_err(io_to_git_error)?;
		git2::Cred::userpass_plaintext(&username, &password)
	}
}

fn io_to_git_error(input: std::io::Error) -> git2::Error {
	// TODO: do better error mapping?
	git2::Error::from_str(&input.to_string())
}

fn get_pub_key_path(priv_key_path: &Path) -> Option<PathBuf> {
	let name = priv_key_path.file_name()?;
	let name = name.to_str()?;
	let pub_key_path = priv_key_path.with_file_name(format!("{name}.pub"));
	if pub_key_path.is_file() {
		Some(pub_key_path)
	} else {
		None
	}
}
