# auth-git2

Easy authentication for [`git2`].

Authentication with [`git2`] can be quite difficult to implement correctly.
This crate aims to make it easy.

In the simplest case, you can create a [`GitAuthenticator`] struct and directly use it for authentication.
By default, it will enable all supported authentication mechanisms.
You can get a [`git2::Credentials`] callback for use with any git operation that requires authentication using the [`GitAuthenticator::credentials()`] function.
Alternatively, you can use a utility function like [`GitAuthenticator::clone()`], [`GitAuthenticator::fetch()`] or [`GitAuthenticator::push()`].

## Features

* Minimal dependency tree!
* Query the SSH agent.
* Get SSH keys from files.
* Prompt for SSH key passwords if needed (for OpenSSH private keys).
* Query the git credential helper.
* Use provided plain username + password.
* Prompt the user for username + password on the terminal.

## Example: Clone a repository with authentication
```rust
use auth_git2::GitAuthenticator;
use std::path::Path;

let auth = GitAuthenticator::default();
let git_config = git2::Config::open_default()?;
let mut repo_builder = git2::build::RepoBuilder::new();
let mut fetch_options = git2::FetchOptions::new();
let mut remote_callbacks = git2::RemoteCallbacks::new();

remote_callbacks.credentials(auth.credentials(&git_config));
fetch_options.remote_callbacks(remote_callbacks);
repo_builder.fetch_options(fetch_options);

let url = "https://github.com/de-vri-es/auth-git2-rs";
let into = Path::new("/tmp/dyfhxoaj/auth-git2-rs");
let mut repo = repo_builder.clone(url, into);
```

[`git2`]: https://docs.rs/git2
[`GitAuthenticator`]: https://docs.rs/auth-git2/latest/git2_auth/struct.GitAuthenticator.html
[`git2::Credentials`]: https://docs.rs/git2/latest/git2/type.Credentials.html
[`GitAuthenticator::credentials()`]: https://docs.rs/auth-git2/latest/git2_auth/struct.GitAuthenticator.html#method.credentials
[`GitAuthenticator::clone()`]: https://docs.rs/auth-git2/latest/git2_auth/struct.GitAuthenticator.html#method.clone
[`GitAuthenticator::fetch()`]: https://docs.rs/auth-git2/latest/git2_auth/struct.GitAuthenticator.html#method.fetch
[`GitAuthenticator::push()`]: https://docs.rs/auth-git2/latest/git2_auth/struct.GitAuthenticator.html#method.push
