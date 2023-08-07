# auth-git2

Easy authentication for [`git2`].

Authentication with [`git2`] can be quite difficult to implement correctly.
This crate aims to make it easy.

In the simplest case, you can create a [`GitAuthenticator`] struct and directly use it for authentication.
By default, it will enable all supported authentication mechanisms.
You can run any git operation that requires authentication using the [`GitAuthenticator::run_operation()`] function.

## Features

* Minimal dependency tree!
* Query the SSH agent.
* Get unencrypted SSH keys from files.
* Query the git credential helper.
* Use provided plain username + password.
* Prompt the user for username + password on the terminal.

## Example: Clone a repository with authentication
```rust
use auth_git2::GitAuthenticator;
use std::path::Path;

let git_config = git2::Config::open_default()?;
let repo = GitAuthenticator::default()
    .run_operation(&git_config, |credentials| {
        let mut remote_callbacks = git2::RemoteCallbacks::new();
        remote_callbacks.credentials(credentials);
        let mut fetch_options = git2::FetchOptions::new();
        fetch_options.remote_callbacks(remote_callbacks);
        let mut repo_builder = git2::build::RepoBuilder::new();
        repo_builder.fetch_options(fetch_options);

        let url = "https://github.com/de-vri-es/auth-git2-rs";
        let path = Path::new("/tmp/auth-git2-rs");
        repo_builder.clone(url, path)
    })?;
```

[`git2`]: https://docs.rs/git2
[`GitAuthenticator`]: https://docs.rs/auth-git2/latest/git2_auth/struct.GitAuthenticator.html
[`GitAuthenticator::run_operation()`]: https://docs.rs/auth-git2/latest/git2_auth/struct.GitAuthenticator.html#method.run_operation
