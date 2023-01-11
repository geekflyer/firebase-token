# firebase-token

## About

Validate firabase ID token written in Rust

[Crates.io](https://crates.io/crates/firebase-token)

[API Docs](https://docs.rs/firebase-token)

## Installation

Add the following to Cargo.toml:

```toml
[dependencies]
firebase-token = "0.3"
```

```rust
use firebase_token::JwkAuth;

let jwk_auth = JwkAuth::new(FIREBASE_PROJECT_ID).await;
let token_claim = jwk_auth.verify(id_token).await;
```

## License

MIT
