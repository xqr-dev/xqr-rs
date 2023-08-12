# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed
- **Breaking change**: `decode` now borrows the XQR instead of taking ownership of it
  - This allows the XQR to be reused after decoding

## [0.3.0] - 2023-08-11
### Added
- Add `CONTRIBUTING.md` and `CODE_OF_CONDUCT.md` for community guidelines
- **Breaking change**: `encode` now takes a `valid_for` argument to set how long the token is valid for
  - This can be set to `None` to make the token valid forever

## [0.2.0] - 2023-08-11
### Added
- Add `fetch_public_key` to fetch a public key based on a key id
- Add `XQR.get_key_id` to get the key id from a JWT

## [0.1.0] - 2023-08-10
### Added
- `encode` method to create a new XQR
- `decode` method to decode an XQR
- `generate_key_pair` method to generate a new ES256 key pair
