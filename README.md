# ZkSchnorr: Multipoint schnorr signatures on Ristretto

This library is an extension of [Starsig](https://github.com/stellar/slingshot/tree/main/starsig), implementation of a simple Schnorr signature protocol to support multipoint Elgamal verification keys. It is 
implemented with [Ristretto](https://ristretto.group) and [Merlin transcripts](https://merlin.cool). 

* [Specification](docs/spec.md)

## Features

* Simple message-based API.
* Flexible [transcript](https://merlin.cool)-based API.
* Single signature verification.
* Batch signature verification.

## Execution

Run the library with `cargo run`

## Tests

Run tests with `cargo tests`