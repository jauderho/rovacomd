//! rovacomd: behavior-preserving Rust port of the novacomd daemon.
#![deny(unsafe_code)]

pub mod bufq;
pub mod cli;
pub mod cmdparse;
pub mod devices;
pub mod inet;
pub mod log;
pub mod mux;
pub mod net;
pub mod server;
#[allow(unsafe_code)]
pub mod sys;
