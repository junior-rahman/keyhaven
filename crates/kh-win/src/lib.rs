//! Windows Hello and named-pipe peer identity. Empty on other platforms.
#![cfg(windows)]

pub mod hello;
pub mod peer;
