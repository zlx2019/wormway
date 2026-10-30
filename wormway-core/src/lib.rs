//! Core types for Wormway: the configuration model, route and rule matching, timestamps, error
//! types and more. It does not depend on any networking framework.
//!
//! Features:
//!
//! - `schema`: JSON Schema generation for the configuration file.

pub mod config;
pub mod routing;
pub mod time;
