#![allow(non_snake_case)]
/*

Copyright 2018 by Suyash Bagad, Saravanan Vijayakumaran

This file is part of revelioPlus library
(<add a link to github>)

*/

// based on the paper: <link to paper>

#![feature(external_doc)]
#![doc(include = "../README.md")]

#[macro_use]
extern crate serde_derive;
extern crate serde;

extern crate curv;
extern crate itertools;
extern crate rand;
extern crate time;

///
/// The `proofs` module contains the API for constructing [RevelioBP](proofs/revelio_bp/index.html) and [Improved Inner Product](proofs/inner_product/index.html) protocols. 
/// 
pub mod proofs;


///
/// Errors in construction of [RevelioBP](proofs/revelio_bp/index.html) and [Improved Inner Product](proofs/inner_product/index.html) protocols.
#[derive(Copy, PartialEq, Eq, Clone, Debug)]
pub enum Errors {
    InnerProductError,
    RevelioBPError,
}
