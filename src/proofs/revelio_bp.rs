//  -*- mode: rust; -*-
// 
// This file is part of revelioBP library.
// Copyright (c) 2020 Suyash Bagad
// See LICENSE for licensing information.
//
// Authors:
// - Suyash Bagad <suyashbagad@iitb.ac.in>
// 

//!
//! An implementation of improved inner product argument
//! based on the paper titled 
//! [Performance Tradeoffs in MimbleWimble Proofs of Reserves](https://to_be_added.com).
//!

// based on the paper: <link to paper>

#![allow(non_snake_case)]

use curv::arithmetic::traits::{Converter, Modulo, Samplable};
use curv::cryptographic_primitives::hashing::hash_sha256::HSha256;
use curv::cryptographic_primitives::hashing::traits::*;
use curv::cryptographic_primitives::hashing::hash_sha512::HSha512;
use curv::elliptic::curves::traits::*;
use curv::BigInt;
use curv::{FE, GE};
use proofs::inner_product::InnerProductArg;
use Errors::{self, RevelioBPError};
use rand::distributions::{Distribution, Uniform};
use std::cmp;


#[derive(Debug, Serialize, Deserialize)]
pub struct Constraints{
    alpha: Vec<BigInt>,
    beta: Vec<BigInt>,
    theta: Vec<BigInt>,
    theta_inv: Vec<BigInt>,
    nu: Vec<BigInt>,
    mu: Vec<BigInt>,
    delta: BigInt,
}

impl Constraints{
    pub fn generate_constraints(
        u: BigInt,
        v: BigInt,
        y: BigInt,
        z: BigInt,
        n: usize,
        s: usize,
    ) -> Constraints {

        // vector sizes
        let t: usize = s*n + n + s + 3;
        let sn: usize = s*n;
        let p_len = n+3;
        let order = FE::q();

        // challenge powers
        let u_s = (0..s)
            .map(|i| {
                BigInt::mod_pow(&u, &BigInt::from(i as u32), &order)
            })
            .collect::<Vec<BigInt>>();

        let y_s = (0..s)
            .map(|i| {
                BigInt::mod_pow(&y, &BigInt::from(i as u32), &order)
            })
            .collect::<Vec<BigInt>>();
        
        let y_n = (0..n)
            .map(|i| {
                BigInt::mod_pow(&y, &BigInt::from(i as u32), &order)
            })
            .collect::<Vec<BigInt>>();

        let minus_y_n = (0..n)
            .map(|i| {
                BigInt::mod_sub(&BigInt::zero(), &y_n[i], &order)
            })
            .collect::<Vec<BigInt>>();

        let y_sn = (0..sn)
            .map(|i| {
                BigInt::mod_pow(&y, &BigInt::from(i as u32), &order)
            })
            .collect::<Vec<BigInt>>();

        let us_kronecker_yn = (0..sn)
            .map(|i| {
                let j = i % n;
                let k = i / n;
                let y_j = BigInt::mod_pow(&y, &BigInt::from(j as u32), &order);
                let u_k = BigInt::mod_pow(&u, &BigInt::from(k as u32), &order);
                BigInt::mod_mul(&u_k, &y_j, &order)
            })
            .collect::<Vec<BigInt>>();
        
        let ys_kronecker_1n = (0..sn)
            .map(|i| {
                let k = i / n;
                BigInt::mod_pow(&y, &BigInt::from(k as u32), &order)
            })
            .collect::<Vec<BigInt>>();

        let y_pow_s = BigInt::mod_pow(&y, &BigInt::from(s as u32), &order);
        let z_2 = BigInt::mod_pow(&z, &BigInt::from(2), &order);
        let z_3 = BigInt::mod_pow(&z, &BigInt::from(3), &order);
        let z_4 = BigInt::mod_pow(&z, &BigInt::from(4), &order);
        
        let v_minus_1 = BigInt::mod_sub(&v, &BigInt::one(), &order);
        let v_minus_1_us = (0..s)
            .map(|i| {
                BigInt::mod_mul(&v_minus_1, &u_s[i], &order)
            })
            .collect::<Vec<BigInt>>();

        // Define constraints fn(u,v,y) : part 1
        let v0 = (0..t)
            .map(|i| {
                if i >= p_len && i < t-s {
                    y_sn[i-p_len].clone()
                }
                else {
                    // Solving the issue of theta by changing v0
                    BigInt::one()
                }
            })
            .collect::<Vec<BigInt>>();

        let v1 = (0..t)
            .map(|i| {
                if i==0 {
                    v.clone()
                }
                else if i==1 {
                    BigInt::one()
                }
                else if i >= t-s {
                    v_minus_1_us[(i+s)-t].clone()
                }
                else {
                    BigInt::zero()
                }
            })
            .collect::<Vec<BigInt>>();

        let v2 = (0..t)
            .map(|i| {
                if i >= 2 && i < n+2 {
                    minus_y_n[i-2].clone()
                }
                else if i < t-s && i >= n+3{
                    us_kronecker_yn[i - (n+3)].clone()
                }
                else {
                    BigInt::zero()
                }
            })
            .collect::<Vec<BigInt>>();

        let v3 = (0..t)
            .map(|i| {
                if i == (n+2) {
                    y_pow_s.clone()
                }
                else if i < t-s && i >= n+3{
                    ys_kronecker_1n[i - (n+3)].clone()
                }
                else {
                    BigInt::zero()
                }
            })
            .collect::<Vec<BigInt>>();

        let v4 = (0..t)
            .map(|i| {
                if i >= p_len && i < t-s {
                    y_sn[i-p_len].clone()
                }
                else {
                    BigInt::zero()
                }
            })
            .collect::<Vec<BigInt>>();
        
        // constraint vectors as a fn of (u,v,y,z) : part 2
        let theta: Vec<BigInt> = v0.clone();

        let zeta = (0..t)
            .map(|i| {
                let zeta_1 = BigInt::mod_mul(&z, &v1[i], &order);
                let zeta_2 = BigInt::mod_mul(&z_2, &v2[i], &order);
                let zeta_3 = BigInt::mod_mul(&z_3, &v3[i], &order);
                let zeta_s1 = BigInt::mod_add(&zeta_1, &zeta_2, &order);
                BigInt::mod_add(&zeta_s1, &zeta_3, &order)
            })
            .collect::<Vec<BigInt>>();

        let theta_inv = (0..t)
            .map(|i| {
                BigInt::mod_inv(&theta[i], &order)
            })
            .collect::<Vec<BigInt>>();
        
        let nu = (0..t)
            .map(|i| {
                BigInt::mod_mul(&z_4, &v4[i], &order)
            })  
            .collect::<Vec<BigInt>>();

        let mu = (0..t)
            .map(|i| {
                BigInt::mod_add(&zeta[i], &nu[i], &order)
            })
            .collect::<Vec<BigInt>>();
        
        // Note that alpha = theta_inv * nu
        // No (-) sign before nu since we want <cL+cR-1^{t}, v4>=0
        let alpha = (0..t)
            .map(|i| {
                BigInt::mod_mul(&theta_inv[i], &nu[i], &order)
            })  
            .collect::<Vec<BigInt>>();

        let beta = (0..t)
            .map(|i| {
                BigInt::mod_mul(&theta_inv[i], &mu[i], &order)
            })  
            .collect::<Vec<BigInt>>();
        
        let one_s_ys = (0..s)
            .map(|i| {
                y_s[i].clone()
            })
            .fold(y_pow_s.clone(), |acc, x| BigInt::mod_add(&acc, &x, &order));

        let one_s_ys_z3 = BigInt::mod_mul(&one_s_ys, &z_3, &order);
        
        let delta: BigInt = (0..t)
            .map(|i| {
                let alp_mu_i = BigInt::mod_mul(&alpha[i], &mu[i], &order);
                BigInt::mod_add(&nu[i], &alp_mu_i, &order)
            })
            .fold(one_s_ys_z3.clone(), |acc, x| BigInt::mod_add(&acc, &x, &order));

        return Constraints{
            alpha,
            beta,
            theta,
            theta_inv,
            nu,
            mu,
            delta,
        };
        
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RevelioBP {
    I_vec: Vec<GE>,
    C_assets: GE,
    A: GE,
    S: GE,
    T1: GE,
    T2: GE,
    tau_x: FE,
    r: FE,
    t_hat: FE,
    inner_product_proof: InnerProductArg,
    constraint_vec: Constraints,
}

impl RevelioBP {
    pub fn prove(
        // crs
        G: &GE,
        H: &GE,
        Gt: &GE,
        H_prime: &GE,
        p_vec: &[GE],
        g_prime_vec: &[GE],
        h_vec: &[GE],
        g_vec_append: &[GE],
        h_vec_append: &[GE],
        // stmt
        C_vec: &[GE],
        // wit
        E_vec: &[BigInt],
        a_vec: &[FE],
        r_vec: &[FE], 
    ) -> RevelioBP {

        // number of outputs on the blockchain
        let n: usize = C_vec.len();

        // number of outputs owned by the exchange
        let s: usize = a_vec.len(); 

        // size of honestly encoded witness vector
        let t: usize = s*n + n + s + 3;

        // other prelims
        let order = FE::q();
        let p_len = n+3;
        
        // generate key-images I = r.Gt + a.H
        let I_vec = (0..s)
            .map(|i| Gt * &r_vec[i] + H * &a_vec[i])
            .collect::<Vec<GE>>();

        // generate commitment to total assets
        let C_assets = (1..s)
            .map(|i| &I_vec[i])
            .fold(I_vec[0], |acc, x| acc + x);

        // generate u,v
        let u = HSha256::create_hash_from_ge(&[G, H, Gt]);
        let base_point: GE = ECPoint::generator();
        let uG: GE = base_point * &u;
        let v = HSha256::create_hash_from_ge(&[&uG]);
        
        let u_bn = u.to_big_int();
        let v_bn = v.to_big_int();

        // define compressed stmt
        let Y_hat: &[GE] = C_vec;
        let Y_hat_vec = Y_hat.to_vec();

        let minus1 = BigInt::mod_sub(&BigInt::zero(), &BigInt::one(), &order);
        let I0_inv = I_vec[0] * &(ECScalar::from(&minus1));
        let I_hat: GE = (1..s)
            .map(|i| {
                let u_i = BigInt::mod_pow(&u_bn, &BigInt::from(i as u32), &order);
                let minus_ui = BigInt::mod_sub(&BigInt::zero(), &u_i, &order);
                let u_i_fe: FE = ECScalar::from(&minus_ui);
                I_vec[i] * &u_i_fe
            })
            .fold(I0_inv, |acc, x| acc.add_point(&x.get_element()));

        // define compressed secrets
        let xi = (0..s)
            .map(|i| {
                let u_i = BigInt::mod_pow(&u_bn, &BigInt::from(i as u32), &order);
                let us_r_i = BigInt::mod_mul(&u_i, &r_vec[i].to_big_int(), &order);
                BigInt::mod_sub(&BigInt::zero(), &us_r_i, &order)
            })
            .fold(BigInt::zero(), |acc, x| BigInt::mod_add(&acc,&x,&order));
              
        let xi_prime = (0..s)
            .map(|i| {
                let u_i = BigInt::mod_pow(&u_bn, &BigInt::from(i as u32), &order);
                BigInt::mod_mul(&u_i, &r_vec[i].to_big_int(), &order)
            })
            .fold(BigInt::zero(), |acc, x| BigInt::mod_add(&acc,&x,&order));

        let mut E_mat: Vec<BigInt> = Vec::new();
        let zero_vec = vec![BigInt::zero(); n];
        let mut index: usize = 0;
        let e_hat = (0..n)
            .map(|i| {
                let bignum_bit: BigInt = &E_vec[i].clone() & BigInt::one();
                let byte = BigInt::to_vec(&bignum_bit);
                if byte[0]==1 {
                    E_mat.extend_from_slice(&zero_vec);
                    E_mat[n*index + i] = BigInt::one();
                    let u_i = BigInt::mod_pow(&u_bn, &BigInt::from(index as u32), &order);
                    index = index + 1;
                    u_i
                }
                else {
                    BigInt::zero()
                }
            })
            .collect::<Vec<BigInt>>();

        // E_mat_comp is NOT(E_mat)
        let sn = E_mat.len();
        let E_mat_comp = (0..sn)
            .map(|i| 
                if E_mat[i]==BigInt::zero() {
                    BigInt::one()
                }
                else {
                    BigInt::zero()
                }
            )
            .collect::<Vec<BigInt>>();

        let r_vec_bn = (0..s)
            .map(|i| r_vec[i].to_big_int()).collect::<Vec<BigInt>>();

        // secret vectors
        let mut c_L: Vec<BigInt> = vec![xi.clone(), xi_prime.clone()];
        c_L.extend_from_slice(&e_hat.clone());
        c_L.push(BigInt::one());
        c_L.extend_from_slice(&E_mat.clone());
        c_L.extend_from_slice(&r_vec_bn.clone());

        let mut c_R: Vec<BigInt> = vec![BigInt::zero(); p_len];
        let rem_zero = vec![BigInt::zero(); s];
        c_R.extend_from_slice(&E_mat_comp);
        c_R.extend_from_slice(&rem_zero);

        // defining g_0
        let mut g_vec_0: Vec<GE> = Vec::new();
        g_vec_0.extend_from_slice(&p_vec);
        g_vec_0.extend_from_slice(&g_prime_vec);

        // P -> V: A
        // A = (H' * r_a) + <g_0 * c_L> + <h * c_R>
        let r_A: FE = ECScalar::new_random();
        let H_prime_rA = H_prime * &r_A;
        
        let cL_g0 = g_vec_0.iter().zip(c_L.clone()).fold(H_prime_rA, |acc, x| {
            if x.1 != BigInt::zero() {
                // Mult and Add only if the element cL[i] is not zero
                let cL_i_fe: FE = ECScalar::from(&x.1);
                let cL_i_fe_g_i: GE = x.0 * &cL_i_fe;
                acc.add_point(&cL_i_fe_g_i.get_element())
            } else {
                // move on otherwise
                acc
            }
        });

        let A = h_vec.iter().zip(c_R.clone()).fold(cL_g0, |acc, x| {
            if x.1 != BigInt::zero() {
                let cR_i_fe: FE = ECScalar::from(&x.1);
                let cR_i_fe_h_i: GE = x.0 * &cR_i_fe;
                acc.add_point(&cR_i_fe_h_i.get_element())
            } else {
                acc
            }
        });

        // challenge w
        let challenge_w = HSha256::create_hash_from_ge(&[&A]);
        let challenge_w_fe: FE = ECScalar::from(&challenge_w.to_big_int());

        // defining g_w
        let mut g_vec_w: Vec<GE> = vec![*G, *Gt];
        g_vec_w.extend_from_slice(&Y_hat_vec);
        g_vec_w.push(I_hat);

        g_vec_w = (0..p_len)
            .map(|i| {
                let g_vec_w_mul_w_i: GE = g_vec_w[i] * &challenge_w_fe;
                g_vec_w_mul_w_i.add_point(&p_vec[i].get_element())
            })
            .collect::<Vec<GE>>();
        g_vec_w.extend_from_slice(&g_prime_vec);
        
        // P -> V: S
        // S = (H' * r_s) + <g_w * s_L> + <h * s_R>
        let r_S: FE = ECScalar::new_random();
        let s_R = (0..t).map(|_| ECScalar::new_random()).collect::<Vec<FE>>();
        let s_L = (0..t).map(|_| ECScalar::new_random()).collect::<Vec<FE>>();

        let H_prime_r_S: GE = H_prime * &r_S;
        let sL_gw = (0..t)
            .map(|i| {
                &g_vec_w[i] * &s_L[i]
            })
            .fold(H_prime_r_S, |acc, x| acc + x as GE);
        let S = (0..t)
            .map(|i| {
                &h_vec[i] * &s_R[i]
            })
            .fold(sL_gw, |acc, x| acc + x as GE);

        // challenges y,z
        let y = HSha256::create_hash_from_ge(&[&A, &S]);
        let base_point: GE = ECPoint::generator();
        let yG: GE = base_point * &y;
        let z = HSha256::create_hash_from_ge(&[&A, &S, &yG]);
        let y_bn = y.to_big_int();
        let z_bn = z.to_big_int();

        // generate constraint vectors
        let constraint_vec = Constraints::generate_constraints(u_bn.clone(),
            v_bn.clone(),
            y_bn.clone(),
            z_bn.clone(),
            n.clone(),
            s.clone()
        );

        let theta = constraint_vec.theta.clone();
        let theta_inv = constraint_vec.theta_inv.clone();
        let alpha = constraint_vec.alpha.clone();
        let mu = constraint_vec.mu.clone();
        
        // calculate t2, t1, t0
        let t2 = (0..t)
            .map(|i| {
                let sR_bn = s_R[i].to_big_int();
                let sL_bn = s_L[i].to_big_int();
                let sR_sL = BigInt::mod_mul(&sR_bn, &sL_bn, &order);
                BigInt::mod_mul(&sR_sL, &theta[i], &order)
            })
            .fold(BigInt::zero(), |acc, x| BigInt::mod_add(&acc, &x, &order));
        
        let t1 = (0..t)
            .map(|i| {
                let t1_1 = BigInt::mod_add(&c_L[i], &alpha[i], &order);
                let t1_2 = BigInt::mod_mul(&t1_1, &theta[i], &order);
                let t1_3 = BigInt::mod_mul(&t1_2, &s_R[i].to_big_int(), &order);
                let t1_4 = BigInt::mod_mul(&c_R[i], &theta[i], &order);
                let t1_5 = BigInt::mod_add(&t1_4, &mu[i], &order);
                let t1_6 = BigInt::mod_mul(&t1_5, &s_L[i].to_big_int(), &order);
                BigInt::mod_add(&t1_3, &t1_6, &order)
            })
            .fold(BigInt::zero(), |acc, x| BigInt::mod_add(&acc, &x, &order));  

        // P -> V: T_1, T_2
        let tau1: FE = ECScalar::new_random();
        let tau2: FE = ECScalar::new_random();
        let t1_fe = ECScalar::from(&t1);
        let t2_fe = ECScalar::from(&t2);
        let T1 = G * &t1_fe + H * &tau1;
        let T2 = G * &t2_fe + H * &tau2;

        // generate challenge x
        let challenge_x = HSha256::create_hash_from_ge(&[&A, &S, &yG, &T1, &T2, G, H]);
        let challenge_x_square = challenge_x.mul(&challenge_x.get_element());

        // compute tau_x, r, Lp, Rp, t_hat
        let taux_1 = challenge_x.mul(&tau1.get_element());
        let taux_2 = challenge_x_square.mul(&tau2.get_element());
        let tau_x = taux_1.add(&taux_2.get_element());

        let r = (r_S.mul(&challenge_x.get_element())).add(&r_A.get_element());

        let Lp = (0..t)
            .map(|i| {
                let Lp_1 = (s_L[i].mul(&challenge_x.get_element())).to_big_int();
                let Lp_2 = BigInt::mod_add(&c_L[i], &alpha[i], &order);
                BigInt::mod_add(&Lp_1, &Lp_2, &order)
            })
            .collect::<Vec<BigInt>>();

        let Rp = (0..t)
            .map(|i| {
                let Rp_1 = (s_R[i].mul(&challenge_x.get_element())).to_big_int();
                let Rp_2 = BigInt::mod_add(&c_R[i], &Rp_1, &order);
                let Rp_3 = BigInt::mod_mul(&Rp_2, &theta[i], &order);
                BigInt::mod_add(&Rp_3, &mu[i], &order)
            })
            .collect::<Vec<BigInt>>();

        let t_hat = Lp.iter().zip(&Rp).fold(BigInt::zero(), |acc, x| {
            let Lp_iRp_i = BigInt::mod_mul(x.0, x.1, &order);
            BigInt::mod_add(&acc, &Lp_iRp_i, &order)
        });     

        // Running inner product argument
        let t_hat_fe: FE = ECScalar::from(&t_hat);
        let challenge_x_prime = HSha256::create_hash(&[&tau_x.to_big_int(), &r.to_big_int(), &t_hat]);
        let challenge_x_prime: FE = ECScalar::from(&challenge_x_prime);
        let Gx = G * &challenge_x_prime;

        // P1 = <Lp,Rp> * u
        let P1 = &Gx * &t_hat_fe;
        
        // P2 = P1 + <Lp, g_vec_w>
        let P2 = g_vec_w.iter().zip(&Lp).fold(P1, |acc, x| {
            let g_vec_w_i_lp_i = x.0 * &ECScalar::from(x.1);
            acc + g_vec_w_i_lp_i
        });

        // define hi_tag
        let hi_tag = (0..t)
            .map(|i| {
                let theta_inv_i_fe: FE = ECScalar::from(&theta_inv[i]);
                &h_vec[i] * &theta_inv_i_fe
            })
            .collect::<Vec<GE>>();

        // P = P2 + <Rp, hi_tag>
        let P = hi_tag.iter().zip(&Rp).fold(P2, |acc, x| {
            if x.1 == &BigInt::zero() {
                acc
            }
            else {
                let hi_tag_i_rp_i = x.0 * &ECScalar::from(x.1);
                acc + hi_tag_i_rp_i
            }
        });
        
        // Run ipp for non-power of two secret vectors
        let N = t.next_power_of_two();
        let res = N-t;
        let zero_append_vec = vec![BigInt::zero();res];

        // Append 0s to secret vectors
        let mut a = Lp.clone();
        let mut b = Rp.clone();

        a.extend_from_slice(&zero_append_vec);
        b.extend_from_slice(&zero_append_vec);
        
        let mut g_vec = g_vec_w.clone();
        let mut h_vec_long = hi_tag.clone();
        g_vec.extend_from_slice(&g_vec_append);
        h_vec_long.extend_from_slice(&h_vec_append);

        let L_vec = Vec::with_capacity(n);
        let R_vec = Vec::with_capacity(n);
        let inner_product_proof =
            InnerProductArg::prove(&g_vec[..], &h_vec_long, &Gx, &P, &a, &b, L_vec, R_vec);

        return RevelioBP {
            I_vec,
            C_assets,
            A,
            S,
            T1,
            T2,
            tau_x,
            r,
            t_hat: t_hat_fe,
            inner_product_proof,
            constraint_vec,
        };
    }

    pub fn verify(
        &self,
        // crs
        G: &GE,
        H: &GE,
        Gt: &GE,
        H_prime: &GE,
        p_vec: &[GE],
        g_prime_vec: &[GE],
        h_vec: &[GE],
        g_vec_append: &[GE],
        h_vec_append: &[GE],
        // stmt
        C_vec: &[GE],
    ) -> Result<(), Errors> {

        // vector lengths
        let n = C_vec.len();
        let s = self.I_vec.len();
        let t = s*n + n + s + 3;
        let p_len = n+3;
        
        // other prelims
        let order = FE::q();

        // computed C_assets from I_vec
        let C_assets_comp = (1..s)
            .map(|i| &self.I_vec[i])
            .fold(self.I_vec[0], |acc, x| acc + x);

        // re-generate challenges u, v, y, z
        let u = HSha256::create_hash_from_ge(&[G, H, Gt]);
        let u_bn = u.to_big_int();
        let base_point: GE = ECPoint::generator();
        let uG: GE = base_point * &u;
        let v = HSha256::create_hash_from_ge(&[&uG]);
        let v_bn = v.to_big_int();   

        let y = HSha256::create_hash_from_ge(&[&self.A, &self.S]);
        let base_point: GE = ECPoint::generator();
        let yG: GE = base_point * &y;
        let y_bn = y.to_big_int();
        
        let z = HSha256::create_hash_from_ge(&[&self.A, &self.S, &yG]);
        let z_bn = z.to_big_int();
        
        let constraint_vec = Constraints::generate_constraints(u_bn.clone(),
            v_bn.clone(),
            y_bn.clone(),
            z_bn.clone(),
            n.clone(),
            s.clone()
        );

        // independently computing constraints 
        let theta_inv = constraint_vec.theta_inv.clone();
        let alpha = constraint_vec.alpha.clone();
        let delta = constraint_vec.delta.clone();
        let beta = constraint_vec.beta.clone();

        // // we are using already computed constraint vectors by prover
        // let theta_inv = self.constraint_vec.theta_inv.clone();
        // let alpha = self.constraint_vec.alpha.clone();
        // let delta = self.constraint_vec.delta.clone();
        // let beta = self.constraint_vec.beta.clone();     

        // verification equation #2
        // lhs
        let Gt_hat = G * &self.t_hat;
        let Htau_x = H * &self.tau_x;
        let left_side = Gt_hat + Htau_x;

        // rhs
        // re-generate challenge x
        let challenge_x = HSha256::create_hash_from_ge(&[&self.A, &self.S, &yG, &self.T1, &self.T2, G, H]);
        let challenge_x_square = challenge_x.mul(&challenge_x.get_element());

        let delta_fe: FE = ECScalar::from(&delta);
        let Gdelta = G * &delta_fe;
        let Tx = &self.T1 * &challenge_x;
        let Tx_sq = &self.T2 * &challenge_x_square;
        let right_side = Gdelta + Tx + Tx_sq;

        // towards verification eqn #3
        // re-generate challenge w, x'
        let challenge_w = HSha256::create_hash_from_ge(&[&self.A]);
        let challenge_w_fe: FE = ECScalar::from(&challenge_w.to_big_int());

        let challenge_x_prime = HSha256::create_hash(&[
            &self.tau_x.to_big_int(),
            &self.r.to_big_int(),
            &self.t_hat.to_big_int(),
        ]);
        let challenge_x_prime: FE = ECScalar::from(&challenge_x_prime);
        let Gx = G * &challenge_x_prime;   

        // define compressed stmt
        let Y_hat: &[GE] = C_vec;
        let Y_hat_vec = Y_hat.to_vec();

        let minus1 = BigInt::mod_sub(&BigInt::zero(), &BigInt::one(), &order);
        let I0_inv = self.I_vec[0] * &(ECScalar::from(&minus1));
        let I_hat: GE = (1..s)
            .map(|i| {
                let u_i = BigInt::mod_pow(&u_bn, &BigInt::from(i as u32), &order);
                let minus_ui = BigInt::mod_sub(&BigInt::zero(), &u_i, &order);
                let u_i_fe: FE = ECScalar::from(&minus_ui);
                self.I_vec[i] * &u_i_fe
            })
            .fold(I0_inv, |acc, x| acc.add_point(&x.get_element()));
            
        // defining g_w
        let mut g_vec_w: Vec<GE> = vec![*G, *Gt];
        g_vec_w.extend_from_slice(&Y_hat_vec);
        g_vec_w.push(I_hat);

        g_vec_w = (0..p_len)
            .map(|i| {
                let g_vec_w_mul_w_i: GE = g_vec_w[i] * &challenge_w_fe;
                g_vec_w_mul_w_i.add_point(&p_vec[i].get_element())
            })
            .collect::<Vec<GE>>();
        g_vec_w.extend_from_slice(&g_prime_vec);

        // compute generator hi_tag
        let hi_tag = (0..t)
            .map(|i| {
                let theta_inv_i_fe: FE = ECScalar::from(&theta_inv[i]);
                &h_vec[i] * &theta_inv_i_fe
            })
            .collect::<Vec<GE>>();

        // compute a commitment to l(x),r(x)
        // P' = u^{xc}
        let P1_prime = &Gx * &self.t_hat;
        let minus_r = BigInt::mod_sub(&BigInt::zero(), &self.r.to_big_int(), &FE::q());
        let minus_r_fe: FE = ECScalar::from(&minus_r);
        let Hr = H_prime * &minus_r_fe;
        let Sx = &self.S * &challenge_x;
        let P1 = Hr + P1_prime + self.A.clone() + Sx;

        let P_1 = g_vec_w.iter().zip(&alpha).fold(P1, |acc, x| {
            if x.1 != &BigInt::zero() {
                let alphai: FE = ECScalar::from(&x.1);
                let alpha_gvec_i: GE = x.0 * &alphai;
                acc.add_point(&alpha_gvec_i.get_element())
            } else {
                acc
            }
        });

        let P = h_vec.iter().zip(&beta).fold(P_1, |acc, x| {
            if x.1 != &BigInt::zero() {
                let betai: FE = ECScalar::from(&x.1);
                let beta_gvec_i: GE = x.0 * &betai;
                acc.add_point(&beta_gvec_i.get_element())
            } else {
                acc
            }
        });
        
        let mut g_vec = g_vec_w.clone();
        let mut h_vec_long = hi_tag.clone();
        g_vec.extend_from_slice(&g_vec_append);
        h_vec_long.extend_from_slice(&h_vec_append);

        let verify = self.inner_product_proof.fast_verify(&g_vec, &h_vec_long, &Gx, &P);

        // check all three conditions are true
        if verify.is_ok() && C_assets_comp==self.C_assets && left_side==right_side{
            Ok(())
        } else {
            Err(RevelioBPError)
        }
    }

    pub fn gen_params(n: usize, s: usize) -> (
        GE, GE, GE, GE,
        Vec<GE>, Vec<GE>, Vec<GE>, Vec<GE>, Vec<GE>, Vec<GE>,
        Vec<BigInt>, Vec<FE>, Vec<FE>
    ){

        let sn = s * n;
        let t = sn + n + s + 3;
        let amt_bit_range = 8;
        let one = BigInt::from(1);
        let N = t.next_power_of_two();
        let res = N-t;
        
        // sigma_t equals the block height 
        let block_ht: u32 = 100; 

        // generate random amounts in range {0,..,2^{amt_bit_range}}
        let range = BigInt::from(2).pow(amt_bit_range as u32);
        let a_vec = (0..s)
            .map(|_| ECScalar::from(&BigInt::sample_range(&one, &range)))
            .collect::<Vec<FE>>();
        
        // generate blinding factors
        let r_vec = (0..s).map(|_| ECScalar::new_random()).collect::<Vec<FE>>();
        
        // G, H, Gt - curve points for generating outputs and key-images
        let G: GE = ECPoint::generator();
        let label1 = BigInt::from(1);
        let hash1 = HSha512::create_hash(&[&label1]);
        let H = generate_random_point(&Converter::to_vec(&hash1));
        let label2 = BigInt::from(block_ht);
        let hash2 = HSha512::create_hash(&[&label2]);
        let Gt = generate_random_point(&Converter::to_vec(&hash2));
          
        let label2 = BigInt::from(2);
        let hash2 = HSha512::create_hash(&[&label2]);
        let H_prime = generate_random_point(&Converter::to_vec(&hash2));   

        // generate p_vec, g_prime_vec, h_vec
        let p_len = n+3;
        let g_prime_len = t-p_len;
        let h_len = t;

        let order = FE::q();
        let order_sq = BigInt::mod_mul(&order, &order, &order);
        let order_cube = BigInt::mod_mul(&order_sq, &order, &order);
        let order_four = BigInt::mod_mul(&order_cube, &order, &order);
        let order_five = BigInt::mod_mul(&order_four, &order, &order);
        let q_hash = HSha256::create_hash(&[&order]);
        let q_sq_hash = HSha256::create_hash(&[&order_sq]);
        let q_cube_hash = HSha256::create_hash(&[&order_cube]);
        let q_four_hash = HSha256::create_hash(&[&order_four]);
        let q_five_hash = HSha256::create_hash(&[&order_five]);

        let p_vec = (0..p_len)
            .map(|i| {
                let label_i = BigInt::from(i as u32) + q_hash.clone();
                let hash_i = HSha512::create_hash(&[&label_i]);
                generate_random_point(&Converter::to_vec(&hash_i))
            })
            .collect::<Vec<GE>>();

        let g_prime_vec = (0..g_prime_len)
            .map(|i| {
                let label_i = BigInt::from(i as u32) + q_sq_hash.clone();
                let hash_i = HSha512::create_hash(&[&label_i]);
                generate_random_point(&Converter::to_vec(&hash_i))
            })
            .collect::<Vec<GE>>();

        let h_vec = (0..h_len)
            .map(|i| {
                let label_i = BigInt::from(i as u32) + q_cube_hash.clone();
                let hash_i = HSha512::create_hash(&[&label_i]);
                generate_random_point(&Converter::to_vec(&hash_i))
            })
            .collect::<Vec<GE>>();

        // Append random group generators to g_vec_w and hi_tag
        let g_vec_append = (0..res)
            .map(|i| {
                let rString_label_i = BigInt::from(i as u32) +q_four_hash.clone();
                let hash_i = HSha256::create_hash(&[&rString_label_i]);
                generate_random_point(&Converter::to_vec(&hash_i))
            })
            .collect::<Vec<GE>>();

        let h_vec_append = (0..res)
            .map(|i| {
                let rString_label_i = BigInt::from(i as u32) + q_five_hash.clone();
                let hash_i = HSha256::create_hash(&[&rString_label_i]);
                generate_random_point(&Converter::to_vec(&hash_i))
            })
            .collect::<Vec<GE>>();

        // Select random outputs owned by the exchange
        let mut C_vec_mut: Vec<GE> = (0..n).map(|_| G).collect::<Vec<GE>>();
        
        // generate random index vector of size s
        let mut rng = rand::thread_rng();
        let setsize = n / s;
        let mut start_idx = 0;
        let mut end_idx = cmp::max(1, setsize-1);
        let idx = (0..s).map(|_| {
            
            let dist1 = Uniform::from(start_idx..end_idx);
            start_idx = setsize + start_idx;
            end_idx =  cmp::min(n-1, end_idx + setsize);

            dist1.sample(&mut rng)
        })
        .collect::<Vec<usize>>();

        let mut index = 0;
        let E_vec = (0..n)
            .map(|i| {
                if index < idx.len() {
                    if i == idx[index] {
                        // generate commitments using a_vec, r_vec
                        C_vec_mut[i as usize] = G * &r_vec[index] + H * &a_vec[index];
                        index = index + 1;
                        one.clone()
                    }
                    else {
                        BigInt::zero()
                    }
                }
                else{
                    BigInt::zero()
                }
            })
            .collect::<Vec<BigInt>>();  

        (G, H, Gt, H_prime, p_vec, g_prime_vec, h_vec, g_vec_append, h_vec_append, C_vec_mut, E_vec, a_vec, r_vec)

    }
}

pub fn generate_random_point(bytes: &[u8]) -> GE {
    let result: Result<GE, _> = ECPoint::from_bytes(&bytes);
    if result.is_ok() {
        return result.unwrap();
    } else {
        let two = BigInt::from(2);
        let bn = BigInt::from(bytes);
        let bn_times_two = BigInt::mod_mul(&bn, &two, &FE::q());
        let bytes = BigInt::to_vec(&bn_times_two);
        return generate_random_point(&bytes);
    }
}

#[cfg(test)]
mod tests {
    
    use curv::arithmetic::traits::{Converter, Modulo, Samplable};
    use curv::cryptographic_primitives::hashing::hash_sha256::HSha256;
    use curv::cryptographic_primitives::hashing::hash_sha512::HSha512;
    use curv::cryptographic_primitives::hashing::traits::*;
    use curv::elliptic::curves::traits::*;
    use curv::BigInt;
    use curv::{FE, GE};
    use proofs::revelio_bp::generate_random_point;
    use proofs::revelio_bp::RevelioBP;
    use rand::distributions::{Distribution, Uniform};
    use std::cmp;
    use time::PreciseTime;

    #[test]
    pub fn test_revelio_plus_aok_1_in_8(){
        
        let n=8;
        let s=1;
        let sn = s * n;
        let t = sn + n + s + 3;
        let amt_bit_range = 8;
        let one = BigInt::from(1);
        let N = (t as u64).next_power_of_two();
        let res = N-t;
        
        // sigma_t equals the block height 
        let block_ht: u32 = 100; 

        // generate random amounts in range {0,..,2^{amt_bit_range}}
        let range = BigInt::from(2).pow(amt_bit_range as u32);
        let a_vec = (0..s)
            .map(|_| ECScalar::from(&BigInt::sample_range(&one, &range)))
            .collect::<Vec<FE>>();
        
        // generate blinding factors
        let r_vec = (0..s).map(|_| ECScalar::new_random()).collect::<Vec<FE>>();
        
        // G, H, Gt - curve points for generating outputs and key-images
        let G: GE = ECPoint::generator();
        let label1 = BigInt::from(1);
        let hash1 = HSha512::create_hash(&[&label1]);
        let H = generate_random_point(&Converter::to_vec(&hash1));
        let label2 = BigInt::from(block_ht);
        let hash2 = HSha512::create_hash(&[&label2]);
        let Gt = generate_random_point(&Converter::to_vec(&hash2));
          
        let label2 = BigInt::from(2);
        let hash2 = HSha512::create_hash(&[&label2]);
        let H_prime = generate_random_point(&Converter::to_vec(&hash2));   

        // generate p_vec, g_prime_vec, h_vec
        let p_len = n+3;
        let g_prime_len = t-p_len;
        let h_len = t;

        let order = FE::q();
        let order_sq = BigInt::mod_mul(&order, &order, &order);
        let order_cube = BigInt::mod_mul(&order_sq, &order, &order);
        let order_four = BigInt::mod_mul(&order_cube, &order, &order);
        let order_five = BigInt::mod_mul(&order_four, &order, &order);
        let q_hash = HSha256::create_hash(&[&order]);
        let q_sq_hash = HSha256::create_hash(&[&order_sq]);
        let q_cube_hash = HSha256::create_hash(&[&order_cube]);
        let q_four_hash = HSha256::create_hash(&[&order_four]);
        let q_five_hash = HSha256::create_hash(&[&order_five]);

        let p_vec = (0..p_len)
            .map(|i| {
                let label_i = BigInt::from(i as u32) + q_hash.clone();
                let hash_i = HSha512::create_hash(&[&label_i]);
                generate_random_point(&Converter::to_vec(&hash_i))
            })
            .collect::<Vec<GE>>();

        let g_prime_vec = (0..g_prime_len)
            .map(|i| {
                let label_i = BigInt::from(i as u32) + q_sq_hash.clone();
                let hash_i = HSha512::create_hash(&[&label_i]);
                generate_random_point(&Converter::to_vec(&hash_i))
            })
            .collect::<Vec<GE>>();

        let h_vec = (0..h_len)
            .map(|i| {
                let label_i = BigInt::from(i as u32) + q_cube_hash.clone();
                let hash_i = HSha512::create_hash(&[&label_i]);
                generate_random_point(&Converter::to_vec(&hash_i))
            })
            .collect::<Vec<GE>>();

        // Append random group generators to g_vec_w and hi_tag
        let g_vec_append = (0..res)
            .map(|i| {
                let rString_label_i = BigInt::from(i as u32) +q_four_hash.clone();
                let hash_i = HSha256::create_hash(&[&rString_label_i]);
                generate_random_point(&Converter::to_vec(&hash_i))
            })
            .collect::<Vec<GE>>();

        let h_vec_append = (0..res)
            .map(|i| {
                let rString_label_i = BigInt::from(i as u32) + q_five_hash.clone();
                let hash_i = HSha256::create_hash(&[&rString_label_i]);
                generate_random_point(&Converter::to_vec(&hash_i))
            })
            .collect::<Vec<GE>>();

        // Select random outputs owned by the exchange
        let mut C_vec_mut: Vec<GE> = (0..n)
            .map(|_| {
                G
            })
            .collect::<Vec<GE>>();
        
        let idx = vec![7];
        let mut index = 0;
        let E_vec = (0..n)
            .map(|i| {
                if index < idx.len() {
                    if i == idx[index] {
                        // generate commitments using a_vec, r_vec
                        C_vec_mut[i as usize] = G * &r_vec[index] + H * &a_vec[index];
                        index = index + 1;
                        one.clone()
                    }
                    else {
                        BigInt::zero()
                    }
                }
                else{
                    BigInt::zero()
                }
            })
            .collect::<Vec<BigInt>>();

        let revelio_test = RevelioBP::prove(&G, &H, &Gt, &H_prime, &p_vec, &g_prime_vec, &h_vec, &g_vec_append, &h_vec_append, &C_vec_mut, &E_vec, &a_vec, &r_vec);
        let result = revelio_test.verify(&G, &H, &Gt, &H_prime, &p_vec, &g_prime_vec, &h_vec, &g_vec_append, &h_vec_append, &C_vec_mut);
        assert!(result.is_ok());
    }

    pub fn test_revelio_plus_helper(n: usize, s: usize){
        
        let sn = s * n;
        let t = sn + n + s + 3;
        let amt_bit_range = 8;
        let one = BigInt::from(1);
        let N = t.next_power_of_two();
        let res = N-t;
        
        // sigma_t equals the block height 
        let block_ht: u32 = 100; 

        // generate random amounts in range {0,..,2^{amt_bit_range}}
        let range = BigInt::from(2).pow(amt_bit_range as u32);
        let a_vec = (0..s)
            .map(|_| ECScalar::from(&BigInt::sample_range(&one, &range)))
            .collect::<Vec<FE>>();
        
        // generate blinding factors
        let r_vec = (0..s).map(|_| ECScalar::new_random()).collect::<Vec<FE>>();
        
        // G, H, Gt - curve points for generating outputs and key-images
        let G: GE = ECPoint::generator();
        let label1 = BigInt::from(1);
        let hash1 = HSha512::create_hash(&[&label1]);
        let H = generate_random_point(&Converter::to_vec(&hash1));
        let label2 = BigInt::from(block_ht);
        let hash2 = HSha512::create_hash(&[&label2]);
        let Gt = generate_random_point(&Converter::to_vec(&hash2));
          
        let label2 = BigInt::from(2);
        let hash2 = HSha512::create_hash(&[&label2]);
        let H_prime = generate_random_point(&Converter::to_vec(&hash2));   

        // generate p_vec, g_prime_vec, h_vec
        let p_len = n+3;
        let g_prime_len = t-p_len;
        let h_len = t;

        let order = FE::q();
        let order_sq = BigInt::mod_mul(&order, &order, &order);
        let order_cube = BigInt::mod_mul(&order_sq, &order, &order);
        let order_four = BigInt::mod_mul(&order_cube, &order, &order);
        let order_five = BigInt::mod_mul(&order_four, &order, &order);
        let q_hash = HSha256::create_hash(&[&order]);
        let q_sq_hash = HSha256::create_hash(&[&order_sq]);
        let q_cube_hash = HSha256::create_hash(&[&order_cube]);
        let q_four_hash = HSha256::create_hash(&[&order_four]);
        let q_five_hash = HSha256::create_hash(&[&order_five]);

        let p_vec = (0..p_len)
            .map(|i| {
                let label_i = BigInt::from(i as u32) + q_hash.clone();
                let hash_i = HSha512::create_hash(&[&label_i]);
                generate_random_point(&Converter::to_vec(&hash_i))
            })
            .collect::<Vec<GE>>();

        let g_prime_vec = (0..g_prime_len)
            .map(|i| {
                let label_i = BigInt::from(i as u32) + q_sq_hash.clone();
                let hash_i = HSha512::create_hash(&[&label_i]);
                generate_random_point(&Converter::to_vec(&hash_i))
            })
            .collect::<Vec<GE>>();

        let h_vec = (0..h_len)
            .map(|i| {
                let label_i = BigInt::from(i as u32) + q_cube_hash.clone();
                let hash_i = HSha512::create_hash(&[&label_i]);
                generate_random_point(&Converter::to_vec(&hash_i))
            })
            .collect::<Vec<GE>>();

        // Append random group generators to g_vec_w and hi_tag
        let g_vec_append = (0..res)
            .map(|i| {
                let rString_label_i = BigInt::from(i as u32) +q_four_hash.clone();
                let hash_i = HSha256::create_hash(&[&rString_label_i]);
                generate_random_point(&Converter::to_vec(&hash_i))
            })
            .collect::<Vec<GE>>();

        let h_vec_append = (0..res)
            .map(|i| {
                let rString_label_i = BigInt::from(i as u32) + q_five_hash.clone();
                let hash_i = HSha256::create_hash(&[&rString_label_i]);
                generate_random_point(&Converter::to_vec(&hash_i))
            })
            .collect::<Vec<GE>>();

        // Select random outputs owned by the exchange
        let mut C_vec_mut: Vec<GE> = (0..n).map(|_| G).collect::<Vec<GE>>();
        
        // generate random index vector of size s
        let mut rng = rand::thread_rng();
        let setsize = n / s;
        let mut start_idx = 0;
        let mut end_idx = cmp::max(1, setsize-1);
        let idx = (0..s).map(|_| {
            
            let dist1 = Uniform::from(start_idx..end_idx);
            start_idx = setsize + start_idx;
            end_idx =  cmp::min(n-1, end_idx + setsize);

            dist1.sample(&mut rng)
        })
        .collect::<Vec<usize>>();

        // println!("idx {:?}", idx);

        let mut index = 0;
        let E_vec = (0..n)
            .map(|i| {
                if index < idx.len() {
                    if i == idx[index] {
                        // generate commitments using a_vec, r_vec
                        C_vec_mut[i as usize] = G * &r_vec[index] + H * &a_vec[index];
                        index = index + 1;
                        one.clone()
                    }
                    else {
                        BigInt::zero()
                    }
                }
                else{
                    BigInt::zero()
                }
            })
            .collect::<Vec<BigInt>>();
        
        let revelio_test = RevelioBP::prove(&G, &H, &Gt, &H_prime, &p_vec, &g_prime_vec, &h_vec, &g_vec_append, &h_vec_append, &C_vec_mut, &E_vec, &a_vec, &r_vec);
        let result = revelio_test.verify(&G, &H, &Gt, &H_prime, &p_vec, &g_prime_vec, &h_vec, &g_vec_append, &h_vec_append, &C_vec_mut);
        
        assert!(result.is_ok());
    }

    pub fn rPlus_simulation_helper(n: usize, s: usize){
        
        let sn = s * n;
        let t = sn + n + s + 3;
        let amt_bit_range = 8;
        let one = BigInt::from(1);
        let N = t.next_power_of_two();
        let res = N-t;
        
        // sigma_t equals the block height 
        let block_ht: u32 = 100; 

        // generate random amounts in range {0,..,2^{amt_bit_range}}
        let range = BigInt::from(2).pow(amt_bit_range as u32);
        let a_vec = (0..s)
            .map(|_| ECScalar::from(&BigInt::sample_range(&one, &range)))
            .collect::<Vec<FE>>();
        
        // generate blinding factors
        let r_vec = (0..s).map(|_| ECScalar::new_random()).collect::<Vec<FE>>();
        
        // G, H, Gt - curve points for generating outputs and key-images
        let G: GE = ECPoint::generator();
        let label1 = BigInt::from(1);
        let hash1 = HSha512::create_hash(&[&label1]);
        let H = generate_random_point(&Converter::to_vec(&hash1));
        let label2 = BigInt::from(block_ht);
        let hash2 = HSha512::create_hash(&[&label2]);
        let Gt = generate_random_point(&Converter::to_vec(&hash2));
          
        let label2 = BigInt::from(2);
        let hash2 = HSha512::create_hash(&[&label2]);
        let H_prime = generate_random_point(&Converter::to_vec(&hash2));   

        // generate p_vec, g_prime_vec, h_vec
        let p_len = n+3;
        let g_prime_len = t-p_len;
        let h_len = t;

        let order = FE::q();
        let order_sq = BigInt::mod_mul(&order, &order, &order);
        let order_cube = BigInt::mod_mul(&order_sq, &order, &order);
        let order_four = BigInt::mod_mul(&order_cube, &order, &order);
        let order_five = BigInt::mod_mul(&order_four, &order, &order);
        let q_hash = HSha256::create_hash(&[&order]);
        let q_sq_hash = HSha256::create_hash(&[&order_sq]);
        let q_cube_hash = HSha256::create_hash(&[&order_cube]);
        let q_four_hash = HSha256::create_hash(&[&order_four]);
        let q_five_hash = HSha256::create_hash(&[&order_five]);

        let p_vec = (0..p_len)
            .map(|i| {
                let label_i = BigInt::from(i as u32) + q_hash.clone();
                let hash_i = HSha512::create_hash(&[&label_i]);
                generate_random_point(&Converter::to_vec(&hash_i))
            })
            .collect::<Vec<GE>>();

        let g_prime_vec = (0..g_prime_len)
            .map(|i| {
                let label_i = BigInt::from(i as u32) + q_sq_hash.clone();
                let hash_i = HSha512::create_hash(&[&label_i]);
                generate_random_point(&Converter::to_vec(&hash_i))
            })
            .collect::<Vec<GE>>();

        let h_vec = (0..h_len)
            .map(|i| {
                let label_i = BigInt::from(i as u32) + q_cube_hash.clone();
                let hash_i = HSha512::create_hash(&[&label_i]);
                generate_random_point(&Converter::to_vec(&hash_i))
            })
            .collect::<Vec<GE>>();

        // Append random group generators to g_vec_w and hi_tag
        let g_vec_append = (0..res)
            .map(|i| {
                let rString_label_i = BigInt::from(i as u32) +q_four_hash.clone();
                let hash_i = HSha256::create_hash(&[&rString_label_i]);
                generate_random_point(&Converter::to_vec(&hash_i))
            })
            .collect::<Vec<GE>>();

        let h_vec_append = (0..res)
            .map(|i| {
                let rString_label_i = BigInt::from(i as u32) + q_five_hash.clone();
                let hash_i = HSha256::create_hash(&[&rString_label_i]);
                generate_random_point(&Converter::to_vec(&hash_i))
            })
            .collect::<Vec<GE>>();

        // Select random outputs owned by the exchange
        let mut C_vec_mut: Vec<GE> = (0..n).map(|_| G).collect::<Vec<GE>>();
        
        // generate random index vector of size s
        let mut rng = rand::thread_rng();
        let setsize = n / s;
        let mut start_idx = 0;
        let mut end_idx = cmp::max(1, setsize-1);
        let idx = (0..s).map(|_| {
            
            let dist1 = Uniform::from(start_idx..end_idx);
            start_idx = setsize + start_idx;
            end_idx =  cmp::min(n-1, end_idx + setsize);

            dist1.sample(&mut rng)
        })
        .collect::<Vec<usize>>();

        // println!("idx {:?}", idx);

        let mut index = 0;
        let E_vec = (0..n)
            .map(|i| {
                if index < idx.len() {
                    if i == idx[index] {
                        // generate commitments using a_vec, r_vec
                        C_vec_mut[i as usize] = G * &r_vec[index] + H * &a_vec[index];
                        index = index + 1;
                        one.clone()
                    }
                    else {
                        BigInt::zero()
                    }
                }
                else{
                    BigInt::zero()
                }
            })
            .collect::<Vec<BigInt>>();
        
        println!("({}, {})", n, s);
        let start = PreciseTime::now();
        let revelio_test = RevelioBP::prove(&G, &H, &Gt, &H_prime, &p_vec, &g_prime_vec, &h_vec, &g_vec_append, &h_vec_append, &C_vec_mut, &E_vec, &a_vec, &r_vec);
        let end = PreciseTime::now();
        println!("{:?}", start.to(end));

        let start = PreciseTime::now();
        let result = revelio_test.verify(&G, &H, &Gt, &H_prime, &p_vec, &g_prime_vec, &h_vec, &g_vec_append, &h_vec_append, &C_vec_mut);
        let end = PreciseTime::now();
        println!("{:?}", start.to(end));

        assert!(result.is_ok());
        
    }

    #[test]
    fn rPlus_2_in_100(){
        test_revelio_plus_helper(100, 2);
    }
    
    #[test]
    fn rPlus_5_in_100(){
        test_revelio_plus_helper(100, 5);
    }

    #[test]
    fn rPlus_4_in_500(){
        test_revelio_plus_helper(500, 4);
    }

    #[test]
    fn rPlus_19_in_20(){
        test_revelio_plus_helper(20, 19);
    }

    #[test]
    fn rPlus_simulation(){
        println!("Format:");
        println!("(UTXO set size, Own set size)");
        println!("<generation time>");
        println!("<verification time>\n");

        // Data for (Gen,Ver) vs (s) for constant n 
        // rPlus_simulation_helper(1000,10);
        // rPlus_simulation_helper(1000,50);
        // rPlus_simulation_helper(1000,100);
        // rPlus_simulation_helper(1000,200);
        // rPlus_simulation_helper(1000,500);
        // rPlus_simulation_helper(1000,800);

        // Data for (Gen,Ver) vs (n) for constant s 
        rPlus_simulation_helper(100,20);
        rPlus_simulation_helper(200,20);
        // rPlus_simulation_helper(400,20);
        // rPlus_simulation_helper(800,20);
        // rPlus_simulation_helper(1600,20);
        // rPlus_simulation_helper(3200,20);
        // rPlus_simulation_helper(6400,20);
        // rPlus_simulation_helper(12800,20);
        // rPlus_simulation_helper(25600,20);
        // rPlus_simulation_helper(51200,20);
        // rPlus_simulation_helper(102400,20);
    }
}
