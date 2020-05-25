#![allow(non_snake_case)]

extern crate structopt;
extern crate revelioPlus;

use structopt::StructOpt;
use std::time::{Instant, Duration};
use revelioPlus::proofs::revelio_plus::RevelioPlus;

#[derive(Debug, StructOpt)]
#[structopt(name = "revelio_plus", about = "RevelioPlus proof generation simulator using curv library.")]
struct Opt {
  //#[structopt(short = "a", long = "anonsize")]
  anon_list_size: usize,
  //#[structopt(short = "o", long = "ownsize")]
  own_list_size: usize,
  #[structopt(short = "n", long = "numiter", default_value = "1")]
  num_iter: u32,
}

fn main() {
    // 
    // cargo run --release --bin revelio_plus_bin 1000 100 -n 10
    //
    let opt = Opt::from_args();

    let num_iter = opt.num_iter;
    let mut gen_proof_start;
    let mut gen_proof_end;
    let mut ver_proof_start;
    let mut ver_proof_end;
    let mut total_gen_proof_duration = Duration::new(0, 0);
    let mut total_ver_proof_duration = Duration::new(0, 0);

    let (G, H, Gt, H_prime, p_vec, g_prime_vec, h_vec, g_vec_append, h_vec_append, C_vec_mut, E_vec, a_vec, r_vec) = RevelioPlus::gen_params(opt.anon_list_size, opt.own_list_size);

    let sim_start = Instant::now();

    for _i in 0..num_iter {    
    
        gen_proof_start = Instant::now();
        let revelio_plus_proof = RevelioPlus::prove(&G, &H, &Gt, &H_prime, &p_vec, &g_prime_vec, &h_vec, &g_vec_append, &h_vec_append, &C_vec_mut, &E_vec, &a_vec, &r_vec);
        gen_proof_end = Instant::now();
        total_gen_proof_duration += gen_proof_end.duration_since(gen_proof_start);
  
        ver_proof_start = Instant::now();
        let result = revelio_plus_proof.verify(&G, &H, &Gt, &H_prime, &p_vec, &g_prime_vec, &h_vec, &g_vec_append, &h_vec_append, &C_vec_mut);
        assert!(result.is_ok());
        ver_proof_end = Instant::now();
        total_ver_proof_duration += ver_proof_end.duration_since(ver_proof_start);
      }
  
      let sim_end = Instant::now();
      println!("Total simulation time = {:?}", sim_end.duration_since(sim_start));
  
      println!("Options = {:?}", opt);
      println!("Average proof generation time = {:?}",
        total_gen_proof_duration.checked_div(num_iter).unwrap());
      println!("Average proof verification time = {:?}",
        total_ver_proof_duration.checked_div(num_iter).unwrap());

}
