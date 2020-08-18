#![allow(non_snake_case)]

#[macro_use]
extern crate criterion;
extern crate revelioBP;

mod bench_reveliobp {
    use revelioBP::proofs::revelio_bp::RevelioBP;
    use criterion::Criterion;

    static OWN_SET_SIZES: [usize; 5] = [5, 10, 20, 50, 80];

    fn create_reveliobp_helper(n: usize, c: &mut Criterion) {
        let label = format!("Create RevelioBP proofs with n={} and s=", n);

        c.bench_function_over_inputs(
            &label,
            move |b, &&s| {

                // create artificial crs and wit
                let (G, H, Gt, 
                    H_prime, 
                    p_vec, 
                    g_prime_vec, 
                    h_vec, 
                    g_vec_append, 
                    h_vec_append, 
                    C_vec_mut, 
                    E_vec, 
                    a_vec, 
                    r_vec) 
                    = RevelioBP::gen_params(n, s);

                
                b.iter(|| {
                    RevelioBP::prove(&G, &H, &Gt, 
                        &H_prime, 
                        &p_vec, 
                        &g_prime_vec, 
                        &h_vec, 
                        &g_vec_append, 
                        &h_vec_append, 
                        &C_vec_mut,
                        &E_vec, 
                        &a_vec,
                        &r_vec);
                })
            },
            &OWN_SET_SIZES,
        );
    }

    fn verify_reveliobp_helper(n: usize, c: &mut Criterion) {
        let label = format!("Verify RevelioBP proofs with n={} and s=", n);

        c.bench_function_over_inputs(
            &label,
            move |b, &&s| {

                // create artificial crs and wit
                let (G, H, Gt, 
                    H_prime, 
                    p_vec, 
                    g_prime_vec, 
                    h_vec, 
                    g_vec_append, 
                    h_vec_append, 
                    C_vec_mut, 
                    E_vec, 
                    a_vec, 
                    r_vec) 
                    = RevelioBP::gen_params(n, s);

                let reveliobp_proof = RevelioBP::prove(&G, &H, &Gt, 
                    &H_prime, 
                    &p_vec, 
                    &g_prime_vec, 
                    &h_vec, 
                    &g_vec_append, 
                    &h_vec_append, 
                    &C_vec_mut,
                    &E_vec, 
                    &a_vec,
                    &r_vec);
                
                b.iter(|| {
                    let result = reveliobp_proof.verify(&G, &H, &Gt, 
                        &H_prime, 
                        &p_vec, 
                        &g_prime_vec, 
                        &h_vec, 
                        &g_vec_append, 
                        &h_vec_append, 
                        &C_vec_mut);
                        
                    assert!(result.is_ok());
                })
            },
            &OWN_SET_SIZES,
        );
    }

    fn fast_verify_reveliobp_helper(n: usize, c: &mut Criterion) {
        let label = format!("Fast Verify RevelioBP proofs with n={} and s=", n);

        c.bench_function_over_inputs(
            &label,
            move |b, &&s| {

                // create artificial crs and wit
                let (G, H, Gt, 
                    H_prime, 
                    p_vec, 
                    g_prime_vec, 
                    h_vec, 
                    g_vec_append, 
                    h_vec_append, 
                    C_vec_mut, 
                    E_vec, 
                    a_vec, 
                    r_vec) 
                    = RevelioBP::gen_params(n, s);

                let reveliobp_proof = RevelioBP::prove(&G, &H, &Gt, 
                    &H_prime, 
                    &p_vec, 
                    &g_prime_vec, 
                    &h_vec, 
                    &g_vec_append, 
                    &h_vec_append, 
                    &C_vec_mut,
                    &E_vec, 
                    &a_vec,
                    &r_vec);
                
                b.iter(|| {
                    let result = reveliobp_proof.fast_verify(&G, &H, &Gt, 
                        &H_prime, 
                        &p_vec, 
                        &g_prime_vec, 
                        &h_vec, 
                        &g_vec_append, 
                        &h_vec_append, 
                        &C_vec_mut);
                        
                    assert!(result.is_ok());
                })
            },
            &OWN_SET_SIZES,
        );
    }

    pub fn create_reveliobp_100(c: &mut Criterion) {
        create_reveliobp_helper(100, c);
    }

    pub fn verify_reveliobp_100(c: &mut Criterion) {
        verify_reveliobp_helper(100, c);
    }

    pub fn fast_verify_reveliobp_100(c: &mut Criterion) {
        fast_verify_reveliobp_helper(100, c);
    }

    criterion_group! {
    name = reveliobp;
    config = Criterion::default().sample_size(10);
    targets =
        create_reveliobp_100,
        verify_reveliobp_100,
        fast_verify_reveliobp_100,
    }

}

//fn main() {}
criterion_main!(
    bench_reveliobp::reveliobp,
);

