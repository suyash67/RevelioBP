# RevelioBP - Short, Privacy-preserving MimbleWimble Proof of Reserves Protocol

RevelioBP is a proof of reserves protocol designed for MimbleWimble based cryptocurrencies.
It in proposed in a paper titled [Performance Trade-offs in Design of MimbleWimble Proofs of Reserves](https://tobeadded.com) which is to appear at *[IEEE Security & Privacy on Blockchain](https://ieeesb.org/)*, 2020.

RevelioBP is a *log-sized* proof of reserves protocol aimed at enhancing the privacy guarantees for a cryptocurrency exchange, building on the first proof of reserves protocol [Revelio](https://eprint.iacr.org/2019/684) (CVCBT 2019). Revelio suffered from the following drawbacks:

- Collusion between exchanges can be detected only if all the exchanges generate proofs from same blockchain state. Need a cryptographic way to enforce this!
- The proof sizes scale linearly in the anonymity set which could be a bottleneck if exchanges are required to publish the proofs on blockchain.

RevelioBP succeeds in alleviating both of these problems. Since the proof size of RevelioBP proofs is logarithmic in the anonymity set size, the entire UTXO set can be chosen as the anonymity set. This enhances the privacy of exchanges' outputs. This ensures that exchanges publishing RevelioBP proofs can only do so in coordination with the UTXO set. Going further, the verification times of RevelioBP are slightly better than that of Revelio. A faster verification is crucial since it is to be carried out by the customers of the exchange who possess limited computational power.

On the downside, the proof generation times of RevelioBP are \(2 \times\) than that of Revelio generation times. Further, the memory usage in case of RevelioBP implementation is much larger than that of Revelio. Revelio implementation could be parallelised but RevelioBP cannot. Therefore, decision of whether an exchange should use Revelio or RevelioBP boils down to the trade-off between performance and scalability.

## Overview of RevelioBP

Given a UTXO set lexicographically ordered as \(\textbf{C}^{(h)} = (C_1, C_2, \dots, C_{n(h)})\), where \(h, n(h)\) are the block height and number of unspent outputs till height \(h\) respectively, suppose an exchange owns outputs \( \textbf{C}^{own} \subset \textbf{C}^{(h)}\) and \( | \textbf{C}^{own}| = s\). Let the index set of exchange-owned addressed be \(\mathcal{E} = (i_1, i_2, \dots, i_s)\). Since each output is a Pedersen commitment of the form \(C = g^{r}h^{a}\) for secret key \(r \in \mathbb{Z}\_q \) and amount \(a \in \mathbb{Z}\_{q}\), knowledge of the secret key \(r\) implies the ownership of an output. Given an output \(C\) and the corresponding secret key \(k\), it is feasible to compute the amount hidden in \(C\) since \(a \in \{0,1,\dots,2^{64}-1\}\). Suppose the secret keys of the exchange-owned outputs is \(\textbf{r} = (r\_1, r\_2, \dots, r\_s)\) and define \(\textbf{e}\_{j}  \in \{0,1\}^n\) such that it has \(1\) only in position \(i\_j\). We also publish a tag vector \(\textbf{I} = (I\_1, \dots, I\_s)\) where \(I\_j = g\_t^{r\_j} h^{a\_j} \) is a deterministic function of the secret key \(r\_j\) and amount \(a\_j\).
This tag vector would be used to detect collusion in exchanges sharing outputs. Note that \(g\_t\) is a generator dependent on the block height \(h\).

RevelioBP is a zero-knowledge proof of reserves protocol for the following statement:

\\[ \mathcal{L}\_{\textsf{RevBP}} = \left[ [\textbf{C}, \textbf{I}] \ | \ \exists [ \textbf{r}, \textbf{e}\_{1}, \dots, \textbf{e}\_{s}]  \text{  s.t  } C_{i\_j} = g^{r\_j} h^{a\_j}, \ I_{j} = g\_{t}^{r\_j} h^{a\_j} \right] \\]

## Sample Simulation 

```rust
//
// Prover's Computation (For Crypto Exchanges)
//

// `s` is the number of exchange owned outputs
// `n` is the UTXO set size
// `a_vec` and `r_vec` are respectively the amount and secret key vectors
// `E_mat` is the index vector of exchange-owned outputs. 

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

let revBP_proof_of_res = RevelioBP::prove(&G, &H, &Gt, &H_prime, &p_vec, &g_prime_vec, &h_vec, &g_vec_append, &h_vec_append, &C_vec_mut, &E_vec, &a_vec, &r_vec);

//
// Verification by customers
//
let result = revelio_test.verify(&G, &H, &Gt, &H_prime, &p_vec, &g_prime_vec, &h_vec, &g_vec_append, &h_vec_append, &C_vec_mut);

assert!(result.is_ok());
```

---

**NOTE**: This library is currently unavailable on [crates.io](https://crates.io) and [DOCS.RS](https://docs.rs/) due to one of the dependencies being unavailable on [crates.io](https://crates.io). We are working to resolve this. Temporarily, you can clone this repository and view the documentation locally using the following commands:

```
cargo doc
RUSTDOCFLAGS="--html-in-header katex.html" cargo doc --no-deps --open
```

This will open the documentation in your browser locally.