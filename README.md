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




