# Plot 1: Gen and Ver times vs n (for s=20)
# Estimated time to run on an Intel® Core™ i7-5500U CPU @ 2.40GHz × 1
# => 5.5 hours 
cargo build --release
cargo run --release --bin revelio_bp_bin 100 20 -n 1
cargo run --release --bin revelio_bp_bin 200 20 -n 1
cargo run --release --bin revelio_bp_bin 400 20 -n 1
cargo run --release --bin revelio_bp_bin 800 20 -n 1
cargo run --release --bin revelio_bp_bin 1600 20 -n 1
cargo run --release --bin revelio_bp_bin 3200 20 -n 1
cargo run --release --bin revelio_bp_bin 6400 20 -n 1
cargo run --release --bin revelio_bp_bin 12800 20 -n 1
cargo run --release --bin revelio_bp_bin 25600 20 -n 1
cargo run --release --bin revelio_bp_bin 51200 20 -n 1
cargo run --release --bin revelio_bp_bin 102400 20 -n 1
cargo run --release --bin revelio_bp_bin 204800 20 -n 1

# Plot 1: Gen and Ver times vs s (for n=1000)
# Estimated time to run on an Intel® Core™ i7-5500U CPU @ 2.40GHz × 1
# => 1 hour 
cargo build release
cargo run --release --bin revelio_bp_bin 1000 10 -n 1
cargo run --release --bin revelio_bp_bin 1000 20 -n 1
cargo run --release --bin revelio_bp_bin 1000 50 -n 1
cargo run --release --bin revelio_bp_bin 1000 100 -n 1
cargo run --release --bin revelio_bp_bin 1000 200 -n 1
cargo run --release --bin revelio_bp_bin 1000 500 -n 1
cargo run --release --bin revelio_bp_bin 1000 800 -n 1
