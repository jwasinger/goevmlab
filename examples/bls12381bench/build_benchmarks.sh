#! /usr/bin/env bash

./bls12381bench --precompile g1add evaluate
./bls12381bench --precompile g1mul evaluate

./bls12381bench --precompile g2add evaluate
./bls12381bench --precompile g2mul evaluate

./bls12381bench --precompile mapfp evaluate
./bls12381bench --precompile mapfp2 evaluate

# generate msm and pairing benchmarks
for input_count in {1..32}
do
./bls12381bench --precompile g1msm --input-count $input_count evaluate
./bls12381bench --precompile g2msm --input-count $input_count evaluate
./bls12381bench --precompile pairing --input-count $input_count evaluate
done
