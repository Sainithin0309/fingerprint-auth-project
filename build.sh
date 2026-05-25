#!/usr/bin/env bash

# Install Node dependencies (circomlibjs for Poseidon hashing)
npm install

# Install snarkjs globally for proof generation
npm install -g snarkjs

echo "Node dependencies and ZKP tools installed successfully."
