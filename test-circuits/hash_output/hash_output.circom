pragma circom 2.0.0;

include "../../node_modules/circomlib/circuits/poseidon.circom";

template HashChain(n) {
    signal input preimage;
    signal output result;
    signal intermediate[n + 1];
    intermediate[0] <== preimage;
    component hasher[n];
    for(var i = 0; i < n; i++) {
        hasher[i] = Poseidon(1); // parallel this? 
        hasher[i].inputs[0] <== intermediate[i];
        intermediate[i+1] <== hasher[i].out;
    }
    log(intermediate[n]);
    result <== intermediate[n];
}

component main = HashChain(1);

