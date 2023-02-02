pragma circom 2.0.0;

template Multiplier() {
    signal input a;
    signal input b;
    signal output c;
    signal i;
    signal j;
    i <== b*b;
    j <== a*b;
    c <== i*j;
}

component main = Multiplier();

