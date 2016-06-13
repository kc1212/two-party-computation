package com.twopc;

import java.math.BigInteger;

public class Util {
    public static BigInteger pow2(int l) {
        BigInteger two = BigInteger.valueOf(2);
        return two.pow(l);
    }

    public static BigInteger bitAt(BigInteger x, int n) {
        if (x.testBit(n)) {
            return BigInteger.valueOf(1);
        }
        return BigInteger.valueOf(0);
    }
}
