package com.twopc;

import com.twopc.paillier.Paillier;
import com.twopc.paillier.PaillierException;

import java.math.BigInteger;
import java.util.Random;

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

    public static void decryptAndPrint(String name, Paillier phe, BigInteger[] xs) throws PaillierException {
        System.out.print(name + ":\t");
        for (BigInteger x  : xs) {
            System.out.print(phe.decrypt(x) + " ");
        }
        System.out.println();
    }

    public static BigInteger randomS(BigInteger n) {
        if ((new Random()).nextBoolean()) {
            return BigInteger.ONE;
        }
        return BigInteger.valueOf(-1).mod(n);
    }
}
