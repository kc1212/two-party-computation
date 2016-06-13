package com.twopc;

import com.twopc.paillier.Paillier;
import com.twopc.paillier.PaillierException;

import java.math.BigInteger;

public class Main {

    public static void main(String[] args) throws PaillierException {
        Paillier phe = new Paillier(128);
        BigInteger pt = new BigInteger("123123123");
        BigInteger ct = phe.encrypt(pt);
        System.out.println(phe.decrypt(ct).toString());
    }
}
