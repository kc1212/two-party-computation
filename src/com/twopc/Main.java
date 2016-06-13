package com.twopc;

import com.twopc.paillier.Paillier;
import com.twopc.paillier.PaillierException;

import java.math.BigInteger;

public class Main {

    public static void main(String[] args) throws PaillierException {
        Paillier phe = new Paillier(30);
        BigInteger ct = phe.encrypt(new BigInteger("111"));
        BigInteger ct2 = phe.encrypt(new BigInteger("112"));
        System.out.println(phe.decrypt(ct.multiply(ct2).mod(phe.nsquare)).toString());
        System.out.println(phe.decrypt(ct.modPow(new BigInteger("3"), phe.nsquare)).toString());

        Database db = new Database(10);
        db.printPt();
        System.out.println();
        db.decryptAndPrint();
    }
}
