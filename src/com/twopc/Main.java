package com.twopc;

import com.twopc.paillier.Paillier;
import com.twopc.paillier.PaillierException;

import java.math.BigInteger;

public class Main {

    public static void main(String[] args) throws PaillierException {
        Paillier phe = new Paillier(30);
        BigInteger a = phe.encrypt(new BigInteger("6"));
        BigInteger b = phe.encrypt(new BigInteger("5"));
        System.out.println(phe.decrypt(a.multiply(b).mod(phe.n2)).toString());
        System.out.println(phe.decrypt(a.modPow(new BigInteger("3"), phe.n2)).toString());

        /*
        Database db = new Database(10);
        db.printPt();
        System.out.println();
        db.decryptAndPrint();
        */

        Alice alice = new Alice(phe.publicKey(), a, b, 3);
        Bob bob = new Bob(phe, 3);
        bob.d1d2(alice.d());
    }
}
