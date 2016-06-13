package com.twopc;

import com.twopc.paillier.Paillier;
import com.twopc.paillier.PaillierException;

import java.math.BigInteger;
import java.util.Arrays;

public class Main {

    public static void main(String[] args) throws PaillierException {
        Paillier phe = new Paillier(30);
        BigInteger a = phe.encrypt(new BigInteger("1"));
        BigInteger b = phe.encrypt(new BigInteger("7"));

        /*
        Database db = new Database(10);
        db.printPt();
        System.out.println();
        db.decryptAndPrint();
        */

        Alice alice = new Alice(phe.publicKey(), a, b, 3);
        Bob bob = new Bob(phe, 3);
        Bob.Message msg = bob.msg(alice.d());
        System.out.println("d1: " + phe.decrypt(msg.d1));
        System.out.println("d2: " + phe.decrypt(msg.d2));
        Util.decryptAndPrint("ts", phe, msg.ts);

        BigInteger[] es = alice.es(msg);
        Util.decryptAndPrint("es", phe, es);

        BigInteger lambda = bob.lambda(es);
        System.out.print("lambda: ");
        System.out.println(phe.decrypt(lambda));
        System.out.print("res: ");
        System.out.println(phe.decrypt(alice.result(lambda)));
    }
}
