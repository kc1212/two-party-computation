package com.twopc;

import com.twopc.paillier.Paillier;
import com.twopc.paillier.PaillierException;

import java.math.BigInteger;
import java.util.Arrays;

public class Main {

    public static void main(String[] args) throws PaillierException {
        // database stuff
        Database db = new Database(10);
        db.printPt();
        BigInteger x = BigInteger.valueOf(30);
        System.out.println("count: " + db.countGreaterThan(x));

        protocol(db.phe, db.phe.encrypt(BigInteger.valueOf(7)), db.phe.encrypt(BigInteger.valueOf(6)), 3);

        int cnt = 0;
        for (Database.Triple t : db.ct) {
            if (protocol(db.phe, db.phe.encrypt(x), t.age, 7)) {
                cnt++;
            }
        }
        System.out.println("secure count: " + cnt);
    }

    private static boolean protocol(Paillier phe, BigInteger a, BigInteger b, int l) throws PaillierException {
        // TODO no need to re-initiate alice and bob
        Alice alice = new Alice(phe.publicKey(), a, b, l);
        Bob bob = new Bob(phe, l);

        Bob.Message msg = bob.msg(alice.d());
        BigInteger[] es = alice.es(msg);
        BigInteger lambda = bob.lambda(es);
        int res = phe.decrypt(alice.result(lambda)).intValue();

        if (res == 1)
            return false;
        return true;
    }
}
