package com.twopc;

import com.twopc.paillier.PaillierException;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;

public class Main {

    public static void main(String[] args) throws PaillierException {
        Database db = new Database(10);
        db.printPt();

        BigInteger x = BigInteger.valueOf(40);
        Alice alice = new Alice(db.phe.publicKey());
        Bob bob = new Bob(db.phe);

        // get a list of indices of ages that are greater or equal to x
        // and then check with the plaintext
        List<Integer> secureIdxs = listOfOlderThanX(alice, bob, db, x);
        List<Integer> insecureIdxs = db.listOfOlderThanX(x);
        assert secureIdxs.equals(insecureIdxs);

        // compute the total income of the rows in the list from above
        // check with the plaintext
        int secureSum = sumIncomeOnIdx(db, secureIdxs);
        int insecureSum = db.sumIncomeOnIdx(insecureIdxs);
        assert secureSum == insecureSum;

        System.out.println("There are " + secureIdxs.size() + " rows with age greater or equal to " + x + ".");
        System.out.print("These are: ");
        secureIdxs.forEach(p -> System.out.print(p + " "));
        System.out.println();
        System.out.println("The sum of their income is: " + secureSum);
    }

    private static int sumIncomeOnIdx(Database db, List<Integer> is) throws PaillierException {
        BigInteger esum = db.phe.encrypt(BigInteger.ZERO);
        for (Integer i : is) {
            esum = esum.multiply(db.ct.get(i).income).mod(db.phe.n2);
        }
        return db.phe.decrypt(esum).intValue();
    }

    private static List<Integer> listOfOlderThanX(Alice alice, Bob bob, Database db, BigInteger x) throws PaillierException {
        List<Integer> is = new ArrayList<>();
        for (int i = 0; i < db.ct.size(); i++) {
            if (protocol(alice, bob, db.phe.encrypt(x), db.ct.get(i).age, 7)) {
                is.add(i);
            }
        }
        return is;
    }

    private static boolean protocol(Alice alice, Bob bob, BigInteger a, BigInteger b, int l) throws PaillierException {
        alice.prep(a, b, l);
        bob.prep(l);

        Bob.Message msg = bob.msg(alice.d());
        BigInteger[] es = alice.es(msg);
        BigInteger lambda = bob.lambda(es);
        int res = bob.phe.decrypt(alice.result(lambda)).intValue();

        if (res == 1)
            return false;
        return true;
    }
}
