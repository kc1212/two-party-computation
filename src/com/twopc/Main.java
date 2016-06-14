package com.twopc;

import com.twopc.paillier.PaillierException;

import java.math.BigInteger;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

public class Main {

    static final int M = 1000000;

    public static void main(String[] args) throws PaillierException {
        int dbLen = 10;
        if (args.length > 0) {
            dbLen = Integer.parseInt(args[0]);
        }
        Instant startInstant;

        startInstant = Instant.now();
        Database db = new Database(dbLen);
        // db.printPt();
        System.out.println("Duration for database creation (ms):\t"
                + Duration.between(startInstant, Instant.now()).getNano() / M);

        // initiate value x, Alice and Bob
        BigInteger x = BigInteger.valueOf(40);
        Alice alice = new Alice(db.phe.publicKey());
        Bob bob = new Bob(db.phe);

        // get a list of indices of ages that are greater than x
        // and then check with the plaintext
        startInstant = Instant.now();
        List<Integer> secureIdxs = listOfOlderThanX(alice, bob, db, x);
        long dur = Duration.between(startInstant, Instant.now()).getNano() / M;
        System.out.println("Duration to find number of people (ms):\t" + dur);
        System.out.println("Duration for comparison protocol (ms):\t" + dur / db.ct.size());

        List<Integer> insecureIdxs = db.listOfOlderThanX(x);
        assert secureIdxs.equals(insecureIdxs);

        // compute the total income of the rows in the list from above
        // check with the plaintext
        startInstant = Instant.now();
        int secureSum = sumIncomeOnIdx(db, secureIdxs);
        System.out.println("Duration for Paillier summation (ms):\t"
                + Duration.between(startInstant, Instant.now()).getNano() / M);

        int insecureSum = db.sumIncomeOnIdx(insecureIdxs);
        assert secureSum == insecureSum;

        System.out.println("There are " + secureIdxs.size() + " rows with age greater than " + x + ".");
        System.out.print("These are: ");
        secureIdxs.forEach(p -> System.out.print(p + " "));
        System.out.print("\b.\n");
        System.out.println("The sum of their income is: " + secureSum + ".");
    }

    /**
     * Use Paillier Homomorphic Encryption to add the income of the rows index by `is`.
     * @param db
     * @param is
     * @return The total income.
     * @throws PaillierException
     */
    private static int sumIncomeOnIdx(Database db, List<Integer> is) throws PaillierException {
        BigInteger esum = db.phe.encrypt(BigInteger.ZERO);
        for (Integer i : is) {
            esum = esum.multiply(db.ct.get(i).income).mod(db.phe.n2);
        }
        return db.phe.decrypt(esum).intValue();
    }

    /**
     * Finds all the rows in the database `db` that are greater than `x`.
     * @param alice
     * @param bob
     * @param db
     * @param x
     * @return A list of indices representing rows that are greater than `x`.
     * @throws PaillierException
     */
    private static List<Integer> listOfOlderThanX(Alice alice, Bob bob, Database db, BigInteger x) throws PaillierException {
        List<Integer> is = new ArrayList<>();
        for (int i = 0; i < db.ct.size(); i++) {
            if (protocol(alice, bob, db.phe.encrypt(x), db.ct.get(i).age, 7)) {
                is.add(i);
            }
        }
        return is;
    }

    /**
     * The secure comparison protocol is implemented here.
     * @param alice Alice wishes to compare two encrypted values `a` and `b`.
     * @param bob Bob holds the private key to the databse.
     * @param a
     * @param b
     * @param l Bit length used in the protocol.
     * @return True if a > b otherwise false.
     * @throws PaillierException
     */
    private static boolean protocol(Alice alice, Bob bob, BigInteger a, BigInteger b, int l) throws PaillierException {
        alice.prep(a, b, l);
        bob.prep(l);

        Bob.Message msg = bob.msg(alice.d());
        BigInteger[] es = alice.es(msg);
        BigInteger lambda = bob.lambda(es);
        return 1 != bob.phe.decrypt(alice.result(lambda)).intValue();
    }
}
