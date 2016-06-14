package com.twopc;

import com.twopc.paillier.Paillier;
import com.twopc.paillier.PaillierException;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;
import java.util.Random;

public class Database {

    public class Triple {
        public Triple(BigInteger name, BigInteger age, BigInteger income) {
            this.name = name;
            this.age = age;
            this.income = income;
        }
        public final BigInteger name;
        public final BigInteger age;
        public final BigInteger income;
        public void print() {
            System.out.format("%6.6s\t%2.2s\t%s\n", decodeString(name), age.toString(), income.toString());
        }

        private Triple decrypt(Paillier phe) throws PaillierException {
            return new Triple(
                    phe.decrypt(this.name),
                    phe.decrypt(this.age),
                    phe.decrypt(this.income));
        }
    }

    final int PAILLIER_BITS = 2048;

    private final List<Triple> pt;
    public final List<Triple> ct;
    public final Paillier phe;

    public Database(int n) throws PaillierException {
        pt = new ArrayList<>();
        ct = new ArrayList<>();
        phe = new Paillier(PAILLIER_BITS);
        Random rand = new Random();

        for (int i = 0; i < n; i++) {
            BigInteger name = encodeString("name");
            BigInteger age = BigInteger.valueOf(18 + rand.nextInt(90 - 18));
            BigInteger income = BigInteger.valueOf(10000 + rand.nextInt(100000 - 10000));

            pt.add(new Triple(name, age, income));
            ct.add(new Triple(phe.encrypt(name), phe.encrypt(age), phe.encrypt(income)));
        }
    }

    private static BigInteger encodeString(String s) {
        return new BigInteger(s.getBytes());
    }

    private static String decodeString(BigInteger x) {
        return new String(x.toByteArray());
    }

    public void printPt() {
        pt.forEach(Triple::print);
    }

    public void decryptAndPrint() throws PaillierException {
        for (Triple t : ct) {
            t.decrypt(phe).print();
        }
    }

    public List<Integer> listOfOlderThanX(BigInteger x) {
        List<Integer> is = new ArrayList<>();
        for (int i = 0; i < pt.size(); i++) {
            if (pt.get(i).age.compareTo(x) != -1)
                is.add(i);
        }
        return is;
    }

    public int sumIncomeOnIdx(List<Integer> is) {
        BigInteger sum = BigInteger.ZERO;
        for (Integer i : is) {
            sum = sum.add(pt.get(i).income);
        }
        return sum.intValue();
    }
}
