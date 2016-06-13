package com.twopc;

import com.twopc.paillier.Paillier;
import com.twopc.paillier.PaillierException;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class Bob {
    public class Message {
        public final BigInteger d1;
        public final BigInteger d2;
        public final BigInteger[] ts;
        public Message(BigInteger d1, BigInteger d2, BigInteger[] ts) {
            this.d1 = d1;
            this.d2 = d2;
            this.ts = ts;
        }
    }

    public final Paillier phe;
    public final int l;
    public Bob(Paillier phe, int l) {
        this.phe = phe;
        this.l = l;
        if (l > 31) {
            throw new RuntimeException("value 'l' is too high");
        }
    }

    public Message d1d2(BigInteger ed) throws PaillierException {
        BigInteger d = phe.decrypt(ed);
        BigInteger x = Util.pow2(l);
        BigInteger d1 = d.mod(x);
        BigInteger d2 = d.divide(x); // TODO check

        System.out.println(d.toString());
        System.out.println(d1.toString());
        System.out.println(d2.toString());

        BigInteger[] ts = new BigInteger[l];
        for (int i = 0; i < l; i++) {
            BigInteger tmp = BigInteger.valueOf(0);
            for (int j = i + 1; j < l; j++) {
                tmp = tmp.add(Util.pow2(j).multiply(Util.bitAt(d1, j)).mod(phe.n2)).mod(phe.n2);
            }
            ts[i] = phe.encrypt(Util.bitAt(d1, i).add(tmp));
        }

        return new Message(d1, d2, ts);
    }

    public BigInteger lambda(BigInteger[] es) throws PaillierException {
        if (Arrays.stream(es).anyMatch(e -> e.compareTo(BigInteger.ZERO) == 0)) {
            return phe.encrypt(BigInteger.ONE);
        }
        return phe.encrypt(BigInteger.ZERO);
    }
}
