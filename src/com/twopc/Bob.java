package com.twopc;

import com.twopc.paillier.Paillier;
import com.twopc.paillier.PaillierException;

import java.math.BigInteger;

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
    public int l;

    public Bob(Paillier phe) {
        this.phe = phe;
        if (l > 31) {
            throw new RuntimeException("value 'l' is too high");
        }
    }

    public void prep(int l) {
        this.l = l;
    }

    public Message msg(BigInteger ed) throws PaillierException {
        BigInteger d = phe.decrypt(ed);
        BigInteger x = Util.pow2(l);
        // alternatively use d.divideAndRemainder(x)
        BigInteger d1 = d.mod(x);
        BigInteger d2 = d.divide(x);

        BigInteger[] ts = new BigInteger[l];
        for (int i = 0; i < l; i++) {
            BigInteger tmp = BigInteger.valueOf(0);
            for (int j = i + 1; j < l; j++) {
                tmp = tmp.add(Util.pow2(j).multiply(Util.bitAt(d1, j)).mod(phe.n2)).mod(phe.n2);
            }
            ts[i] = phe.encrypt(Util.bitAt(d1, i).add(tmp));
        }
        return new Message(phe.encrypt(d1), phe.encrypt(d2), ts);
    }

    public BigInteger lambda(BigInteger[] es) throws PaillierException {
        for (BigInteger e : es) {
            if (phe.decrypt(e).compareTo(BigInteger.ZERO) == 0) {
                return phe.encrypt(BigInteger.ONE);
            }
        }
        return phe.encrypt(BigInteger.ZERO);
    }
}
