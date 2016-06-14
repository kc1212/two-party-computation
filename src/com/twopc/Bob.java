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

    /**
     * Prepare Bob with initial values, this function should be called when a new round of the comparison protocol begins.
     * @param l
     */
    public void prep(int l) {
        this.l = l;
    }

    /**
     * Receive [d] from Alice and compute [d^1], [d^2] and [t_i] for i = {0, ..., l-1}
     * @param ed
     * @return
     * @throws PaillierException
     */
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

    /**
     * Receive [e_i] from Alice and compute [~lambda].
     * @param es
     * @return
     * @throws PaillierException
     */
    public BigInteger lambda(BigInteger[] es) throws PaillierException {
        for (BigInteger e : es) {
            if (phe.decrypt(e).compareTo(BigInteger.ZERO) == 0) {
                return phe.encrypt(BigInteger.ONE);
            }
        }
        return phe.encrypt(BigInteger.ZERO);
    }
}
