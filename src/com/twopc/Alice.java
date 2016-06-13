package com.twopc;

import com.twopc.paillier.Paillier;
import com.twopc.paillier.PaillierException;

import java.math.BigInteger;

public class Alice {
    public final Paillier.PublicKey pk;
    public final BigInteger a;
    public final BigInteger b;
    public final BigInteger r;
    public final int l;

    public BigInteger d2;
    public BigInteger s;

    public Alice(Paillier.PublicKey pk, BigInteger a, BigInteger b, int l) {
        this.pk = pk;
        this.a = a;
        this.b = b;
        this.l = l;
        this.r = BigInteger.valueOf(27); // TODO randomise this, need to be in Z_n
        // this.r = Paillier.encrypt(pk, Paillier.randomZStarN(pk.modLength, pk.n));
        this.s = BigInteger.ONE; // TODO randomise this
        if (l > 31) {
            throw new RuntimeException("value 'l' is too high");
        }
    }

    public BigInteger d() throws PaillierException {
        BigInteger x = Paillier.encrypt(pk, Util.pow2(l)); // [2^l]
        BigInteger z = x.multiply(a.multiply(b.modInverse(pk.n2)).mod(pk.n2)).mod(pk.n2); // [2^l]*[a]*[b]^{-1}
        return z.multiply(Paillier.encrypt(pk, r)).mod(pk.n2);
    }

    public BigInteger[] es(Bob.Message msg) throws PaillierException {
        this.d2 = msg.d2;

        BigInteger[] es = new BigInteger[l];
        BigInteger[] hs = new BigInteger[]{BigInteger.valueOf(2), BigInteger.valueOf(3), BigInteger.valueOf(4)};
        // System.out.println("vs");
        for (int i = 0; i < l; i++) {
            BigInteger tmp = BigInteger.valueOf(0);
            for (int j = i + 1; j < l; j++) {
                tmp = tmp.add(Util.pow2(j).multiply(Util.bitAt(r, j)));
            }
            BigInteger v = s.subtract(Util.bitAt(r, i)).subtract(tmp).mod(pk.n);
            // System.out.println(v);
            BigInteger c = Paillier.encrypt(pk, v).multiply(msg.ts[i]).mod(pk.n2);
            // BigInteger h = Paillier.randomZStarN(pk.modLength, pk.n);
            es[i] = c.modPow(hs[i], pk.n2);
        }

        return es;
    }

    public BigInteger result(BigInteger _lambda) throws PaillierException {
        BigInteger lambda;
        if (s.compareTo(BigInteger.ONE) == 0) {
            lambda = _lambda;
        } else {
            lambda = Paillier.encrypt(pk, BigInteger.ONE).multiply(_lambda.modInverse(pk.n2));
        }
        // System.out.println("r/2^l");
        // System.out.println(r.divide(Util.pow2(l)));
        BigInteger tmp = Paillier.encrypt(pk, r.divide(Util.pow2(l))).modInverse(pk.n2); // [r / (2^l)]^{-1}
        return d2.multiply(tmp)
                 .multiply(lambda.modInverse(pk.n2))
                 .mod(pk.n2);
    }
}
