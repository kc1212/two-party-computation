package com.twopc;

import com.twopc.paillier.Paillier;
import com.twopc.paillier.PaillierException;

import java.math.BigInteger;
import java.util.Random;

public class Alice {
    public final Paillier.PublicKey pk;
    public BigInteger a;
    public BigInteger b;
    public BigInteger r;
    public BigInteger r2; // for masking the final result
    public int l;

    public BigInteger d2;
    public BigInteger s;

    public Alice(Paillier.PublicKey pk) {
        this.pk = pk;
    }

    /**
     * Prepare Alice with initial values, this function should be called when a new round of the comparison protocol begins.
     * @param a
     * @param b
     * @param l
     */
    public void prep(BigInteger a, BigInteger b, int l) {
        this.a = a;
        this.b = b;
        this.l = l;
        this.r = new BigInteger(80 + l + 1, new Random()); // can't be larger than n
        this.s = Util.randomS(pk.n);

        // we assume plaintext are 32 bit integers and can't be larger
        if (l > 32) {
            throw new RuntimeException("value 'l' is too high");
        }
    }

    /**
     * Create [d] for Bob to consume.
     * @return
     * @throws PaillierException
     */
    public BigInteger d() throws PaillierException {
        BigInteger x = Paillier.encrypt(pk, Util.pow2(l)); // [2^l]
        BigInteger z = x.multiply(a.multiply(b.modInverse(pk.n2)).mod(pk.n2)).mod(pk.n2); // [z] = [2^l]*[a]*[b]^{-1}
        return z.multiply(Paillier.encrypt(pk, r)).mod(pk.n2); // [d] = [z]*[r]
    }

    /**
     * Take [d^1], [d^2] and [t_i] to compute [e_i] for i = {0, ..., l-1}
     * @param msg
     * @return
     * @throws PaillierException
     */
    public BigInteger[] es(Bob.Message msg) throws PaillierException {
        this.d2 = msg.d2; // need it  for later

        BigInteger[] es = new BigInteger[l];
        for (int i = 0; i < l; i++) {
            BigInteger tmp = BigInteger.valueOf(0);
            for (int j = i + 1; j < l; j++) {
                tmp = tmp.add(Util.pow2(j).multiply(Util.bitAt(r, j)));
            }
            BigInteger v = s.subtract(Util.bitAt(r, i)).subtract(tmp).mod(pk.n);
            BigInteger c = Paillier.encrypt(pk, v).multiply(msg.ts[i]).mod(pk.n2); // [c_i] = [v_i] * [t_i]
            BigInteger h = Paillier.randomZStarN(pk.modLength, pk.n); // h_i \in_R Z^*_n
            es[i] = c.modPow(h, pk.n2); // [e_i] = [c_i]^{h_i}
        }

        return es;
    }

    /**
     * Takes [~lambda] from Bob and compute the masked result [C'] = [C]*[r2] = [C + r2].
     * @param _lambda
     * @return
     * @throws PaillierException
     */
    public BigInteger maskedResult(BigInteger _lambda) throws PaillierException {
        this.r2 = new BigInteger(32 + 80, new Random());
        return this.result(_lambda)
                .multiply(Paillier.encrypt(pk, r2))
                .mod(pk.n2);
    }

    /**
     * Takes C' from Bob (after decrypting it), then compute the final result.
     * @param res
     * @return
     * @throws PaillierException
     */
    public BigInteger unmaskResult(BigInteger res) throws PaillierException {
        return res.subtract(r2);
    }

    /**
     * Takes [~lambda] from Bob and compute [z_l].
     * @param _lambda
     * @return
     * @throws PaillierException
     */
    private BigInteger result(BigInteger _lambda) throws PaillierException {
        BigInteger lambda;
        if (s.compareTo(BigInteger.ONE) == 0) {
            lambda = _lambda;
        } else {
            lambda = Paillier.encrypt(pk, BigInteger.ONE).multiply(_lambda.modInverse(pk.n2));
        }
        BigInteger tmp = Paillier.encrypt(pk, r.divide(Util.pow2(l))).modInverse(pk.n2); // [r / (2^l)]^{-1}
        return d2.multiply(tmp)
                 .multiply(lambda.modInverse(pk.n2))
                 .mod(pk.n2); // [d^2] * [r / 2^l] * [lambda]^{-1}
    }
}
