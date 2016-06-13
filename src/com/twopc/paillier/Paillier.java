/*  Copyright (c) 2009 Omar Hasan (omar dot hasan at insa-lyon dot fr)
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

package com.twopc.paillier;

import java.math.*;
import java.util.*;

public class Paillier {
    private final int CERTAINTY = 64;            // certainty with which primes are generated: 1-2^(-CERTAINTY)
    public final int modLength;                  // length in bits of the modulus n
    public final BigInteger p;                   // a random prime
    public final BigInteger q;                   // a random prime (distinct from p)
    public final BigInteger lambda;              // lambda = lcm(p-1, q-1) = (p-1)*(q-1)/gcd(p-1, q-1)
    public final BigInteger n;                   // n = p*q
    public final BigInteger n2;                  // n2 = n*n
    public final BigInteger g;                   // a random integer in Z*_{n^2}
    public final BigInteger mu;                  // mu = (L(g^lambda mod n^2))^{-1} mod n, where L(u) = (u-1)/n

    public class PublicKey {
        public final BigInteger n;
        public final BigInteger n2;
        public final BigInteger g;
        public final int modLength;
        public PublicKey(BigInteger n, BigInteger n2, BigInteger g, int modLength) {
            this.n = n;
            this.n2 = n2;
            this.g = g;
            this.modLength = modLength;
        }
    }

    public Paillier(int modLengthIn) throws PaillierException {
        if (modLengthIn < 8)
            throw new PaillierException("Paillier(int modLength): modLength must be >= 8");

        modLength = modLengthIn;

        // code below generates the key
        p = new BigInteger(modLength / 2, CERTAINTY, new Random());     // a random prime

        BigInteger tmp_q;
        do {
            tmp_q = new BigInteger(modLength / 2, CERTAINTY, new Random()); // a random prime (distinct from p)
        }
        while (tmp_q.compareTo(p) == 0);
        q = tmp_q;

        // lambda = lcm(p-1, q-1) = (p-1)*(q-1)/gcd(p-1, q-1)
        lambda = (p.subtract(BigInteger.ONE).multiply(q.subtract(BigInteger.ONE))).divide(
                p.subtract(BigInteger.ONE).gcd(q.subtract(BigInteger.ONE)));

        n = p.multiply(q);              // n = p*q
        n2 = n.multiply(n);        // n2 = n*n

        BigInteger tmp_g;
        do {
            // generate g, a random integer in Z*_{n^2}
            tmp_g = randomZStarNSquare();
        }
        // verify g, the following must hold: gcd(L(g^lambda mod n^2), n) = 1, where L(u) = (u-1)/n
        while (tmp_g.modPow(lambda, n2).subtract(BigInteger.ONE).divide(n).gcd(n).intValue() != 1);
        g = tmp_g;

        // mu = (L(g^lambda mod n^2))^{-1} mod n, where L(u) = (u-1)/n
        mu = g.modPow(lambda, n2).subtract(BigInteger.ONE).divide(n).modInverse(n);
    }

    public BigInteger encrypt(BigInteger m) throws PaillierException {
        return Paillier.encrypt(this.publicKey(), m);
    }

    public BigInteger encrypt(BigInteger m, BigInteger r) throws PaillierException {
        return Paillier.encrypt(this.publicKey(), m, r);
    }

    public static BigInteger encrypt(PublicKey pk, BigInteger m) throws PaillierException {
        // generate r, a random integer in Z*_n
        BigInteger r = Paillier.randomZStarN(pk.modLength, pk.n);
        return Paillier.encrypt(pk, m, r);
    }

    public static BigInteger encrypt(PublicKey pk, BigInteger m, BigInteger r) throws PaillierException {
        // if m is not in Z_n
        if (m.compareTo(BigInteger.ZERO) < 0 || m.compareTo(pk.n) >= 0) {
            throw new PaillierException("Paillier.encrypt(BigInteger m, BigInteger r): plaintext m is not in Z_n");
        }

        // if r is not in Z*_n
        if (r.compareTo(BigInteger.ZERO) < 0 || r.compareTo(pk.n) >= 0 || r.gcd(pk.n).intValue() != 1) {
            throw new PaillierException("Paillier.encrypt(BigInteger m, BigInteger r): random integer r is not in Z*_n");
        }

        // c = g^m * r^n mod n^2
        return (pk.g.modPow(m, pk.n2).multiply(r.modPow(pk.n, pk.n2))).mod(pk.n2);
    }

    public BigInteger decrypt(BigInteger c) throws PaillierException {
        // if c is not in Z*_{n^2}
        if (c.compareTo(BigInteger.ZERO) < 0 || c.compareTo(n2) >= 0 || c.gcd(n2).intValue() != 1) {
            throw new PaillierException("Paillier.decrypt(BigInteger c): ciphertext c is not in Z*_{n^2}");
        }

        // m = L(c^lambda mod n^2) * mu mod n, where L(u) = (u-1)/n
        return c.modPow(lambda, n2).subtract(BigInteger.ONE).divide(n).multiply(mu).mod(n);
    }

    public void printValues() {
        System.out.println("p:      " + p);
        System.out.println("q:      " + q);
        System.out.println("lambda: " + lambda);
        System.out.println("n:      " + n);
        System.out.println("n2:     " + n2);
        System.out.println("g:      " + g);
        System.out.println("mu:     " + mu);
    }

    // return a random integer in Z*_n
    private BigInteger randomZStarN() {
        return Paillier.randomZStarN(modLength, n);
    }

    // return a random integer in Z*_{n^2}
    private BigInteger randomZStarNSquare() {
        return Paillier.randomZStarN(modLength * 2, n2);
    }

    public static BigInteger randomZStarN(int modLength, BigInteger n) {
        BigInteger r;

        do {
            r = new BigInteger(modLength, new Random());
        }
        while (r.compareTo(n) >= 0 || r.gcd(n).intValue() != 1);

        return r;
    }

    // return public key
    public PublicKey publicKey() {
        return new PublicKey(n, n2, g, modLength);
    }
}
