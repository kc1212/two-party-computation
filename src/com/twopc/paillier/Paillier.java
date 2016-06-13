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
    private final int CERTAINTY = 64;       // certainty with which primes are generated: 1-2^(-CERTAINTY)
    final int modLength;                  // length in bits of the modulus n
    final BigInteger p;                   // a random prime
    final BigInteger q;                   // a random prime (distinct from p)
    final BigInteger lambda;              // lambda = lcm(p-1, q-1) = (p-1)*(q-1)/gcd(p-1, q-1)
    final BigInteger n;                   // n = p*q
    final BigInteger nsquare;             // nsquare = n*n
    final BigInteger g;                   // a random integer in Z*_{n^2}
    final BigInteger mu;                  // mu = (L(g^lambda mod n^2))^{-1} mod n, where L(u) = (u-1)/n

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
        nsquare = n.multiply(n);        // nsquare = n*n

        BigInteger tmp_g;
        do {
            // generate g, a random integer in Z*_{n^2}
            tmp_g = randomZStarNSquare();
        }
        // verify g, the following must hold: gcd(L(g^lambda mod n^2), n) = 1, where L(u) = (u-1)/n
        while (tmp_g.modPow(lambda, nsquare).subtract(BigInteger.ONE).divide(n).gcd(n).intValue() != 1);
        g = tmp_g;

        // mu = (L(g^lambda mod n^2))^{-1} mod n, where L(u) = (u-1)/n
        mu = g.modPow(lambda, nsquare).subtract(BigInteger.ONE).divide(n).modInverse(n);
    }

    public BigInteger encrypt(BigInteger m) throws PaillierException {
        // if m is not in Z_n
        if (m.compareTo(BigInteger.ZERO) < 0 || m.compareTo(n) >= 0) {
            throw new PaillierException("Paillier.encrypt(BigInteger m): plaintext m is not in Z_n");
        }

        // generate r, a random integer in Z*_n
        BigInteger r = randomZStarN();

        // c = g^m * r^n mod n^2
        return (g.modPow(m, nsquare).multiply(r.modPow(n, nsquare))).mod(nsquare);
    }

    public BigInteger encrypt(BigInteger m, BigInteger r) throws PaillierException {
        // if m is not in Z_n
        if (m.compareTo(BigInteger.ZERO) < 0 || m.compareTo(n) >= 0) {
            throw new PaillierException("Paillier.encrypt(BigInteger m, BigInteger r): plaintext m is not in Z_n");
        }

        // if r is not in Z*_n
        if (r.compareTo(BigInteger.ZERO) < 0 || r.compareTo(n) >= 0 || r.gcd(n).intValue() != 1) {
            throw new PaillierException("Paillier.encrypt(BigInteger m, BigInteger r): random integer r is not in Z*_n");
        }

        // c = g^m * r^n mod n^2
        return (g.modPow(m, nsquare).multiply(r.modPow(n, nsquare))).mod(nsquare);
    }

    public BigInteger decrypt(BigInteger c) throws PaillierException {
        // if c is not in Z*_{n^2}
        if (c.compareTo(BigInteger.ZERO) < 0 || c.compareTo(nsquare) >= 0 || c.gcd(nsquare).intValue() != 1) {
            throw new PaillierException("Paillier.decrypt(BigInteger c): ciphertext c is not in Z*_{n^2}");
        }

        // m = L(c^lambda mod n^2) * mu mod n, where L(u) = (u-1)/n
        return c.modPow(lambda, nsquare).subtract(BigInteger.ONE).divide(n).multiply(mu).mod(n);
    }

    public void printValues() {
        System.out.println("p:       " + p);
        System.out.println("q:       " + q);
        System.out.println("lambda:  " + lambda);
        System.out.println("n:       " + n);
        System.out.println("nsquare: " + nsquare);
        System.out.println("g:       " + g);
        System.out.println("mu:      " + mu);
    }

    // return a random integer in Z_n
    public BigInteger randomZN() {
        BigInteger r;

        do {
            r = new BigInteger(modLength, new Random());
        }
        while (r.compareTo(BigInteger.ZERO) <= 0 || r.compareTo(n) >= 0);

        return r;
    }

    // return a random integer in Z*_n
    public BigInteger randomZStarN() {
        BigInteger r;

        do {
            r = new BigInteger(modLength, new Random());
        }
        while (r.compareTo(n) >= 0 || r.gcd(n).intValue() != 1);

        return r;
    }

    // return a random integer in Z*_{n^2}
    public BigInteger randomZStarNSquare() {
        BigInteger r;

        do {
            r = new BigInteger(modLength * 2, new Random());
        }
        while (r.compareTo(nsquare) >= 0 || r.gcd(nsquare).intValue() != 1);

        return r;
    }

    // return public key as the vector <n, g>
    public Vector publicKey() {
        Vector pubKey = new Vector();
        pubKey.add(n);
        pubKey.add(g);

        return pubKey;
    }
}
