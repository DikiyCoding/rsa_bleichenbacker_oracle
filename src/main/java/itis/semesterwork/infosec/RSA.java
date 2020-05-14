package itis.semesterwork.infosec;

import java.math.BigInteger;
import java.security.SecureRandom;

public class RSA {

    private BigInteger n;
    private BigInteger e;
    private BigInteger d;

    public RSA() {
        this(1024);
    }

    public RSA(int primesBits) {
        SecureRandom random = new SecureRandom();
        boolean tryAgain = true;
        while (tryAgain) {
            tryAgain = false;
            try {
                crashingGenerateKeyPair(random, primesBits);
            } catch (ArithmeticException ex) {
                tryAgain = true;
            }
        }
    }

    private void crashingGenerateKeyPair(SecureRandom random, int primesBits) {
        BigInteger p = BigInteger.probablePrime(primesBits, random);
        BigInteger q = BigInteger.probablePrime(primesBits, random);

        n = p.multiply(q);
        BigInteger et = p.add(BigInteger.ONE.negate()).multiply(q.add(BigInteger.ONE.negate()));
        e = BigInteger.valueOf(3);
        d = e.modInverse(et);
    }

    public byte[] encrypt(byte[] plaintext) {
        BigInteger m = new BigInteger(plaintext);
        return encrypt(m).toByteArray();
    }

    public BigInteger encrypt(BigInteger plaintext) {
        return plaintext.modPow(e, n);
    }

    public byte[] decrypt(byte[] ciphertext) {
        BigInteger c = new BigInteger(ciphertext);
        return c.modPow(d, n).toByteArray();
    }

    public RSAPublicKey getPublicKey() {
        return new RSAPublicKey(e, n);
    }

    public static class RSAPublicKey {
        private final BigInteger e;
        private final BigInteger n;

        public RSAPublicKey(BigInteger e, BigInteger n) {
            super();
            this.e = e;
            this.n = n;
        }

        public BigInteger getE() {
            return e;
        }

        public BigInteger getN() {
            return n;
        }
    }
}
