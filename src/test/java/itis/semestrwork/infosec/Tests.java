package itis.semestrwork.infosec;

import com.sun.org.apache.xerces.internal.impl.dv.util.Base64;
import itis.semesterwork.infosec.ArrayUtils;
import itis.semesterwork.infosec.Bleichenbacher;
import itis.semesterwork.infosec.RSA;
import itis.semesterwork.infosec.SHA1;
import org.junit.Test;

import java.math.BigDecimal;
import java.math.BigInteger;

import static org.junit.Assert.*;

public class Tests {

    private static final BigInteger TWO = BigInteger.valueOf(2);
    private static final BigInteger THREE = BigInteger.valueOf(3);
    private static final String EX_46_INPUT = "VGhhdCdzIHdoeSBJIGZvdW5kIHlvdSBkb24ndCBwbGF5IGFyb3VuZCB3aXRoIHRoZSBGdW5reSBDb2xkIE1lZGluYQ==";

    /**
     * Second Option with integer cube root
     */
    @Test
    public void ex42() {
        ArrayUtils arrayUtils = new ArrayUtils();
        Bleichenbacher bleichenbacher = new Bleichenbacher();
        RSA.RSAPublicKey publicKey = bleichenbacher.getPublicKey();
        byte[] forgedMessage = "hi mom".getBytes();

        if (!publicKey.getE().equals(THREE))
            throw new IllegalArgumentException("Attack is valid only for e=3.");

        byte[] paddedHash = arrayUtils.join(new byte[]{0, 1, (byte) 0xff, 0},
                SHA1.encode(forgedMessage));

        byte[] paddedMessageMinimum = new byte[publicKey.getN().toByteArray().length - 1];
        System.arraycopy(paddedHash, 0, paddedMessageMinimum, 0, paddedHash.length);

        byte[] paddedMessageMaximum = arrayUtils.createInitializedArray(
                publicKey.getN().toByteArray().length - 1, 255);
        System.arraycopy(paddedHash, 0, paddedMessageMaximum, 0, paddedHash.length);

        BigInteger minimum = new BigInteger(paddedMessageMinimum);
        BigInteger maximum = new BigInteger(paddedMessageMaximum);

        BigInteger min = TWO;
        BigInteger max = minimum;
        BigInteger current = min.divide(THREE);

        while (!((minimum.compareTo(current.pow(3)) < 0) && current.pow(3).compareTo(maximum) < 0)) {
            if (current.pow(3).compareTo(minimum) < 0) min = current;
            else max = current;
            current = min.add(max.add(current.negate()).divide(TWO));
        }
        BigInteger cubeRoot = current;

        byte[] forgedSignature = cubeRoot.toByteArray();

        assertTrue(bleichenbacher.isValidSignature(forgedMessage, forgedSignature));
    }

    @Test
    public void ex42Bleichenbacher() {
        Bleichenbacher bleichenbacher = new Bleichenbacher();
        byte[] signedMessage = "hi dad".getBytes();
        byte[] forgedMessage = "hi mom".getBytes();
        byte[] signature = bleichenbacher.createSignature(signedMessage);
        assertTrue(bleichenbacher.isValidSignature(signedMessage, signature));
        assertFalse(bleichenbacher.isValidSignature(forgedMessage, signature));
    }

    @Test
    public void ex46() {
        RSA rsa = new RSA();

        byte[] plaintext = Base64.decode(EX_46_INPUT);
        byte[] ciphertext = rsa.encrypt(plaintext);

        BigInteger number = rsa.getPublicKey().getN();
        BigInteger cipher = new BigInteger(ciphertext);

        BigDecimal minimum = BigDecimal.ZERO;
        BigDecimal maximum = new BigDecimal(number);
        BigInteger encryptedMultiplier = rsa.encrypt(TWO);

        while (0 > BigDecimal.valueOf(0.5).compareTo(maximum.add(minimum.negate()))) {
            cipher = cipher.multiply(encryptedMultiplier).mod(number);
            BigDecimal half = minimum.add(maximum).divide(BigDecimal.valueOf(2));

            byte[] decrypt = rsa.decrypt(cipher.toByteArray());
            if (decrypt[decrypt.length - 1] % 2 == 0) maximum = half;
            else minimum = half;
        }

        byte[] decrypted = maximum.toBigInteger().toByteArray();

        assertArrayEquals(plaintext, decrypted);
    }
}
