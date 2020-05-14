package itis.semesterwork.infosec;

import java.util.Arrays;

public class Bleichenbacher {
    private final RSA rsa = new RSA();
    private final ArrayUtils arrayUtils = new ArrayUtils();

    public byte[] createSignature(byte[] message) {
        byte[] hash = hash(message);
        int hashLength = getHashLength();
        if (hashLength != hash.length)
            throw new IllegalStateException("Something is wrong.");

        int blockLength = getRsaBlockLength();
        byte[] paddedMessage = arrayUtils.createInitializedArray(blockLength, 0xFF);
        paddedMessage[0] = 0;
        paddedMessage[1] = 1;
        paddedMessage[blockLength - 1 - hashLength] = 0;
        System.arraycopy(hash, 0, paddedMessage, blockLength - hashLength, hashLength);

        return rsa.decrypt(paddedMessage);
    }

    private int getHashLength() {
        return 20;
    }

    private int getRsaBlockLength() {
        return rsa.getPublicKey().getN().toByteArray().length - 1;
    }

    private byte[] hash(byte[] message) {
        return SHA1.encode(message);
    }

    public boolean isValidSignature(byte[] signedMessage, byte[] signature) {
        byte[] hash = hash(signedMessage);

        byte[] decrypt = rsa.encrypt(signature);
        int hashStart = findPaddingEnd(decrypt) + 1;
        byte[] signedHash = Arrays.copyOfRange(decrypt, hashStart, hashStart + hash.length);

        return Arrays.equals(hash, signedHash);
    }

    private int findPaddingEnd(byte[] decrypt) {
        for (int indx = 2; indx < decrypt.length; indx++) {
            if (decrypt[indx] == 0)
                return indx;
        }
        throw new IllegalStateException("Infinite padding.");
    }

    public RSA.RSAPublicKey getPublicKey() {
        return rsa.getPublicKey();
    }
}
