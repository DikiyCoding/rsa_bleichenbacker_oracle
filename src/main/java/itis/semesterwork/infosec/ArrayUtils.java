package itis.semesterwork.infosec;

import java.util.Arrays;

public class ArrayUtils {

    public byte[] biteWiseToBytes(int[] ints) {
        byte[] result = new byte[0];
        for (int oneInt : ints)
            result = join(result, intToBytes(oneInt));
        return result;
    }

    public int[] biteWiseToIntegers(byte[] bytes) {
        int length = bytes.length / 4 + (bytes.length % 4 == 0 ? 0 : 1);
        int[] result = new int[length];
        for (int i = 0; i < bytes.length; i++) {
            int indx = i / 4;
            result[indx] = result[indx] << 8;
            result[indx] += bytes[i] & 0xff;
        }
        return result;
    }

    public byte[] createInitializedArray(int length, int content) {
        return createInitializedArray(length, (byte) content);
    }

    public byte[] join(byte[] first, byte[]... rest) {
        byte[] result = first;
        for (byte[] next : rest)
            result = joinTwo(result, next);
        return result;
    }

    private byte[] joinTwo(byte[] first, byte[] second) {
        byte[] result = new byte[first.length + second.length];
        System.arraycopy(first, 0, result, 0, first.length);
        System.arraycopy(second, 0, result, first.length, second.length);
        return result;
    }

    private byte[] intToBytes(int x) {
        byte[] bytes = new byte[4];
        for (int i = 0; x != 0; i++, x >>>= 8)
            bytes[4 - i - 1] = (byte) (x & 0xFF);
        return bytes;
    }

    private byte[] createInitializedArray(int length, byte content) {
        byte[] result = new byte[length];
        Arrays.fill(result, content);
        return result;
    }
}
