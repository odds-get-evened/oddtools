package org.odds;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.zip.CRC32;

public class Toolset {
    public static String crc32(String s) {
        byte[] inB = s.getBytes();

        CRC32 c = new CRC32();
        c.update(inB);

        long cL = c.getValue();

        return Long.toHexString(cL);
    }

    public static byte[] salt(int n) throws NoSuchAlgorithmException {
        SecureRandom rand = SecureRandom.getInstance("SHA1PRNG");

        byte[] iv = new byte[n / 8];
        rand.nextBytes(iv);

        return iv;
    }

    public static byte[][] byteBlock(byte[] b, int n) {
        byte[][] rows = new byte[b.length / n + 1][n];

        int k = 0;
        for(int i=0; i<b.length; i++) {
            int j = i % n;

            rows[k][j] = b[i];

            if(j == n - 1) k++;
        }

        return rows;
    }
}
