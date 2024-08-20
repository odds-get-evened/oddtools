package org.odds.crypto;

import io.github.novacrypto.base58.Base58;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;

/**
 * Symmetric encryption using AES
 */
public class Symmetrical {
	public static final int ITERATIONS = 65536;
	public static final int KEYSIZE = 256;

	public static final String AES = "AES";
	public static final String PBKDF2_WITH_HMAC = "PBKDF2WithHmacSHA256";
	private static final String AES_CIPHER_ALGORITHM = "AES/CBC/PKCS5PADDING";

	/**
	 * generate a random byte array with specified length
	 * @param n needed length of array
	 * @return byte array
	 */
	public static byte[] randomBytes(int n) {
		byte[] iv = new byte[n];
		new SecureRandom().nextBytes(iv);

		return iv;
	}

	/**
	 * generate a plain symmetric key
	 * @param n key length
	 * @return SecretKey
	 * @throws NoSuchAlgorithmException
	 */
	public static SecretKey getAESKey(int n) throws NoSuchAlgorithmException {
		KeyGenerator gen = KeyGenerator.getInstance(AES);
		gen.init(n, SecureRandom.getInstanceStrong());

		return gen.generateKey();
	}

	/**
	 * generate a password protected symmetric key
	 * @param passwd password
	 * @param salt salt for flavor
	 * @return SecretKey
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidKeySpecException
	 */
	public SecretKey getAESKeyFromPassword(char[] passwd, byte[] salt) throws NoSuchAlgorithmException, InvalidKeySpecException {
		SecretKeyFactory f = SecretKeyFactory.getInstance(PBKDF2_WITH_HMAC);
		KeySpec spec = new PBEKeySpec(passwd, salt, ITERATIONS, KEYSIZE);

		return new SecretKeySpec(f.generateSecret(spec).getEncoded(), AES);
	}

	/**
	 * AES encryption of provided bytes
	 * @param data bytes
	 * @param secret the key
	 * @param iv some saltiness
	 * @return encrypted bytes
	 * @throws NoSuchPaddingException
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidAlgorithmParameterException
	 * @throws InvalidKeyException
	 * @throws IllegalBlockSizeException
	 * @throws BadPaddingException
	 */
	public static byte[] encrypt(byte[] data, String secret, String iv) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
		Cipher c = Cipher.getInstance(AES_CIPHER_ALGORITHM);
		c.init(Cipher.ENCRYPT_MODE, keyFromBytes(Base58.base58Decode(secret)), new IvParameterSpec(Base58.base58Decode(iv)));

		return c.doFinal(data);
	}

	/**
	 * AES decryption of provided encrypted byte data
	 * @param data byte data
	 * @param secret the key
	 * @param iv saltiness
	 * @return decrypted bytes
	 * @throws NoSuchPaddingException
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidAlgorithmParameterException
	 * @throws InvalidKeyException
	 * @throws IllegalBlockSizeException
	 * @throws BadPaddingException
	 */
	private static byte[] decrypt(byte[] data, String secret, String iv) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
		Cipher c = Cipher.getInstance(AES_CIPHER_ALGORITHM);
		c.init(Cipher.DECRYPT_MODE, keyFromBytes(Base58.base58Decode(secret)), new IvParameterSpec(Base58.base58Decode(iv)));

		return c.doFinal(data);
	}

	/**
	 * return Java SecretKey from bytes
	 * @param b byte data
	 * @return SecretKey
	 */
	private static SecretKey keyFromBytes(byte[] b) {
		return new SecretKeySpec(b, 0, b.length, AES);
	}
}
