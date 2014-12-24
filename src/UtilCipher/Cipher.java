package UtilCipher;


/**
 * Cipher.java TODO:
 * 
 * @author Kim Dinh Son Email:sonkdbk@gmail.com
 */

public abstract class Cipher extends CryptoUtils {

	public Cipher(int keySize) {
		this.keySize = keySize;
	}

	public int keySize;

	public int keySize() {
		return keySize;
	}

	public abstract void setKey(byte[] key);

	public void setKey(String keyStr) {
		setKey(makeKey(keyStr));
	}

	public byte[] makeKey(String keyStr) {
		byte[] key;
		if (keySize == 0)
			key = new byte[keyStr.length()];
		else
			key = new byte[keySize];
		int i, j;

		for (j = 0; j < key.length; ++j)
			key[j] = 0;

		for (i = 0, j = 0; i < keyStr.length(); ++i, j = (j + 1) % key.length)
			key[j] ^= (byte) keyStr.charAt(i);

		return key;
	}

}
