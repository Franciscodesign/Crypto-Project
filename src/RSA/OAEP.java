package RSA;

import java.math.BigInteger;
import java.security.SecureRandom;

import SHA3.Keccak;
import UtilCipher.CryptoUtils;


/**
 * OAEP.java
 * TODO: 
 * Algorithm: http://en.wikipedia.org/wiki/Optimal_asymmetric_encryption_padding
 * @author Kim Dinh Son
 * Email:sonkdbk@gmail.com
 */

public class OAEP {
	static int hLen = 32; // hash 256 bits
	public static final SecureRandom random = new SecureRandom();
	private static String LHash = "RSA-OAEP";
	
	// Keccak (SHA3) - 256
	public static byte[] SHA3(byte[] m){
		Keccak sha3 = new Keccak();
		sha3.setBitRate(256);
		sha3.setDiversifier(0);
		
		sha3.init(256);
		sha3.update(m, m.length);
		byte[] hash = sha3.getHash(new byte[sha3.getC()/16]);
		return hash;
	}
	
	// Mask Generation Function
	public static byte[] MGF1(byte[] seed, int seedOffset, int seedLength,
			int desiredLength) {
		int hLen = 32;
		int offset = 0;
		int i = 0;
		byte[] mask = new byte[desiredLength];
		byte[] temp = new byte[seedLength + 4];
		System.arraycopy(seed, seedOffset, temp, 4, seedLength);
		while (offset < desiredLength) {
			temp[0] = (byte) (i >>> 24);
			temp[1] = (byte) (i >>> 16);
			temp[2] = (byte) (i >>> 8);
			temp[3] = (byte) i;
			int remaining = desiredLength - offset;
			System.arraycopy(SHA3(temp), 0, mask, offset,
					remaining < hLen ? remaining : hLen);
			offset = offset + hLen;
			i = i + 1;
		}
		return mask;
	}
	
	public static byte[] unPad(byte[] message, String label) throws Exception {
		if (!label.equals(LHash)) {
			return null;
		}
		
		int mLen = message.length;
		int hLen = 32;
		if (mLen < (hLen << 1) + 1) {
			return null;
		}
		byte[] copy = new byte[mLen];
		System.arraycopy(message, 0, copy, 0, mLen);
		byte[] seedMask = MGF1(copy, hLen, mLen - hLen, hLen);
		CryptoUtils.xorBlock(copy, 0, seedMask, 0, copy,0, hLen);

		byte[] hash = SHA3(label.getBytes("UTF-8")); 
		byte[] dataBlockMask = MGF1(copy, 0, hLen, mLen - hLen);
		int index = -1;
		for (int i = hLen; i < mLen; i++) {
			copy[i] ^= dataBlockMask[i - hLen];
			if (i < (hLen << 1)) {
				if (copy[i] != hash[i - hLen]) {
					return null;
				}
			} else if (index == -1) {
				if (copy[i] == 1) {
					index = i + 1;
				}
			}
		}
		if (index == -1 || index == mLen) {
			return null;
		}
		byte[] unpadded = new byte[mLen - index];
		System.arraycopy(copy, index, unpadded, 0, mLen - index);
		return unpadded;
	}

	/*
	 * mLen <= length - hLen * 2 - 1
	 */
	public static byte[] pad(byte[] message, int length, String label)
			throws Exception {
		if (!label.equals(LHash)) {
			return null;
		}
		int mLen = message.length;
		int hLen = 32;
		if (mLen > length - (hLen << 1) - 1) {
			return null;
		}
		int zeroPad = length - mLen - (hLen << 1) - 1;
		byte[] dataBlock = new byte[length - hLen];
		System.arraycopy(SHA3(label.getBytes("UTF-8")), 0, dataBlock, 0,
				hLen);
		System.arraycopy(message, 0, dataBlock, hLen + zeroPad + 1, mLen);
		dataBlock[hLen + zeroPad] = 1;
		byte[] seed = new byte[hLen];
		random.nextBytes(seed);
		byte[] dataBlockMask = MGF1(seed, 0, hLen, length - hLen);
		CryptoUtils.xorBlock(dataBlock, dataBlockMask, dataBlock);

		byte[] seedMask = MGF1(dataBlock, 0, length - hLen, hLen);
		CryptoUtils.xorBlock(seed, seedMask, seed);

		byte[] padded = new byte[length];
		System.arraycopy(seed, 0, padded, 0, hLen);
		System.arraycopy(dataBlock, 0, padded, hLen, length - hLen);
		return padded;
	}
	
	public static byte[] encrypt(byte[] message, RSA rsa, int length, String label) throws Exception{
		int mLen = message.length;
		if (mLen > length - (hLen << 1) - 1) {
			System.out.println("Encoding error: message too long. Try again.");
			return null;
		}
		byte[] out = new byte[length]; 
		out = pad(message, length, label);
		// RSA Encrypt
		BigInteger m = new BigInteger(out);
		BigInteger c = rsa.encrypt(m);
		return c.toByteArray();
	}
	
	public static byte[] decrypt(byte[] cipherText, RSA rsa, String label) throws Exception{
		int mLen = cipherText.length;
		if (mLen < (hLen << 1) + 1) {
			System.out.println("Decoding error.");
			return null;
		}
		
		if (mLen != (rsa.getN().bitLength() / 8)) {
			System.out.println("Decoding error."+" "+(rsa.getN().bitLength() / 8)+" "+mLen);
			return null;
		}
		
		// RSA Decrypt
		BigInteger c = new BigInteger(cipherText);
		BigInteger m = rsa.decrypt(c);
		byte[] out = unPad(m.toByteArray(), label);		
		return out;
	}
}
