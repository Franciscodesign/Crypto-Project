package UtilCipher;

import java.security.SecureRandom;

/**
 * PKCS5Padding.java TODO:
 * 
 * @author Kim Dinh Son Email:sonkdbk@gmail.com
 */

public class PKCS5Padding implements BlockCipherPadding {
	/**
	 * Initialise the padder.
	 * 
	 * @param random
	 * - a SecureRandom if available.
	 */
	public void init(SecureRandom random) throws IllegalArgumentException {
		// nothing to do.
	}

	/**
	 * @return the name of the algorithm the padder implements.
	 */
	public String getPaddingName() {
		return "PKCS5";
	}

	/**inOff: 0 to 15
	 * add the pad bytes to the passed in block, returning the number of bytes
	 * added.
	 */
	public int addPadding(byte[] in, int inOff) {
		byte code = (byte) (inOff);
		byte[] padded = new byte[in.length + inOff];
		System.arraycopy(in, 0, padded, 0, in.length);
		int add = in.length;
		while (add < in.length+inOff) {
			padded[add] = code;
			add++;
		}
		in = padded;
		System.out.println(Util.byteToHex(in));
		return code;
	}

	/**
	 * return the number of pad bytes present in the block.
	 */
	public int padCount(byte[] in) throws InvalidCipherTextException {
		int count = in[in.length - 1] & 0xff;

		if (count > in.length || count == 0) {
			throw new InvalidCipherTextException("pad block corrupted");
		}

		for (int i = 1; i <= count; i++) {
			if (in[in.length - i] != count) {
				throw new InvalidCipherTextException("pad block corrupted");
			}
		}

		return count;
	}
}
