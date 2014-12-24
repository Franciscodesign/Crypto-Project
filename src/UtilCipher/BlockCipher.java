package UtilCipher;


/**
 * BlockCipher.java TODO:
 * 
 * @author Kim Dinh Son Email:sonkdbk@gmail.com
 */

public abstract class BlockCipher extends Cipher {
	private byte[] cipherT;
	private byte[] clearT;
	
	public BlockCipher(int keySize, int blockSize) {
		super(keySize);
		this.blockSize = blockSize;
	}

	public int blockSize;

	public int blockSize() {
		return blockSize;
	}

	public abstract void encrypt(byte[] clearText, int clearOff,
			byte[] cipherText, int cipherOff);

	public abstract void decrypt(byte[] cipherText, int cipherOff,
			byte[] clearText, int clearOff) throws InvalidCipherTextException;

	public void encrypt(byte[] clearText, byte[] cipherText) {
		encrypt(clearText, 0, cipherText, 0);
	}

	public void decrypt(byte[] cipherText, byte[] clearText) throws InvalidCipherTextException {
		decrypt(cipherText, 0, clearText, 0);
	}
	
	/**
	 * @return the cipherT
	 */
	public byte[] getCipherT() {
		return cipherT;
	}

	/**
	 * @param cipherT the cipherT to set
	 */
	public void setCipherT(byte[] cipherT) {
		this.cipherT = cipherT;
	}

	/**
	 * @return the clearT
	 */
	public byte[] getClearT() {
		return clearT;
	}

	/**
	 * @param clearT the clearT to set
	 */
	public void setClearT(byte[] clearT) {
		this.clearT = clearT;
	}

}