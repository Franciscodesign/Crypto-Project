package UtilCipher;


/**
 * CBCBlockCipher.java TODO:
 * 
 * @author Kim Dinh Son Email:sonkdbk@gmail.com
 */

public class CBCBlockCipher extends BlockCipher {
	
	private BlockCipher blockCipher;
	private byte[] iv;
	private byte[] ivReset;
	private byte[] tempV;

	public CBCBlockCipher(BlockCipher blockCipher) {
		super(blockCipher.keySize(), blockCipher.blockSize());
		this.blockCipher = blockCipher;
		iv = new byte[blockSize()*keySize];
		zeroBlock(iv);
		ivReset = iv;
		tempV = new byte[blockSize()*keySize]; 	// blockSize()*keySize
	}
	
	public BlockCipher getUnderlyingCipher() {
		return blockCipher;
	}

	// Key routines.

	// Set the key.
	public void setKey(byte[] key) {
		blockCipher.setKey(key);
	}

	// IV routines.
	public void setIv(byte[] iv) {
		copyBlock(iv, this.iv);
	}

	public byte[] setRandomIv() {
		byte[] riv = new byte[blockSize()*keySize];
		randomBlock(riv);
		ivReset = riv;
		setIv(riv);
		return riv;
	}
	
	public void resetIV(){
		setIv(ivReset);
	}

	// Block encryption routines.

	public void encrypt(byte[] clearText, int clearOff, byte[] cipherText,
			int cipherOff) {
		
		if ((clearOff + blockSize()*keySize) > clearText.length) {
		}
		xorBlock(clearText, clearOff, iv, 0, tempV, 0, blockSize()*keySize);
		blockCipher.encrypt(tempV, 0, cipherText, cipherOff);
		copyBlock(cipherText, cipherOff, iv, 0, blockSize()*keySize);
	}
	
	public void encrypt(byte[] clearText, byte[] cipherKey){
		int length = blockSize() * keySize;
		byte[] temp = new byte[length];
		int c = clearText.length / (length);
		byte[] cipherText = clearText;
		for (int i = 0; i < c; i++) {
			copyBlock(clearText, i * length, temp, 0, length);
			encrypt(temp, 0, cipherKey, 0);
			copyBlock(blockCipher.getCipherT(), 0, cipherText, i * length,
					length);
			resetIV();
		}

		copyBlock(clearText, c * length, temp, 0, clearText.length - c * length);
		encrypt(temp, 0, cipherKey, 0);
		copyBlock(blockCipher.getCipherT(), 0, cipherText, c * length, clearText.length - c * length);
		
		setCipherT(cipherText);
		
	}

	// / Decrypt a block of bytes.
	public void decrypt(byte[] cipherText, int cipherOff, byte[] clearText,
			int clearOff) throws InvalidCipherTextException {
		blockCipher.decrypt(cipherText, cipherOff, clearText, 0);
		xorBlock(clearText, 0, iv, 0, clearText, clearOff, blockSize()
				* keySize);
		copyBlock(cipherText, cipherOff, iv, 0, blockSize() * keySize);
	}
	
	public void decrypt(byte[] cipherText, byte[] cipherKey) throws InvalidCipherTextException{
		int length = blockSize() * keySize;
		byte[] temp = new byte[length];
		int c = cipherText.length / (length);
		byte[] clearText = cipherText;
		for (int i = 0; i < c; i++) {
			copyBlock(cipherText, i * length, temp, 0, length);
			decrypt(temp, 0, cipherKey, 0);
			copyBlock(blockCipher.getClearT(), 0, clearText, i * length, length);
			resetIV();
		}
		
		copyBlock(cipherText, c * length, temp, 0, cipherText.length - c * length);
		decrypt(temp, 0, cipherKey, 0);
		copyBlock(blockCipher.getClearT(), 0, clearText, c * length, cipherText.length - c * length);
		
		setClearT(clearText);
		
	}
}
