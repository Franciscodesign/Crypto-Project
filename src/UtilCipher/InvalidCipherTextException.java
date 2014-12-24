package UtilCipher;

/**
 * InvalidCipherTextException.java
 * TODO: 
 *
 * @author Kim Dinh Son
 * Email:sonkdbk@gmail.com
 */

public class InvalidCipherTextException extends CryptoException {
	/**
	 * 
	 */
	private static final long serialVersionUID = 3113126262746007437L;

	/**
	 * base constructor.
	 */
	public InvalidCipherTextException() {
	}

	/**
	 * create a InvalidCipherTextException with the given message.
	 * 
	 * @param message the message to be carried with the exception.
	 */
	public InvalidCipherTextException(String message) {
		super(message);
	}
}
