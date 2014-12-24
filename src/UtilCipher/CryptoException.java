package UtilCipher;

/**
 * CryptoException.java
 * TODO: 
 *
 * @author Kim Dinh Son
 * Email:sonkdbk@gmail.com
 */

public class CryptoException extends Exception {
	/**
	 * 
	 */
	private static final long serialVersionUID = -1440196127446934116L;

	/**
	 * base constructor.
	 */
	public CryptoException() {
	}

	/**
	 * create a CryptoException with the given message.
	 * 
	 * @param message the message to be carried with the exception.
	 */
	public CryptoException(String message) {
		super(message);
	}
}
