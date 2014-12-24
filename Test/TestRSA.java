package Test;

import java.math.BigInteger;

import RSA.RSA;

/**
 * TestRSA.java
 * TODO: 
 *
 * @author Kim Dinh Son
 * Email:sonkdbk@gmail.com
 */

public class TestRSA {
	public static void main(String[] args) throws Exception {
		RSA rsa = new RSA(Integer.parseInt(args[1]));
		rsa.generateKeys();
		String text1 = args[0]; //test
		System.out.println("Plaintext: " + text1);
		BigInteger plaintext1 = new BigInteger(text1.getBytes());

		// encryption
		BigInteger ciphertext = rsa.encrypt(plaintext1);
		System.out.println("Ciphertext: " + ciphertext);
		
		// decryption
		BigInteger plaintext2 = rsa.decrypt(ciphertext);
		String text2 = new String(plaintext2.toByteArray());
		System.out.println("Plaintext: " + text2);
	}
}
