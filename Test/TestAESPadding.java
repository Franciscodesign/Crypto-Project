package Test;

import java.io.UnsupportedEncodingException;

import AES.AES;
import UtilCipher.InvalidCipherTextException;
import UtilCipher.Printer;

/**
 * TestAESPadding.java
 * TODO: 
 *
 * @author Kim Dinh Son
 * Email:sonkdbk@gmail.com
 */

public class TestAESPadding {
	public static void main(String[] args) throws UnsupportedEncodingException, InvalidCipherTextException{
//		String plaintext = "I am madly, deeply, truly, passionately in love with you. I am madly, deeply, truly, passionately in love with you";
//		String cipherKey = "2b28ab097eaef7cf15d2154f16a6883c";
		AES aes = new AES(4,4);
		aes.setPadPKCS5(true);
		String plaintext = args[0];
		String cipherKey = args[1];
		
		// AES-128: keySize = 4, blockSize = 4
		// result NO Padding = 3902dc1925dc116a8409850b1dfb973256986fcc5b186fe7c42c28d5773f
		// result Padding = 42812363061d4575377b2580b82c35d956986fcc5b186fe7c42c28d5773f
		aes.encrypt(plaintext.getBytes(), UtilCipher.Util.convertStringToVector(cipherKey));
		Printer.printVector(aes.getCipherT());
		
		System.out.println();
		aes.decrypt(aes.getCipherT(), UtilCipher.Util.convertStringToVector(cipherKey));
		System.out.println(new String(aes.getClearT()));
		
	}
}
