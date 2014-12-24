package Test;

import java.io.UnsupportedEncodingException;

import AES.AES;
import UtilCipher.CBCBlockCipher;
import UtilCipher.InvalidCipherTextException;
import UtilCipher.Printer;

/**
 * TestCBC_AES_PKCS5.java
 * TODO: 
 *
 * @author Kim Dinh Son
 * Email:sonkdbk@gmail.com
 */

public class TestCBC_AES_PKCS5 {
	public static void main(String[] args) throws InvalidCipherTextException, UnsupportedEncodingException{
//		String plaintext = "I am madly, deeply, truly, passionately in love with you. I am madly, deeply, truly, passionately in love with you";
//		String cipherKey = "2b28ab097eaef7cf15d2154f16a6883c";
		AES aes = new AES(4,4);
		aes.setPadPKCS5(true);
		
		String plaintext = args[0];
		String cipherKey = args[1];
		
		System.out.println("\ntest CBC-AES-NoPKCS5");
		// test CBC-AES
		AES aes1 = new AES(4,4);
		aes1.setPadPKCS5(true);
		CBCBlockCipher cbc = new CBCBlockCipher(aes1);
		//cbc.setIv(cbc.toByteArray(iv));
		cbc.setRandomIv();
		cbc.setKey(cipherKey);
		cbc.encrypt(plaintext.getBytes(),UtilCipher.Util.convertStringToVector(cipherKey));
		Printer.printVector(cbc.getCipherT());
		System.out.println("\n");
		cbc.decrypt(cbc.getCipherT(), UtilCipher.Util.convertStringToVector(cipherKey));
		Printer.printVector(cbc.getClearT());
		System.out.println("\n"+new String(cbc.getClearT()));
				
	}
}
