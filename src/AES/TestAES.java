package AES;

import java.io.UnsupportedEncodingException;

import SHA3.Util;
import UtilCipher.CBCBlockCipher;
import UtilCipher.InvalidCipherTextException;
import UtilCipher.Printer;

/**
 * TestAES.java
 * TODO: 
 *
 * @author Kim Dinh Son
 * Email:sonkdbk@gmail.com
 */

public class TestAES { 
	public static void main(String[] args) throws InvalidCipherTextException, UnsupportedEncodingException{
		String plaintext = "I am madly, deeply, truly, passionately in love with you. I am madly, deeply, truly, passionately in love with you";
		String cipherKey = "2b28ab097eaef7cf15d2154f16a6883c";
		AES aes = new AES(4,4);
		aes.setPadPKCS5(true);
		
		// AES-128: keySize = 4, blockSize = 4
		// result NO Padding = 3902dc1925dc116a8409850b1dfb973256986fcc5b186fe7c42c28d5773f
		// result Padding = 42812363061d4575377b2580b82c35d956986fcc5b186fe7c42c28d5773f
		aes.encrypt(plaintext.getBytes(), UtilCipher.Util.convertStringToVector(cipherKey));
		Printer.printVector(aes.getCipherT());
		
		System.out.println();
		aes.decrypt(aes.getCipherT(), UtilCipher.Util.convertStringToVector(cipherKey));
		System.out.println(new String(aes.getClearT()));
		
		System.out.println("\ntest CBC-AES-NoPKCS5");
		// test CBC-AES
		AES aes1 = new AES(4,4);
		//aes1.setPadPKCS5(true);
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
