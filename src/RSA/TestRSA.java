package RSA;

import java.math.BigInteger;

import UtilCipher.Printer;

/**
 * TestShareFile.java
 * TODO: 
 *
 * @author Kim Dinh Son
 * Email:sonkdbk@gmail.com
 */

public class TestRSA {

	public static void main(String[] args) throws Exception {
		RSA rsa = new RSA(6142);
		rsa.generateKeys();
		String text1 = "I am madly, deeply, truly, passionately in love with you"; //test
		System.out.println("Plaintext: " + text1);
		BigInteger plaintext1 = new BigInteger(text1.getBytes());

		// encryption
		BigInteger ciphertext = rsa.encrypt(plaintext1);
		System.out.println("Ciphertext: " + ciphertext);
		
		// decryption
		BigInteger plaintext2 = rsa.decrypt(ciphertext);
		String text2 = new String(plaintext2.toByteArray());
		System.out.println("Plaintext: " + text2);
	
		// OAEP test
		String myMessage = "I am madly, deeply, truly, passionately in love with you";
		String label = "RSA-OAEP";
		byte[] m1 = OAEP.pad(myMessage.getBytes("UTF-8"), myMessage.length()+32+32+1, label);

		System.out.println("OAEP test:");
		Printer.printVector(m1);
		System.out.println("\nDecode: "+new String(OAEP.unPad(m1, label), "UTF-8"));
		System.out.println();
		
		// test file
		String filename = "1000Primes.txt";
		byte[] dataFile = UtilCipher.IO.readFile("src\\"+filename);
		byte[] em = OAEP.pad(dataFile, dataFile.length+32+32+1, label);
		UtilCipher.IO.saveFile("src\\Decode_"+filename, OAEP.unPad(em, label));
		
		// RSA-OAEP test
		System.out.println("RSA-OAEP test:");
		RSA rsa_1 = new RSA(2048);		
		//rsa_1.generateKeys();
		while (!test(rsa_1, myMessage, label)){			
		}

	}
	
	public static boolean test(RSA rsa_1, String myMessage, String label)
			throws Exception {
		rsa_1.generateKeys();
		// Encode
		byte[] m = OAEP.encrypt(myMessage.getBytes(), rsa_1,
				myMessage.getBytes().length + 32 + 32 + 1, label);

		// Decode
		byte[] mm = OAEP.decrypt(m, rsa_1, label);
		if (mm == null) {
			System.out.println("Decoding error. Test again.\n");
			return false;
		} else {
			System.out.println("\nFinish test\nDecode: "
					+ Printer.printVector(mm));
			return true;
		}
	}
}
