package Test;

import RSA.OAEP;
import RSA.RSA;
import UtilCipher.Printer;

/**
 * TestOAEP_RSA.java
 * TODO: 
 *
 * @author Kim Dinh Son
 * Email:sonkdbk@gmail.com
 */

public class TestOAEP_RSA {
	
	public static void main(String[] args) throws Exception {
		
		// RSA-OAEP test
		System.out.println("RSA-OAEP test:");
		RSA rsa_1 = new RSA(2048);		
		//rsa_1.generateKeys();
		while (!test(rsa_1, args[0], args[1])){
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
