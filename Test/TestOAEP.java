package Test;

import java.io.UnsupportedEncodingException;

import RSA.OAEP;
import UtilCipher.Printer;

/**
 * TestOAEP.java TODO:
 * 
 * @author Kim Dinh Son Email:sonkdbk@gmail.com
 */

public class TestOAEP {

	/**
	 * @param args
	 * @throws Exception
	 * @throws UnsupportedEncodingException
	 */
	public static void main(String[] args) throws UnsupportedEncodingException,
			Exception {
		// TODO Auto-generated method stub
		// OAEP test
		String myMessage = args[0];
		String label = "RSA-OAEP";
		byte[] m1 = OAEP.pad(myMessage.getBytes("UTF-8"),
				myMessage.length() + 32 + 32 + 1, label);

		System.out.println("OAEP test:");
		Printer.printVector(m1);
		System.out.println("\nDecode: "
				+ new String(OAEP.unPad(m1, label), "UTF-8"));
		System.out.println();
	}

}
