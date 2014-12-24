package Test;

import ShareFile.Encryption;
import UtilCipher.Printer;

/**
 * TestShareFile.java
 * TODO: 
 *
 * @author Kim Dinh Son
 * Email:sonkdbk@gmail.com
 */

public class TestShareFile {
	public static void main(String[] args) throws Exception{
		
		String dataInput = "I am madly, deeply, truly, passionately in love with you";
		Encryption enc = new Encryption();
		test3User(enc, dataInput);

	}
	
	public static void test3User(Encryption enc, String dataInput ) throws Exception{
		//Printer.printVector(enc.genFile1(dataInput));
		byte[] output = enc.manager(enc.genKey(dataInput));
		System.out.println("\n Output: ");
		Printer.printVector(output);
		
		System.out.println("\n Private keys: ");
		System.out.print("\n kA: ");
		Printer.printVector(enc.getkA());
		System.out.print("\n kB: ");
		Printer.printVector(enc.getkB());
		System.out.print("\n kC: ");
		Printer.printVector(enc.getkC());
		
		System.out.print("\n\nInformation Security: \n");
		System.out.print("\nPerson A: ");
		enc.getPA().getInformationSecurity();
		System.out.print("\nPerson B: ");
		enc.getPB().getInformationSecurity();
		System.out.print("\nPerson C: ");
		enc.getPC().getInformationSecurity();
		
		// test 3 users
		System.out.print(new String(enc.getPA().decrypt(output, 3)));
	}
	
	public static byte[] test(Encryption enc, String dataInput) throws Exception{
		// add User
		byte[] output = enc.manager(enc.genKey(dataInput));
		enc.addNewUser(output);
		enc.addNewUser(output);
		enc.addNewUser(output);
		enc.setAddNewUserAvaliable(false);
		// sync
		enc.syncManager(output);

		return output;
	}
	
	public static void testUser(Encryption enc, byte[] output,int id) throws Exception{
		if (id < enc.maxUser) {
			// test user 1
			System.out.print(new String(enc.getListUsers().get(id).decrypt(output, enc.maxUser)));
		}
	}
}
