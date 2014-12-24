package ShareFile;

import java.util.ArrayList;

import AES.AES;
import RSA.OAEP;
import RSA.RSA;
import UtilCipher.CBCBlockCipher;
import UtilCipher.Util;

/**
 * Encryption.java TODO:
 * 
 * @author Kim Dinh Son Email:sonkdbk@gmail.com
 */

public class Encryption {
	private static String key = "2b7e151628aed2a6abf7158809cf4f3c";
	static byte[] keyTemp = null;
	private static byte[] kA;
	private static byte[] kB;
	private static byte[] kC;
	
	private ArrayList<byte[]> listKeys = new ArrayList<>();
	private ArrayList<Person> listUsers = new ArrayList<>();

	private static Person PA;
	private static Person PB;
	private static Person PC;
	
	private static Person PX; // temp
	
	public int maxUser = 0;

	/*
	 * key: random generation dataInput: file data Encryption: AES-CBC
	 */
	public byte[] genKey(String dataInput) {
		AES aes = new AES(4, 4);
		// random key

		CBCBlockCipher cbc = new CBCBlockCipher(aes);
		cbc.setKey(key);
		cbc.setRandomIv();
		cbc.encrypt(dataInput.getBytes(), UtilCipher.Util.convertStringToVector(key));
		return cbc.getCipherT();
	}

	public byte[] manager(byte[] g) throws Exception {
		while (kA == null)
			kA = updatePerson(1);
		setPA(PX);
		maxUser++;
		while (kB == null)
			kB = updatePerson(2);
		setPB(PX);
		maxUser++;
		while (kC == null)
			kC = updatePerson(3);
		setPC(PX);
		maxUser++;
		
		// g = g || kA || kB || kC
		g = Util.concat(g, kA);
		g = Util.concat(g, kB);
		g = Util.concat(g, kC);
		return g;
	}
	
	public byte[] addNewUser(byte[] g) throws Exception{
		byte[] key = null;
		while (key == null)
			key = updatePerson(++maxUser);
		setPC(PX);
		listKeys.add(key);
		listUsers.add(PX);
		return g;
	}

	public static byte[] updatePerson(int id) throws Exception {
		RSA rsa = new RSA(2048);
		while (!setKey(rsa, key.getBytes("UTF-8"), "RSA-OAEP")){
		}

		Person X = new Person(rsa);
		X.setId(id);
		X.setKeyPrivate(keyTemp);
		setPX(X);
		System.out.println(">>Done "+id+"\n");
		return keyTemp; // 256 octet
	}
	
	public static boolean setKey(RSA rsa, byte[] ciphertext, String label) throws Exception{
		// Encrypt	
		rsa.generateKeys();
		keyTemp = OAEP.encrypt(ciphertext, rsa, ciphertext.length+32+32+1, label);	

		// check decrypt
		byte[] m = OAEP.decrypt(keyTemp, rsa, label);
		if (m == null) {
			System.out.println("Decrypt error. Set key again.\n");
			return false;
		}
		else {
			return true;
		}
	}

	/**
	 * @return the kA
	 */
	public byte[] getkA() {
		return kA;
	}

	/**
	 * @param k the kA to set
	 */
	public static void setkA(byte[] k) {
		kA = k;
	}

	/**
	 * @return the kB
	 */
	public byte[] getkB() {
		return kB;
	}

	/**
	 * @param k the kB to set
	 */
	public static void setkB(byte[] k) {
		kB = k;
	}

	/**
	 * @return the kC
	 */
	public byte[] getkC() {
		return kC;
	}

	/**
	 * @param k the kC to set
	 */
	public static void setkC(byte[] k) {
		kC = k;
	}
	
	public Person getPA() {
		return PA;
	}

	public static void setPA(Person PP) {
		 PA = PP;
	}
	public Person getPB() {
		return PB;
	}

	public static void setPB(Person PP) {
		 PB = PP;
	}
	
	public Person getPC() {
		return PC;
	}

	public static void setPC(Person PP) {
		 PC = PP;
	}

	/**
	 * @return the pX
	 */
	public static Person getPX() {
		return PX;
	}

	/**
	 * @param pX the pX to set
	 */
	public static void setPX(Person pX) {
		PX = pX;
	}

}
