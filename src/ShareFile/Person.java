package ShareFile;

import java.math.BigInteger;

import AES.AES;
import RSA.OAEP;
import RSA.RSA;

/**
 * Person.java
 * TODO: 
 *
 * @author Kim Dinh Son
 * Email:sonkdbk@gmail.com
 */

public class Person {
	public BigInteger n, e; 
	private BigInteger d, p, q;
	private int id;
	
	private byte[] keyPrivate;
	
	public Person(RSA rsa) throws Exception{
		n = rsa.getN();
		e = rsa.getE();
		setD(rsa.getD());
		setP(rsa.getP());
		setQ(rsa.getQ());
	}
	
	public byte[] decrypt(byte[] cipher, int maxUser) throws Exception{
		RSA rsa = new RSA(getP(), getQ(), e);
//		byte[] text = new byte[256]; // AES(4,4)
//		int id = getId();		
//		System.arraycopy(cipher, cipher.length - (maxUser-id+1) * 256, text, 0, 256);
		
		System.out.println("test rsa "+rsa.getN().bitLength());
		BigInteger k = rsa.decrypt(new BigInteger(OAEP.decrypt(keyPrivate, rsa, "RSA-OAEP")));

		byte[] g = new byte[cipher.length - 256 * maxUser];
		System.arraycopy(cipher, 0, g, 0, cipher.length - 256 * maxUser);
		AES aes = new AES(4, 4);
		aes.decrypt(g, k.toByteArray());
		return aes.getClearT();
	}
	
	public void getInformationSecurity() {
		System.out.println("\n\tP = " + getP() + "\n\tQ = " + getQ()
				+ "\n\tD = " + getD() + "\n\tn = " + n + "\n\te = " + e);
	}

	/**
	 * @return the p
	 */
	public BigInteger getP() {
		return p;
	}
	/**
	 * @param p the p to set
	 */
	public void setP(BigInteger p) {
		this.p = p;
	}
	/**
	 * @return the q
	 */
	public BigInteger getQ() {
		return q;
	}
	/**
	 * @param q the q to set
	 */
	public void setQ(BigInteger q) {
		this.q = q;
	}
	/**
	 * @return the d
	 */
	public BigInteger getD() {
		return d;
	}
	/**
	 * @param d the d to set
	 */
	public void setD(BigInteger d) {
		this.d = d;
	}
	
	/**
	 * @param e the e to set
	 */
	public void setE(BigInteger e) {
		this.e = e;
	}

	/**
	 * @return the keyPrivate
	 */
	public byte[] getKeyPrivate() {
		return keyPrivate;
	}

	/**
	 * @param keyPrivate the keyPrivate to set
	 */
	public void setKeyPrivate(byte[] keyPrivate) {
		this.keyPrivate = keyPrivate;
	}

	/**
	 * @return the id
	 */
	public int getId() {
		return id;
	}

	/**
	 * @param id the id to set
	 */
	public void setId(int id) {
		this.id = id;
	}
}
