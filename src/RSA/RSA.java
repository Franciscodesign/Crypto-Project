package RSA;

import java.math.BigInteger;

import PrimeNumber.GenPrime;

/**
 * RSA.java TODO:
 * 
 * @author Kim Dinh Son Email:sonkdbk@gmail.com
 */

public class RSA {
	private BigInteger n, d, e, p, q;

	private int bitlen;

	public RSA(int bits) {
		setBitlen(bits);
		//generateKeys(bitlen);
	}
	
	/**
	 * @param input: p, q, e
	 * initial RSA with fixed n,p,q,e 
	 */
	public RSA(BigInteger p,  BigInteger q, BigInteger e) {
		setP(p);
		setQ(q);
		setE(e);
		setN(p.multiply(q));
		BigInteger m = (p.subtract(BigInteger.ONE)).multiply(q
				.subtract(BigInteger.ONE));
		setD(e.modInverse(m));
	}
	
	// generate keys (e,n) and (d,p,q)
	public synchronized void generateKeys() {
//		SecureRandom r = new SecureRandom();
//		BigInteger p = new BigInteger(bitlen / 2, 100, r);
//		BigInteger q = new BigInteger(bitlen / 2, 100, r);
			
		p = new GenPrime().genPrime(bitlen/2);
		q = new GenPrime().genPrime(bitlen/2);
		n = p.multiply(q);
		BigInteger m = (p.subtract(BigInteger.ONE)).multiply(q
				.subtract(BigInteger.ONE)); // m = (p-1) * (q-1)
		
		e = new BigInteger("3");
		while (m.gcd(e).intValue() > 1) {
			e = e.add(new BigInteger("2"));
		}
		d = e.modInverse(m);
		
	}

	public synchronized String encrypt(String message) {
		return (new BigInteger(message.getBytes())).modPow(e, n).toString();
	}

	public synchronized BigInteger encrypt(BigInteger message) {
		return message.modPow(e, n);
	}

	public synchronized String decrypt(String message) {
		return new String((new BigInteger(message)).modPow(d, n).toByteArray());
	}

	public synchronized BigInteger decrypt(BigInteger message) {
		return message.modPow(d, n);
	}

	public synchronized BigInteger getN() {
		return n;
	}

	public synchronized BigInteger getE() {
		return e;
	}
	
	public synchronized BigInteger getD() {
		return d;
	}
	
	public synchronized BigInteger getP() {
		return p;
	}
	
	public synchronized BigInteger getQ() {
		return q;
	}
	
	public void setN(BigInteger n1){
		n = n1;
	}
	
	public void setD(BigInteger d1){
		d = d1;
	}
	
	public void setP(BigInteger p1){
		p = p1;
	}
	
	public void setQ(BigInteger q1){
		q = q1;
	}
	
	public void setE(BigInteger e1){
		e = e1;
	}

	/**
	 * @return the bitlen
	 */
	public int getBitlen() {
		return bitlen;
	}

	/**
	 * @param bitlen the bitlen to set
	 */
	public void setBitlen(int bitlen) {
		this.bitlen = bitlen;
	}
}
