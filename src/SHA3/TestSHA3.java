package SHA3;

import java.io.UnsupportedEncodingException;

/**
 * TestSHA3.java
 * TODO: 
 *
 * @author Kim Dinh Son
 * Email:sonkdbk@gmail.com
 */

public class TestSHA3 {
	private static int bitrate = 256;
	private static int diversifier = 0;
	
	public static void main(String[] args) throws UnsupportedEncodingException{
		Keccak sha3 = new Keccak();
		sha3.setBitRate(bitrate);
		sha3.setDiversifier(diversifier);
		
		sha3.init(bitrate);
		byte[] mData = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq".getBytes();
		sha3.update(mData, mData.length);
		byte[] hash = new byte[sha3.getC()/16];
		hash = sha3.getHash(hash);

		Printer.printVector(hash);
		System.out.println();
	
	}
}
