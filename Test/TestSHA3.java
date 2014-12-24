package Test;

import java.io.UnsupportedEncodingException;

import SHA3.Keccak;
import UtilCipher.Printer;

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
		byte[] mData = args[0].getBytes();
		sha3.update(mData, mData.length);
		byte[] hash = new byte[sha3.getC()/16];
		hash = sha3.getHash(hash);

		Printer.printVector(hash);
		System.out.println();
	}
}
