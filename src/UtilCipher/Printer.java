package UtilCipher;

import java.io.UnsupportedEncodingException;

import SHA3.Util;

/**
 * Printer.java
 * TODO: 
 *
 * @author Kim Dinh Son
 * Email:sonkdbk@gmail.com
 */

public class Printer {
	public static void printVector(String name, byte[] b){
		System.out.printf(name + ": ");
		for (int i = 0; i < b.length; i++){ 
            System.out.printf(Util.byteToHex(b[i]));
		}
		System.out.println();
	}
	
	public static String printVector(byte[] b) throws UnsupportedEncodingException{
		for (int i = 0; i < b.length; i++){
            System.out.printf(Util.byteToHex(b[i]));
            if (i < (b.length - 1)){
            	//System.out.printf(" ");
            }
		}
		return new String(b, "UTF-8");
	}
	
	public static void printVectorAsPlainText(String name, byte[] b){
		System.out.printf(name + ": ");
		for (int i = 0; i < b.length; i++){ 
            System.out.printf(Util.byteToHex(b[i]));
		}
		System.out.println();
	}
	
	public static String getVectorAsPlainText(byte[] b){
		String vectorString = new String();
		for (int i = 0; i < b.length; i++){ 
            vectorString += Util.byteToHex(b[i]);
		}
		return vectorString;
	}
	
	public static void printMatrix(String name, byte[][] b) throws UnsupportedEncodingException{
		System.out.println(name);
		for (int i = 0; i < b.length; i++){ 
			printVector(b[i]);
		}
		System.out.println();
	}
}
