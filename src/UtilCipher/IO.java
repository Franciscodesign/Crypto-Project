package UtilCipher;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;

/**
 * IO.java TODO:
 * 
 * @author Kim Dinh Son Email:sonkdbk@gmail.com
 */

public class IO {
	private static FileInputStream fis;

	public static byte[] readFile(String filePath) throws java.io.IOException {
		File file = new File(filePath);
		fis = new FileInputStream(file);
		byte[] data = new byte[(int) file.length()];
		fis.read(data, 0, (int) file.length());
		return data;
	}

	public static boolean saveFile(String filePath, byte[] data)
			throws IOException {
		File file = new File(filePath);
		FileOutputStream fis = new FileOutputStream(file);
		fis.write(data);
		fis.close();
		return true;
	}
}
