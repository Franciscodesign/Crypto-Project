package AES;

import java.util.LinkedList;
import java.util.List;

import UtilCipher.BlockCipher;
import UtilCipher.InvalidCipherTextException;
import UtilCipher.PKCS5Padding;

/**
 * AES.java TODO:
 * 
 * @author Kim Dinh Son Email:sonkdbk@gmail.com
 */

public class AES extends BlockCipher {

	private boolean padPKCS5 = false;
	/**
	 * @param keySize = 4
	 * @param blockSize = 4
	 * => 16 byte = 128 bits
	 */
	public AES(int keyLength, int blockSize) {
		super(keyLength, blockSize);
		// TODO Auto-generated constructor stub
		// test();
	}

	private final int nRound = 10;

	private final byte[] Sbox = { 0x63, 0x7c, 0x77, 0x7b, (byte) 0xf2, 0x6b,
			0x6f, (byte) 0xc5, 0x30, 0x01, 0x67, 0x2b, (byte) 0xfe,
			(byte) 0xd7, (byte) 0xab, 0x76, (byte) 0xca, (byte) 0x82,
			(byte) 0xc9, 0x7d, (byte) 0xfa, 0x59, 0x47, (byte) 0xf0,
			(byte) 0xad, (byte) 0xd4, (byte) 0xa2, (byte) 0xaf, (byte) 0x9c,
			(byte) 0xa4, 0x72, (byte) 0xc0, (byte) 0xb7, (byte) 0xfd,
			(byte) 0x93, 0x26, 0x36, 0x3f, (byte) 0xf7, (byte) 0xcc, 0x34,
			(byte) 0xa5, (byte) 0xe5, (byte) 0xf1, 0x71, (byte) 0xd8, 0x31,
			0x15, 0x04, (byte) 0xc7, 0x23, (byte) 0xc3, 0x18, (byte) 0x96,
			0x05, (byte) 0x9a, 0x07, 0x12, (byte) 0x80, (byte) 0xe2,
			(byte) 0xeb, 0x27, (byte) 0xb2, 0x75, 0x09, (byte) 0x83, 0x2c,
			0x1a, 0x1b, 0x6e, 0x5a, (byte) 0xa0, 0x52, 0x3b, (byte) 0xd6,
			(byte) 0xb3, 0x29, (byte) 0xe3, 0x2f, (byte) 0x84, 0x53,
			(byte) 0xd1, 0x00, (byte) 0xed, 0x20, (byte) 0xfc, (byte) 0xb1,
			0x5b, 0x6a, (byte) 0xcb, (byte) 0xbe, 0x39, 0x4a, 0x4c, 0x58,
			(byte) 0xcf, (byte) 0xd0, (byte) 0xef, (byte) 0xaa, (byte) 0xfb,
			0x43, 0x4d, 0x33, (byte) 0x85, 0x45, (byte) 0xf9, 0x02, 0x7f, 0x50,
			0x3c, (byte) 0x9f, (byte) 0xa8, 0x51, (byte) 0xa3, 0x40,
			(byte) 0x8f, (byte) 0x92, (byte) 0x9d, 0x38, (byte) 0xf5,
			(byte) 0xbc, (byte) 0xb6, (byte) 0xda, 0x21, 0x10, (byte) 0xff,
			(byte) 0xf3, (byte) 0xd2, (byte) 0xcd, 0x0c, 0x13, (byte) 0xec,
			0x5f, (byte) 0x97, 0x44, 0x17, (byte) 0xc4, (byte) 0xa7, 0x7e,
			0x3d, 0x64, 0x5d, 0x19, 0x73, 0x60, (byte) 0x81, 0x4f, (byte) 0xdc,
			0x22, 0x2a, (byte) 0x90, (byte) 0x88, 0x46, (byte) 0xee,
			(byte) 0xb8, 0x14, (byte) 0xde, 0x5e, 0x0b, (byte) 0xdb,
			(byte) 0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, (byte) 0xc2,
			(byte) 0xd3, (byte) 0xac, 0x62, (byte) 0x91, (byte) 0x95,
			(byte) 0xe4, 0x79, (byte) 0xe7, (byte) 0xc8, 0x37, 0x6d,
			(byte) 0x8d, (byte) 0xd5, 0x4e, (byte) 0xa9, 0x6c, 0x56,
			(byte) 0xf4, (byte) 0xea, 0x65, 0x7a, (byte) 0xae, 0x08,
			(byte) 0xba, 0x78, 0x25, 0x2e, 0x1c, (byte) 0xa6, (byte) 0xb4,
			(byte) 0xc6, (byte) 0xe8, (byte) 0xdd, 0x74, 0x1f, 0x4b,
			(byte) 0xbd, (byte) 0x8b, (byte) 0x8a, 0x70, 0x3e, (byte) 0xb5,
			0x66, 0x48, 0x03, (byte) 0xf6, 0x0e, 0x61, 0x35, 0x57, (byte) 0xb9,
			(byte) 0x86, (byte) 0xc1, 0x1d, (byte) 0x9e, (byte) 0xe1,
			(byte) 0xf8, (byte) 0x98, 0x11, 0x69, (byte) 0xd9, (byte) 0x8e,
			(byte) 0x94, (byte) 0x9b, 0x1e, (byte) 0x87, (byte) 0xe9,
			(byte) 0xce, 0x55, 0x28, (byte) 0xdf, (byte) 0x8c, (byte) 0xa1,
			(byte) 0x89, 0x0d, (byte) 0xbf, (byte) 0xe6, 0x42, 0x68, 0x41,
			(byte) 0x99, 0x2d, 0x0f, (byte) 0xb0, 0x54, (byte) 0xbb, 0x16 };

	private final byte[] iSbox = { 0x52, 0x09, 0x6a, (byte) 0xd5, 0x30, 0x36,
			(byte) 0xa5, 0x38, (byte) 0xbf, 0x40, (byte) 0xa3, (byte) 0x9e,
			(byte) 0x81, (byte) 0xf3, (byte) 0xd7, (byte) 0xfb, 0x7c,
			(byte) 0xe3, 0x39, (byte) 0x82, (byte) 0x9b, 0x2f, (byte) 0xff,
			(byte) 0x87, 0x34, (byte) 0x8e, 0x43, 0x44, (byte) 0xc4,
			(byte) 0xde, (byte) 0xe9, (byte) 0xcb, 0x54, 0x7b, (byte) 0x94,
			0x32, (byte) 0xa6, (byte) 0xc2, 0x23, 0x3d, (byte) 0xee, 0x4c,
			(byte) 0x95, 0x0b, 0x42, (byte) 0xfa, (byte) 0xc3, 0x4e, 0x08,
			0x2e, (byte) 0xa1, 0x66, 0x28, (byte) 0xd9, 0x24, (byte) 0xb2,
			0x76, 0x5b, (byte) 0xa2, 0x49, 0x6d, (byte) 0x8b, (byte) 0xd1,
			0x25, 0x72, (byte) 0xf8, (byte) 0xf6, 0x64, (byte) 0x86, 0x68,
			(byte) 0x98, 0x16, (byte) 0xd4, (byte) 0xa4, 0x5c, (byte) 0xcc,
			0x5d, 0x65, (byte) 0xb6, (byte) 0x92, 0x6c, 0x70, 0x48, 0x50,
			(byte) 0xfd, (byte) 0xed, (byte) 0xb9, (byte) 0xda, 0x5e, 0x15,
			0x46, 0x57, (byte) 0xa7, (byte) 0x8d, (byte) 0x9d, (byte) 0x84,
			(byte) 0x90, (byte) 0xd8, (byte) 0xab, 0x00, (byte) 0x8c,
			(byte) 0xbc, (byte) 0xd3, 0x0a, (byte) 0xf7, (byte) 0xe4, 0x58,
			0x05, (byte) 0xb8, (byte) 0xb3, 0x45, 0x06, (byte) 0xd0, 0x2c,
			0x1e, (byte) 0x8f, (byte) 0xca, 0x3f, 0x0f, 0x02, (byte) 0xc1,
			(byte) 0xaf, (byte) 0xbd, 0x03, 0x01, 0x13, (byte) 0x8a, 0x6b,
			0x3a, (byte) 0x91, 0x11, 0x41, 0x4f, 0x67, (byte) 0xdc,
			(byte) 0xea, (byte) 0x97, (byte) 0xf2, (byte) 0xcf, (byte) 0xce,
			(byte) 0xf0, (byte) 0xb4, (byte) 0xe6, 0x73, (byte) 0x96,
			(byte) 0xac, 0x74, 0x22, (byte) 0xe7, (byte) 0xad, 0x35,
			(byte) 0x85, (byte) 0xe2, (byte) 0xf9, 0x37, (byte) 0xe8, 0x1c,
			0x75, (byte) 0xdf, 0x6e, 0x47, (byte) 0xf1, 0x1a, 0x71, 0x1d, 0x29,
			(byte) 0xc5, (byte) 0x89, 0x6f, (byte) 0xb7, 0x62, 0x0e,
			(byte) 0xaa, 0x18, (byte) 0xbe, 0x1b, (byte) 0xfc, 0x56, 0x3e,
			0x4b, (byte) 0xc6, (byte) 0xd2, 0x79, 0x20, (byte) 0x9a,
			(byte) 0xdb, (byte) 0xc0, (byte) 0xfe, 0x78, (byte) 0xcd, 0x5a,
			(byte) 0xf4, 0x1f, (byte) 0xdd, (byte) 0xa8, 0x33, (byte) 0x88,
			0x07, (byte) 0xc7, 0x31, (byte) 0xb1, 0x12, 0x10, 0x59, 0x27,
			(byte) 0x80, (byte) 0xec, 0x5f, 0x60, 0x51, 0x7f, (byte) 0xa9,
			0x19, (byte) 0xb5, 0x4a, 0x0d, 0x2d, (byte) 0xe5, 0x7a,
			(byte) 0x9f, (byte) 0x93, (byte) 0xc9, (byte) 0x9c, (byte) 0xef,
			(byte) 0xa0, (byte) 0xe0, 0x3b, 0x4d, (byte) 0xae, 0x2a,
			(byte) 0xf5, (byte) 0xb0, (byte) 0xc8, (byte) 0xeb, (byte) 0xbb,
			0x3c, (byte) 0x83, 0x53, (byte) 0x99, 0x61, 0x17, 0x2b, 0x04, 0x7e,
			(byte) 0xba, 0x77, (byte) 0xd6, 0x26, (byte) 0xe1, 0x69, 0x14,
			0x63, 0x55, 0x21, 0x0c, 0x7d };

	public final byte[] Rcon = { (byte) 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10,
			0x20, 0x40, (byte) 0x80, 0x1b, 0x36, 0x6c, (byte) 0xd8,
			(byte) 0xab, 0x4d, (byte) 0x9a, 0x2f, 0x5e, (byte) 0xbc, 0x63,
			(byte) 0xc6, (byte) 0x97, 0x35, 0x6a, (byte) 0xd4, (byte) 0xb3,
			0x7d, (byte) 0xfa, (byte) 0xef, (byte) 0xc5, (byte) 0x91, 0x39,
			0x72, (byte) 0xe4, (byte) 0xd3, (byte) 0xbd, 0x61, (byte) 0xc2,
			(byte) 0x9f, 0x25, 0x4a, (byte) 0x94, 0x33, 0x66, (byte) 0xcc,
			(byte) 0x83, 0x1d, 0x3a, 0x74, (byte) 0xe8, (byte) 0xcb,
			(byte) 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, (byte) 0x80,
			0x1b, 0x36, 0x6c, (byte) 0xd8, (byte) 0xab, 0x4d, (byte) 0x9a,
			0x2f, 0x5e, (byte) 0xbc, 0x63, (byte) 0xc6, (byte) 0x97, 0x35,
			0x6a, (byte) 0xd4, (byte) 0xb3, 0x7d, (byte) 0xfa, (byte) 0xef,
			(byte) 0xc5, (byte) 0x91, 0x39, 0x72, (byte) 0xe4, (byte) 0xd3,
			(byte) 0xbd, 0x61, (byte) 0xc2, (byte) 0x9f, 0x25, 0x4a,
			(byte) 0x94, 0x33, 0x66, (byte) 0xcc, (byte) 0x83, 0x1d, 0x3a,
			0x74, (byte) 0xe8, (byte) 0xcb, (byte) 0x8d, 0x01, 0x02, 0x04,
			0x08, 0x10, 0x20, 0x40, (byte) 0x80, 0x1b, 0x36, 0x6c, (byte) 0xd8,
			(byte) 0xab, 0x4d, (byte) 0x9a, 0x2f, 0x5e, (byte) 0xbc, 0x63,
			(byte) 0xc6, (byte) 0x97, 0x35, 0x6a, (byte) 0xd4, (byte) 0xb3,
			0x7d, (byte) 0xfa, (byte) 0xef, (byte) 0xc5, (byte) 0x91, 0x39,
			0x72, (byte) 0xe4, (byte) 0xd3, (byte) 0xbd, 0x61, (byte) 0xc2,
			(byte) 0x9f, 0x25, 0x4a, (byte) 0x94, 0x33, 0x66, (byte) 0xcc,
			(byte) 0x83, 0x1d, 0x3a, 0x74, (byte) 0xe8, (byte) 0xcb,
			(byte) 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, (byte) 0x80,
			0x1b, 0x36, 0x6c, (byte) 0xd8, (byte) 0xab, 0x4d, (byte) 0x9a,
			0x2f, 0x5e, (byte) 0xbc, 0x63, (byte) 0xc6, (byte) 0x97, 0x35,
			0x6a, (byte) 0xd4, (byte) 0xb3, 0x7d, (byte) 0xfa, (byte) 0xef,
			(byte) 0xc5, (byte) 0x91, 0x39, 0x72, (byte) 0xe4, (byte) 0xd3,
			(byte) 0xbd, 0x61, (byte) 0xc2, (byte) 0x9f, 0x25, 0x4a,
			(byte) 0x94, 0x33, 0x66, (byte) 0xcc, (byte) 0x83, 0x1d, 0x3a,
			0x74, (byte) 0xe8, (byte) 0xcb, (byte) 0x8d, 0x01, 0x02, 0x04,
			0x08, 0x10, 0x20, 0x40, (byte) 0x80, 0x1b, 0x36, 0x6c, (byte) 0xd8,
			(byte) 0xab, 0x4d, (byte) 0x9a, 0x2f, 0x5e, (byte) 0xbc, 0x63,
			(byte) 0xc6, (byte) 0x97, 0x35, 0x6a, (byte) 0xd4, (byte) 0xb3,
			0x7d, (byte) 0xfa, (byte) 0xef, (byte) 0xc5, (byte) 0x91, 0x39,
			0x72, (byte) 0xe4, (byte) 0xd3, (byte) 0xbd, 0x61, (byte) 0xc2,
			(byte) 0x9f, 0x25, 0x4a, (byte) 0x94, 0x33, 0x66, (byte) 0xcc,
			(byte) 0x83, 0x1d, 0x3a, 0x74, (byte) 0xe8, (byte) 0xcb,
			(byte) 0x8d };

	// Off: column keyExpand
	public byte[] getBockKey(List<byte[]> word, int Off) {
		byte[] block = new byte[4 * keySize];

		for (int i = 0; i < keySize; i++) { // row
			block[i] = word.get(Off)[i];
			block[keySize + i] = word.get(Off + 1)[i];
			block[2 * keySize + i] = word.get(Off + 2)[i];
			block[3 * keySize + i] = word.get(Off + 3)[i];
		}
		return block;

	}

	public byte[] subBytes(byte[] state) {
		byte[] subB = new byte[state.length];
		for (int i = 0; i < state.length; i++) {
			subB[i] = subByte(state[i]);
		}
		return subB;
	}

	public byte subByte(byte si) {
		int size = 4 * blockSize;
		int row = (si & 0xf0) >> 4;
		int col = si & 0x0f;
		return Sbox[row * size + col];
	}

	public byte[] shiftRows(byte[] state) {
		for (int i = 1; i < blockSize; i++) {
			shift(state, i, blockSize);
		}
		return state;
	}

	public void shift(byte[] state, int r, int Nb) {
		int index = r * Nb;
		for (int i = 0; i < r; i++) {
			byte temp = state[index];
			for (int j = 0; j < Nb - 1; j++) {
				state[index + j] = state[index + j + 1];
			}
			state[index + Nb - 1] = temp;
		}
	}

	// fix AES-128
	// polynomial: x^4+1
	public byte[] mixColums(byte[] state) {
		for (int c = 0; c < blockSize; c++) {
			byte s1 = (byte) (mulGF28((byte) 0x02, state[c])
					^ mulGF28((byte) 0x03, state[blockSize + c])
					^ state[2 * blockSize + c] ^ state[3 * blockSize + c]);

			byte s2 = (byte) (state[c]
					^ mulGF28((byte) 0x02, state[blockSize + c])
					^ mulGF28((byte) 0x03, state[2 * blockSize + c]) ^ state[3
					* blockSize + c]);

			byte s3 = (byte) (state[c] ^ state[blockSize + c]
					^ mulGF28((byte) 0x02, state[2 * blockSize + c]) ^ mulGF28(
					(byte) 0x03, state[3 * blockSize + c]));

			byte s4 = (byte) (mulGF28((byte) 0x03, state[c])
					^ state[blockSize + c] ^ state[2 * blockSize + c] ^ mulGF28(
					(byte) 0x02, state[3 * blockSize + c]));

			state[c] = s1;
			state[1 * blockSize + c] = s2;
			state[2 * blockSize + c] = s3;
			state[3 * blockSize + c] = s4;
		}
		return state;
	}

	// multiplication in GF(2^8)
	public byte mulGF28(byte a, byte b) {
		Byte p = 0;
		Byte counter;
		Byte hi_bit_set;
		for (counter = 0; counter < 8; counter++) {
			if ((b & 1) != 0) {
				p = (byte) (p ^ a);
			}
			hi_bit_set = (byte) (a & 0x80);
			a <<= 1;
			if (hi_bit_set != 0) {
				a ^= 0x1b; /* x^8 + x^4 + x^3 + x + 1 */
			}
			b >>= 1;
		}
		return p;
	}

	// s \cdot {0x02}
	public byte mul02(byte s) {
		return (byte) (s << 1);
	}

	// s \cdot {0x03}
	public byte mul03(byte s) {
		return (byte) ((s << 1) ^ s);
	}

	public byte[] addRoundKey(byte[] roundKey, byte[] state) {
		if (blockSize == keySize) { // = 4
			for (int c = 0; c < keySize; c++) {
				state[c * blockSize] = (byte) (state[c * blockSize] ^ roundKey[c]);
				state[c * blockSize + 1] = (byte) (state[c * blockSize + 1] ^ roundKey[c
						+ blockSize]);
				state[c * blockSize + 2] = (byte) (state[c * blockSize + 2] ^ roundKey[c
						+ 2 * blockSize]);
				state[c * blockSize + 3] = (byte) (state[c * blockSize + 3] ^ roundKey[c
						+ 3 * blockSize]);
			}
			return state;
		} else {
			System.out.println("block size is not equal key size.");
			return null;
		}
	}

	public List<byte[]> keyExpansion(byte[] cipherKey) {
		List<byte[]> word = new LinkedList<>();
		byte[] rKey = cipherKey;

		int i = 0;
		while (i < keySize) {
			byte[] wi = new byte[4];
			wi[0] = rKey[i];
			wi[1] = rKey[keySize + i];
			wi[2] = rKey[2 * keySize + i];
			wi[3] = rKey[3 * keySize + i];
			word.add(wi);
			i++;
		}

		i = keySize;
		// tao moi block round key (4 word)
		while (i < blockSize * (nRound + 1)) { // 4*(10+1) = 44
			byte[] wi = new byte[4];
			copyBlock(word.get(i - 1), wi);

			if (i % keySize == 0) {
				// SubWord(RotWord(temp)) xor Rcon[i/Nk]

				// wi = w[i-Nk] xor SubWord(RotWord(temp)) xor Rcon[i/Nk]
				xorBlock(word.get(i - keySize),
						xorRcon(subBytes(rotWord(wi)), i / keySize), wi);
			} else if ((keySize > 6) && (i % keySize == 4)) {
				wi = subBytes(wi);
			} else {
				// wi = w[i-Nk] xor wi
				xorBlock(word.get(i - keySize), wi, wi);
			}
			word.add(wi);
			// System.out.println(">> "+toStringBlock(wi));
			i++;
		}

		return word;
	}

	public byte[] rotWord(byte[] wi) {
		byte temp = wi[0];
		for (int r = 0; r < wi.length - 1; r++)
			wi[r] = wi[r + 1];
		wi[wi.length - 1] = temp;
		return wi;
	}

	public byte[] xorRcon(byte[] wi, int iR) {
		wi[0] = (byte) (wi[0] ^ Rcon[iR]);
		return wi;
	}

	public byte[] ivSubBytes(byte[] state) {
		byte[] subB = new byte[state.length];
		for (int i = 0; i < state.length; i++) {
			subB[i] = ivSubByte(state[i]);
		}
		return subB;
	}

	public byte ivSubByte(byte si) {
		int size = 4 * blockSize;
		int row = (si & 0xf0) >> 4;
		int col = si & 0x0f;
		return iSbox[row * size + col];
	}

	public byte[] ivShiftRows(byte[] state) {
		for (int i = 1; i < blockSize; i++) {
			ivShift(state, i, blockSize);
		}
		return state;
	}
	
	public void ivShift(byte[] state, int r, int Nb) {
		int index = r * Nb;
		for (int i = 0; i < r; i++) {
			byte temp = state[index+Nb-1];
			for (int j = Nb-1; j>0; j--) {
				state[index + j] = state[index + j - 1];
			}
			state[index] = temp;
		}
	}

	// fix AES-128
	// polynomial: x^4+1
	public byte[] ivMixColums(byte[] state) {
		for (int c = 0; c < blockSize; c++) {
			byte s1 = (byte) (mulGF28((byte) 0x0e, state[c])
					^ mulGF28((byte) 0x0b, state[blockSize + c])
					^ mulGF28((byte) 0x0d, state[2 * blockSize + c]) ^ mulGF28((byte) 0x09,state[3 * blockSize + c]));

			byte s2 = (byte) (mulGF28((byte) 0x09,state[c])
					^ mulGF28((byte) 0x0e, state[blockSize + c])
					^ mulGF28((byte) 0x0b, state[2 * blockSize + c]) ^ mulGF28((byte) 0x0d,state[3
					* blockSize + c]));

			byte s3 = (byte) (mulGF28((byte) 0x0d,state[c]) ^ mulGF28((byte) 0x09,state[blockSize + c])
					^ mulGF28((byte) 0x0e, state[2 * blockSize + c]) ^ mulGF28(
					(byte) 0x0b, state[3 * blockSize + c]));

			byte s4 = (byte) (mulGF28((byte) 0x0b, state[c])
					^ mulGF28((byte) 0x0d,state[blockSize + c]) ^ mulGF28((byte) 0x09,state[2 * blockSize + c]) ^ mulGF28(
					(byte) 0x0e, state[3 * blockSize + c]));

			state[c] = s1;
			state[1 * blockSize + c] = s2;
			state[2 * blockSize + c] = s3;
			state[3 * blockSize + c] = s4;
		}
		return state;
	}

	@Override
	public void setKey(byte[] key) {
		// TODO Auto-generated method stub

	}

	@Override
	public void encrypt(byte[] clearText, int clearOff, byte[] cipherText,
			int cipherOff) {	
		// PKCS5Padding AES-128
		if (padPKCS5) {
			int off = 16 - (clearText.length % 16);
			if (off != 0) {
				new PKCS5Padding().addPadding(clearText, off);
				System.out.println("Padded: " + (byte) off);
			}
		}
		
		clearOff = 0;
		cipherOff = 0;

		List<byte[]> word = keyExpansion(cipherText);
		byte[] roundKey = new byte[keySize * blockSize];

		roundKey = getBockKey(word, 0); // init

		// init
		byte[] state = new byte[keySize * blockSize];
		state = clearText;
		addRoundKey(roundKey, state);

		for (int r = 1; r < nRound; r++) {
			// key expansion
			roundKey = getBockKey(word, keySize * r);

			state = subBytes(state);
			state = shiftRows(state);
			state = mixColums(state);
			addRoundKey(roundKey, state);
		}

		state = subBytes(state);
		state = shiftRows(state);
		// key expansion
		roundKey = getBockKey(word, keySize * (nRound));
		addRoundKey(roundKey, state);

		// output
		setCipherT(state);
		// System.out.println(toStringBlock(state));
	}

	@Override
	public void decrypt(byte[] cipherText, int cipherOff, byte[] clearText,
			int clearOff) throws InvalidCipherTextException {
		
		clearOff = 0;
		cipherOff = 0;

		List<byte[]> word = keyExpansion(clearText);
		byte[] roundKey = new byte[keySize * keySize];
		roundKey = getBockKey(word, blockSize * nRound);

		// init
		byte[] state = new byte[keySize * blockSize];
		state = cipherText;
		addRoundKey(roundKey, state);

		for (int r = nRound - 1; r > 0; r--) {

			state = ivShiftRows(state);
			state = ivSubBytes(state);
			// key expansion
			roundKey = getBockKey(word, blockSize * r);
			addRoundKey(roundKey, state);
			
			state = ivMixColums(state);
		}

		state = ivShiftRows(state);
		state = ivSubBytes(state);
		// key expansion
		roundKey = getBockKey(word, 0);
		addRoundKey(roundKey, state);
		setClearT(state);
	}

	/**
	 * @return the padPKCS5
	 */
	public boolean isPad() {
		return padPKCS5;
	}

	/**
	 * @param padPKCS5 the padPKCS5 to set
	 */
	public void setPadPKCS5(boolean pad) {
		this.padPKCS5 = pad;
	}

}
