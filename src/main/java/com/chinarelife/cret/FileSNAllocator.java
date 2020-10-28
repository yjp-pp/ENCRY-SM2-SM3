package com.chinarelife.cret;

import java.io.IOException;
import java.io.RandomAccessFile;
import java.math.BigInteger;
import java.net.URL;

public class FileSNAllocator implements CertSNAllocator {
	private static final String SN_FILENAME = "sn.dat";
	private static String snFilePath;

	static {
		ClassLoader loader = FileSNAllocator.class.getClassLoader();
		snFilePath = loader.getResource("sn.dat").getPath();
	}

	public synchronized BigInteger incrementAndGet() throws Exception {
		BigInteger sn = readSN();
		writeSN(sn.add(BigInteger.ONE));
		return sn;
	}

	private BigInteger readSN() throws IOException {
		RandomAccessFile raf = null;
		try {
			raf = new RandomAccessFile(snFilePath, "r");
			byte[] data = new byte[(int) raf.length()];
			raf.read(data);
			String snStr = new String(data);
			return new BigInteger(snStr);
		} finally {
			if (raf != null) {
				raf.close();
			}
		}
	}

	private void writeSN(BigInteger sn) throws IOException {
		RandomAccessFile raf = null;
		try {
			raf = new RandomAccessFile(snFilePath, "rw");
			raf.writeBytes(sn.toString(10));
			if (raf != null) {
				raf.close();
			}
		} finally {
			if (raf != null) {
				raf.close();
			}
		}
	}
}