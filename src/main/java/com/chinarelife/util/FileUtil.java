package com.chinarelife.util;

import java.io.File;
import java.io.IOException;
import java.io.RandomAccessFile;

public class FileUtil
{
  public static void writeFile(String filePath, byte[] data)
    throws IOException
  {
    RandomAccessFile raf = null;
    try
    {
      File file = new File(filePath).getParentFile();
      if (!file.exists()) {
        file.mkdirs();
      }
      raf = new RandomAccessFile(filePath, "rw");
      raf.write(data);
    }
    finally
    {
      if (raf != null) {
        raf.close();
      }
    }
  }
  
  public static byte[] readFile(String filePath)
    throws IOException
  {
    RandomAccessFile raf = null;
    try
    {
      raf = new RandomAccessFile(filePath, "r");
      byte[] data = new byte[(int)raf.length()];
      raf.read(data);
      return data;
    }
    finally
    {
      if (raf != null) {
        raf.close();
      }
    }
  }
}
