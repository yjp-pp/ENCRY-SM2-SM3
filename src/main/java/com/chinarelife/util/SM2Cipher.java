package com.chinarelife.util;

public class SM2Cipher
{
  private byte[] c1;
  private byte[] c2;
  private byte[] c3;
  private byte[] cipherText;
  
  public byte[] getC1()
  {
    return this.c1;
  }
  
  public void setC1(byte[] c1)
  {
    this.c1 = c1;
  }
  
  public byte[] getC2()
  {
    return this.c2;
  }
  
  public void setC2(byte[] c2)
  {
    this.c2 = c2;
  }
  
  public byte[] getC3()
  {
    return this.c3;
  }
  
  public void setC3(byte[] c3)
  {
    this.c3 = c3;
  }
  
  public byte[] getCipherText()
  {
    return this.cipherText;
  }
  
  public void setCipherText(byte[] cipherText)
  {
    this.cipherText = cipherText;
  }
}
