package com.chinarelife.cret;

import java.math.BigInteger;

public class DefaultSNAllocator
  implements CertSNAllocator
{
  public BigInteger incrementAndGet()
    throws Exception
  {
    return new BigInteger(System.currentTimeMillis() + "");
  }
}
