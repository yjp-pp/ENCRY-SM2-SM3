package com.chinarelife.cret;

import java.math.BigInteger;

public abstract interface CertSNAllocator
{
  public abstract BigInteger incrementAndGet()
    throws Exception;
}
