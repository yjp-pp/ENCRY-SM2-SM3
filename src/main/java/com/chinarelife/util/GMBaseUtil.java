package com.chinarelife.util;

import java.security.Security;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class GMBaseUtil
{
  static
  {
    Security.addProvider(new BouncyCastleProvider());
  }
}
