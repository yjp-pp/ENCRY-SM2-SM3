package com.chinarelife.util;

import java.util.Arrays;
import org.bouncycastle.crypto.agreement.SM2KeyExchange;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.params.ParametersWithID;
import org.bouncycastle.crypto.params.SM2KeyExchangePrivateParameters;
import org.bouncycastle.crypto.params.SM2KeyExchangePublicParameters;

public class SM2KeyExchangeUtil
{
  public static byte[] calculateKey(boolean initiator, int keyBits, ECPrivateKeyParameters selfStaticPriv, ECPrivateKeyParameters selfEphemeralPriv, byte[] selfId, ECPublicKeyParameters otherStaticPub, ECPublicKeyParameters otherEphemeralPub, byte[] otherId)
  {
    SM2KeyExchange exch = new SM2KeyExchange();
    exch.init(new ParametersWithID(new SM2KeyExchangePrivateParameters(initiator, selfStaticPriv, selfEphemeralPriv), selfId));
    

    return exch.calculateKey(keyBits, new ParametersWithID(new SM2KeyExchangePublicParameters(otherStaticPub, otherEphemeralPub), otherId));
  }
  
  public static ExchangeResult calculateKeyWithConfirmation(boolean initiator, int keyBits, byte[] confirmationTag, ECPrivateKeyParameters selfStaticPriv, ECPrivateKeyParameters selfEphemeralPriv, byte[] selfId, ECPublicKeyParameters otherStaticPub, ECPublicKeyParameters otherEphemeralPub, byte[] otherId)
  {
    SM2KeyExchange exch = new SM2KeyExchange();
    exch.init(new ParametersWithID(new SM2KeyExchangePrivateParameters(initiator, selfStaticPriv, selfEphemeralPriv), selfId));
    

    byte[][] result = exch.calculateKeyWithConfirmation(keyBits, confirmationTag, new ParametersWithID(new SM2KeyExchangePublicParameters(otherStaticPub, otherEphemeralPub), otherId));
    


    ExchangeResult confirmResult = new ExchangeResult();
    confirmResult.setKey(result[0]);
    if (initiator)
    {
      confirmResult.setS2(result[1]);
    }
    else
    {
      confirmResult.setS1(result[1]);
      confirmResult.setS2(result[2]);
    }
    return confirmResult;
  }
  
  public static boolean responderConfirm(byte[] s2, byte[] confirmationTag)
  {
    return Arrays.equals(s2, confirmationTag);
  }
  
  public static class ExchangeResult
  {
    private byte[] key;
    private byte[] s1;
    private byte[] s2;
    
    public byte[] getKey()
    {
      return this.key;
    }
    
    public void setKey(byte[] key)
    {
      this.key = key;
    }
    
    public byte[] getS1()
    {
      return this.s1;
    }
    
    public void setS1(byte[] s1)
    {
      this.s1 = s1;
    }
    
    public byte[] getS2()
    {
      return this.s2;
    }
    
    public void setS2(byte[] s2)
    {
      this.s2 = s2;
    }
  }
}
