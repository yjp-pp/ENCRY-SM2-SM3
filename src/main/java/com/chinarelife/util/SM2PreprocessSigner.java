package com.chinarelife.util;

import java.io.IOException;
import java.math.BigInteger;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.CryptoException;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.SM3Digest;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECKeyParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.params.ParametersWithID;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.crypto.signers.DSAKCalculator;
import org.bouncycastle.crypto.signers.RandomDSAKCalculator;
import org.bouncycastle.math.ec.ECAlgorithms;
import org.bouncycastle.math.ec.ECConstants;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECFieldElement;
import org.bouncycastle.math.ec.ECMultiplier;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.math.ec.FixedPointCombMultiplier;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;

public class SM2PreprocessSigner
  implements ECConstants
{
  private static final int DIGEST_LENGTH = 32;
  private final DSAKCalculator kCalculator = new RandomDSAKCalculator();
  private Digest digest = null;
  private ECDomainParameters ecParams;
  private ECPoint pubPoint;
  private ECKeyParameters ecKey;
  private byte[] userID;
  
  public void init(boolean forSigning, CipherParameters param)
  {
    init(forSigning, new SM3Digest(), param);
  }
  
  public void init(boolean forSigning, Digest digest, CipherParameters param)
    throws RuntimeException
  {
    if (digest.getDigestSize() != 32) {
      throw new RuntimeException("Digest size must be 32");
    }
    this.digest = digest;
    CipherParameters baseParam;
    if ((param instanceof ParametersWithID))
    {
      baseParam = ((ParametersWithID)param).getParameters();
      this.userID = ((ParametersWithID)param).getID();
    }
    else
    {
      baseParam = param;
      this.userID = Hex.decode("31323334353637383132333435363738");
    }
    if (forSigning)
    {
      if ((baseParam instanceof ParametersWithRandom))
      {
        ParametersWithRandom rParam = (ParametersWithRandom)baseParam;
        
        this.ecKey = ((ECKeyParameters)rParam.getParameters());
        this.ecParams = this.ecKey.getParameters();
        this.kCalculator.init(this.ecParams.getN(), rParam.getRandom());
      }
      else
      {
        this.ecKey = ((ECKeyParameters)baseParam);
        this.ecParams = this.ecKey.getParameters();
        this.kCalculator.init(this.ecParams.getN(), CryptoServicesRegistrar.getSecureRandom());
      }
      this.pubPoint = createBasePointMultiplier().multiply(this.ecParams.getG(), ((ECPrivateKeyParameters)this.ecKey).getD()).normalize();
    }
    else
    {
      this.ecKey = ((ECKeyParameters)baseParam);
      this.ecParams = this.ecKey.getParameters();
      this.pubPoint = ((ECPublicKeyParameters)this.ecKey).getQ();
    }
  }
  
  public byte[] preprocess(byte[] m, int off, int len)
  {
    byte[] z = getZ(this.userID);
    this.digest.update(z, 0, z.length);
    this.digest.update(m, off, len);
    byte[] eHash = new byte[32];
    this.digest.doFinal(eHash, 0);
    return eHash;
  }
  
  public boolean verifySignature(byte[] eHash, byte[] signature)
  {
    try
    {
      BigInteger[] rs = derDecode(signature);
      if (rs != null) {
        return verifySignature(eHash, rs[0], rs[1]);
      }
    }
    catch (IOException localIOException) {}
    return false;
  }
  
  public void reset()
  {
    this.digest.reset();
  }
  
  public byte[] generateSignature(byte[] eHash)
    throws CryptoException
  {
    BigInteger n = this.ecParams.getN();
    BigInteger e = calculateE(eHash);
    BigInteger d = ((ECPrivateKeyParameters)this.ecKey).getD();
    


    ECMultiplier basePointMultiplier = createBasePointMultiplier();
    BigInteger r;
    BigInteger s;
    do
    {
      BigInteger k;
      do
      {
        k = this.kCalculator.nextK();
        

        ECPoint p = basePointMultiplier.multiply(this.ecParams.getG(), k).normalize();
        

        r = e.add(p.getAffineXCoord().toBigInteger()).mod(n);
      } while ((r.equals(ZERO)) || (r.add(k).equals(n)));
      BigInteger dPlus1ModN = d.add(ONE).modInverse(n);
      
      s = k.subtract(r.multiply(d)).mod(n);
      s = dPlus1ModN.multiply(s).mod(n);
    } while (s.equals(ZERO));
    try
    {
      return derEncode(r, s);
    }
    catch (IOException ex)
    {
      throw new CryptoException("unable to encode signature: " + ex.getMessage(), ex);
    }
  }
  
  private boolean verifySignature(byte[] eHash, BigInteger r, BigInteger s)
  {
    BigInteger n = this.ecParams.getN();
    if ((r.compareTo(ONE) < 0) || (r.compareTo(n) >= 0)) {
      return false;
    }
    if ((s.compareTo(ONE) < 0) || (s.compareTo(n) >= 0)) {
      return false;
    }
    BigInteger e = calculateE(eHash);
    

    BigInteger t = r.add(s).mod(n);
    if (t.equals(ZERO)) {
      return false;
    }
    ECPoint q = ((ECPublicKeyParameters)this.ecKey).getQ();
    ECPoint x1y1 = ECAlgorithms.sumOfTwoMultiplies(this.ecParams.getG(), s, q, t).normalize();
    if (x1y1.isInfinity()) {
      return false;
    }
    BigInteger expectedR = e.add(x1y1.getAffineXCoord().toBigInteger()).mod(n);
    
    return expectedR.equals(r);
  }
  
  private byte[] digestDoFinal()
  {
    byte[] result = new byte[this.digest.getDigestSize()];
    this.digest.doFinal(result, 0);
    
    reset();
    
    return result;
  }
  
  private byte[] getZ(byte[] userID)
  {
    this.digest.reset();
    
    addUserID(this.digest, userID);
    
    addFieldElement(this.digest, this.ecParams.getCurve().getA());
    addFieldElement(this.digest, this.ecParams.getCurve().getB());
    addFieldElement(this.digest, this.ecParams.getG().getAffineXCoord());
    addFieldElement(this.digest, this.ecParams.getG().getAffineYCoord());
    addFieldElement(this.digest, this.pubPoint.getAffineXCoord());
    addFieldElement(this.digest, this.pubPoint.getAffineYCoord());
    
    byte[] result = new byte[this.digest.getDigestSize()];
    
    this.digest.doFinal(result, 0);
    
    return result;
  }
  
  private void addUserID(Digest digest, byte[] userID)
  {
    int len = userID.length * 8;
    digest.update((byte)(len >> 8 & 0xFF));
    digest.update((byte)(len & 0xFF));
    digest.update(userID, 0, userID.length);
  }
  
  private void addFieldElement(Digest digest, ECFieldElement v)
  {
    byte[] p = v.getEncoded();
    digest.update(p, 0, p.length);
  }
  
  protected ECMultiplier createBasePointMultiplier()
  {
    return new FixedPointCombMultiplier();
  }
  
  protected BigInteger calculateE(byte[] message)
  {
    return new BigInteger(1, message);
  }
  
  protected BigInteger[] derDecode(byte[] encoding)
    throws IOException
  {
    ASN1Sequence seq = ASN1Sequence.getInstance(ASN1Primitive.fromByteArray(encoding));
    if (seq.size() != 2) {
      return null;
    }
    BigInteger r = ASN1Integer.getInstance(seq.getObjectAt(0)).getValue();
    BigInteger s = ASN1Integer.getInstance(seq.getObjectAt(1)).getValue();
    
    byte[] expectedEncoding = derEncode(r, s);
    if (!Arrays.constantTimeAreEqual(expectedEncoding, encoding)) {
      return null;
    }
    return new BigInteger[] { r, s };
  }
  
  protected byte[] derEncode(BigInteger r, BigInteger s)
    throws IOException
  {
    ASN1EncodableVector v = new ASN1EncodableVector();
    v.add(new ASN1Integer(r));
    v.add(new ASN1Integer(s));
    return new DERSequence(v).getEncoded("DER");
  }
}
