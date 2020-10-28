package com.chinarelife.cret;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x9.X9ECPoint;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;
import org.bouncycastle.jcajce.provider.asymmetric.util.KeyUtil;

public class SM2PublicKey
  extends BCECPublicKey
{
  public static final ASN1ObjectIdentifier ID_SM2_PUBKEY_PARAM = new ASN1ObjectIdentifier("1.2.156.10197.1.301");
  private boolean withCompression;
  
  public SM2PublicKey(BCECPublicKey key)
  {
    super(key.getAlgorithm(), key);
    this.withCompression = false;
  }
  
  public SM2PublicKey(String algorithm, BCECPublicKey key)
  {
    super(algorithm, key);
    this.withCompression = false;
  }
  
  public byte[] getEncoded()
  {
    ASN1OctetString p = ASN1OctetString.getInstance(new X9ECPoint(
      getQ(), this.withCompression).toASN1Primitive());
    



    SubjectPublicKeyInfo info = new SubjectPublicKeyInfo(new AlgorithmIdentifier(X9ObjectIdentifiers.id_ecPublicKey, ID_SM2_PUBKEY_PARAM), p.getOctets());
    
    return KeyUtil.getEncodedSubjectPublicKeyInfo(info);
  }
  
  public void setPointFormat(String style)
  {
    this.withCompression = (!"UNCOMPRESSED".equalsIgnoreCase(style));
  }
}
