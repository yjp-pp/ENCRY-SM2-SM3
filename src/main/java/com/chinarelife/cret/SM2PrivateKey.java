package com.chinarelife.cret;

import java.io.IOException;
import java.security.spec.ECParameterSpec;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.sec.ECPrivateKey;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPrivateKey;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;
import org.bouncycastle.jcajce.provider.asymmetric.util.ECUtil;
import org.bouncycastle.jcajce.provider.config.ProviderConfiguration;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class SM2PrivateKey extends BCECPrivateKey
{
  private transient DERBitString sm2PublicKey;
  private boolean withCompression;
  
  public SM2PrivateKey(BCECPrivateKey privateKey, BCECPublicKey publicKey)
  {
    super(privateKey.getAlgorithm(), privateKey);
    this.sm2PublicKey = getSM2PublicKeyDetails(new SM2PublicKey(publicKey.getAlgorithm(), publicKey));
    this.withCompression = false;
  }
  
  public void setPointFormat(String style)
  {
    this.withCompression = (!"UNCOMPRESSED".equalsIgnoreCase(style));
  }
  
  public byte[] getEncoded()
  {
    ECParameterSpec ecSpec = getParams();
    ProviderConfiguration configuration = BouncyCastleProvider.CONFIGURATION;
    ASN1Encodable params = SM2PublicKey.ID_SM2_PUBKEY_PARAM;
    int orderBitLength;
    if (ecSpec == null) {
      orderBitLength = ECUtil.getOrderBitLength(configuration, null, getS());
    } else {
      orderBitLength = ECUtil.getOrderBitLength(configuration, ecSpec.getOrder(), getS());
    }
    ECPrivateKey keyStructure;
    if (this.sm2PublicKey != null) {
      keyStructure = new ECPrivateKey(orderBitLength, getS(), this.sm2PublicKey, params);
    } else {
      keyStructure = new ECPrivateKey(orderBitLength, getS(), params);
    }
    try
    {
      PrivateKeyInfo info = new PrivateKeyInfo(new AlgorithmIdentifier(X9ObjectIdentifiers.id_ecPublicKey, params), keyStructure);
      
      return info.getEncoded("DER");
    }
    catch (IOException e) {}
    return null;
  }
  
  private DERBitString getSM2PublicKeyDetails(SM2PublicKey pub)
  {
    try
    {
      SubjectPublicKeyInfo info = SubjectPublicKeyInfo.getInstance(ASN1Primitive.fromByteArray(pub.getEncoded()));
      
      return info.getPublicKeyData();
    }
    catch (IOException e) {}
    return null;
  }
}
