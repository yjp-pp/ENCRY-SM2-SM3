package com.chinarelife.util;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.EllipticCurve;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x9.X962Parameters;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.generators.ECKeyPairGenerator;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECKeyGenerationParameters;
import org.bouncycastle.crypto.params.ECKeyParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPrivateKey;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;
import org.bouncycastle.jcajce.provider.asymmetric.util.EC5Util;
import org.bouncycastle.jcajce.provider.asymmetric.util.ECUtil;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECNamedCurveSpec;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.pqc.math.linearalgebra.ByteUtils;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;
import org.bouncycastle.util.io.pem.PemWriter;

public class BCECUtil
{
  private static final String ALGO_NAME_EC = "EC";
  private static final String PEM_STRING_PUBLIC = "PUBLIC KEY";
  private static final String PEM_STRING_ECPRIVATEKEY = "EC PRIVATE KEY";
  
  public static AsymmetricCipherKeyPair generateKeyPairParameter(ECDomainParameters domainParameters, SecureRandom random)
  {
    ECKeyGenerationParameters keyGenerationParams = new ECKeyGenerationParameters(domainParameters, random);
    
    ECKeyPairGenerator keyGen = new ECKeyPairGenerator();
    keyGen.init(keyGenerationParams);
    return keyGen.generateKeyPair();
  }
  
  public static KeyPair generateKeyPair(ECDomainParameters domainParameters, SecureRandom random)
    throws NoSuchProviderException, NoSuchAlgorithmException, InvalidAlgorithmParameterException
  {
    KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC", "BC");
    
    org.bouncycastle.jce.spec.ECParameterSpec parameterSpec = new org.bouncycastle.jce.spec.ECParameterSpec(domainParameters.getCurve(), domainParameters.getG(), domainParameters.getN(), domainParameters.getH());
    kpg.initialize(parameterSpec, random);
    return kpg.generateKeyPair();
  }
  
  public static int getCurveLength(ECKeyParameters ecKey)
  {
    return getCurveLength(ecKey.getParameters());
  }
  
  public static int getCurveLength(ECDomainParameters domainParams)
  {
    return (domainParams.getCurve().getFieldSize() + 7) / 8;
  }
  
  public static byte[] fixToCurveLengthBytes(int curveLength, byte[] src)
  {
    if (src.length == curveLength) {
      return src;
    }
    byte[] result = new byte[curveLength];
    if (src.length > curveLength) {
      System.arraycopy(src, src.length - result.length, result, 0, result.length);
    } else {
      System.arraycopy(src, 0, result, result.length - src.length, src.length);
    }
    return result;
  }
  
  public static ECPrivateKeyParameters createECPrivateKeyParameters(BigInteger d, ECDomainParameters domainParameters)
  {
    return new ECPrivateKeyParameters(d, domainParameters);
  }
  
  public static ECPublicKeyParameters createECPublicKeyParameters(BigInteger x, BigInteger y, ECCurve curve, ECDomainParameters domainParameters)
  {
    return createECPublicKeyParameters(x.toByteArray(), y.toByteArray(), curve, domainParameters);
  }
  
  public static ECPublicKeyParameters createECPublicKeyParameters(String xHex, String yHex, ECCurve curve, ECDomainParameters domainParameters)
  {
    return createECPublicKeyParameters(ByteUtils.fromHexString(xHex), ByteUtils.fromHexString(yHex), curve, domainParameters);
  }
  
  public static ECPublicKeyParameters createECPublicKeyParameters(byte[] xBytes, byte[] yBytes, ECCurve curve, ECDomainParameters domainParameters)
  {
    byte uncompressedFlag = 4;
    int curveLength = getCurveLength(domainParameters);
    xBytes = fixToCurveLengthBytes(curveLength, xBytes);
    yBytes = fixToCurveLengthBytes(curveLength, yBytes);
    byte[] encodedPubKey = new byte[1 + xBytes.length + yBytes.length];
    encodedPubKey[0] = 4;
    System.arraycopy(xBytes, 0, encodedPubKey, 1, xBytes.length);
    System.arraycopy(yBytes, 0, encodedPubKey, 1 + xBytes.length, yBytes.length);
    return new ECPublicKeyParameters(curve.decodePoint(encodedPubKey), domainParameters);
  }
  
  public static ECPrivateKeyParameters convertPrivateKeyToParameters(BCECPrivateKey ecPriKey)
  {
    org.bouncycastle.jce.spec.ECParameterSpec parameterSpec = ecPriKey.getParameters();
    
    ECDomainParameters domainParameters = new ECDomainParameters(parameterSpec.getCurve(), parameterSpec.getG(), parameterSpec.getN(), parameterSpec.getH());
    return new ECPrivateKeyParameters(ecPriKey.getD(), domainParameters);
  }
  
  public static ECPublicKeyParameters convertPublicKeyToParameters(BCECPublicKey ecPubKey)
  {
    org.bouncycastle.jce.spec.ECParameterSpec parameterSpec = ecPubKey.getParameters();
    
    ECDomainParameters domainParameters = new ECDomainParameters(parameterSpec.getCurve(), parameterSpec.getG(), parameterSpec.getN(), parameterSpec.getH());
    return new ECPublicKeyParameters(ecPubKey.getQ(), domainParameters);
  }
  
  public static BCECPublicKey createPublicKeyFromSubjectPublicKeyInfo(SubjectPublicKeyInfo subPubInfo)
    throws NoSuchProviderException, NoSuchAlgorithmException, InvalidKeySpecException, IOException
  {
    return convertX509ToECPublicKey(subPubInfo.toASN1Primitive().getEncoded("DER"));
  }
  
  public static byte[] convertECPrivateKeyToPKCS8(ECPrivateKeyParameters priKey, ECPublicKeyParameters pubKey)
  {
    ECDomainParameters domainParams = priKey.getParameters();
    
    org.bouncycastle.jce.spec.ECParameterSpec spec = new org.bouncycastle.jce.spec.ECParameterSpec(domainParams.getCurve(), domainParams.getG(), domainParams.getN(), domainParams.getH());
    BCECPublicKey publicKey = null;
    if (pubKey != null) {
      publicKey = new BCECPublicKey("EC", pubKey, spec, BouncyCastleProvider.CONFIGURATION);
    }
    BCECPrivateKey privateKey = new BCECPrivateKey("EC", priKey, publicKey, spec, BouncyCastleProvider.CONFIGURATION);
    
    return privateKey.getEncoded();
  }
  
  public static BCECPrivateKey convertPKCS8ToECPrivateKey(byte[] pkcs8Key)
    throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeySpecException
  {
    PKCS8EncodedKeySpec peks = new PKCS8EncodedKeySpec(pkcs8Key);
    KeyFactory kf = KeyFactory.getInstance("EC", "BC");
    return (BCECPrivateKey)kf.generatePrivate(peks);
  }
  
  public static String convertECPrivateKeyPKCS8ToPEM(byte[] encodedKey)
    throws IOException
  {
    return convertEncodedDataToPEM("EC PRIVATE KEY", encodedKey);
  }
  
  public static byte[] convertECPrivateKeyPEMToPKCS8(String pemString)
    throws IOException
  {
    return convertPEMToEncodedData(pemString);
  }
  
  public static byte[] convertECPrivateKeyToSEC1(ECPrivateKeyParameters priKey, ECPublicKeyParameters pubKey)
    throws IOException
  {
    byte[] pkcs8Bytes = convertECPrivateKeyToPKCS8(priKey, pubKey);
    PrivateKeyInfo pki = PrivateKeyInfo.getInstance(pkcs8Bytes);
    ASN1Encodable encodable = pki.parsePrivateKey();
    ASN1Primitive primitive = encodable.toASN1Primitive();
    byte[] sec1Bytes = primitive.getEncoded();
    return sec1Bytes;
  }
  
  public static byte[] convertECPrivateKeySEC1ToPKCS8(byte[] sec1Key)
    throws IOException
  {
    X962Parameters params = getDomainParametersFromName(SM2Util.JDK_EC_SPEC, false);
    ASN1OctetString privKey = new DEROctetString(sec1Key);
    ASN1EncodableVector v = new ASN1EncodableVector();
    v.add(new ASN1Integer(0L));
    v.add(new AlgorithmIdentifier(X9ObjectIdentifiers.id_ecPublicKey, params));
    v.add(privKey);
    DERSequence ds = new DERSequence(v);
    return ds.getEncoded("DER");
  }
  
  public static BCECPrivateKey convertSEC1ToBCECPrivateKey(byte[] sec1Key)
    throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeySpecException, IOException
  {
    PKCS8EncodedKeySpec peks = new PKCS8EncodedKeySpec(convertECPrivateKeySEC1ToPKCS8(sec1Key));
    KeyFactory kf = KeyFactory.getInstance("EC", "BC");
    return (BCECPrivateKey)kf.generatePrivate(peks);
  }
  
  public static ECPrivateKeyParameters convertSEC1ToECPrivateKey(byte[] sec1Key)
    throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeySpecException, IOException
  {
    BCECPrivateKey privateKey = convertSEC1ToBCECPrivateKey(sec1Key);
    return convertPrivateKeyToParameters(privateKey);
  }
  
  public static byte[] convertECPublicKeyToX509(ECPublicKeyParameters pubKey)
  {
    ECDomainParameters domainParams = pubKey.getParameters();
    
    org.bouncycastle.jce.spec.ECParameterSpec spec = new org.bouncycastle.jce.spec.ECParameterSpec(domainParams.getCurve(), domainParams.getG(), domainParams.getN(), domainParams.getH());
    BCECPublicKey publicKey = new BCECPublicKey("EC", pubKey, spec, BouncyCastleProvider.CONFIGURATION);
    
    return publicKey.getEncoded();
  }
  
  public static BCECPublicKey convertX509ToECPublicKey(byte[] x509Bytes)
    throws NoSuchProviderException, NoSuchAlgorithmException, InvalidKeySpecException
  {
    X509EncodedKeySpec eks = new X509EncodedKeySpec(x509Bytes);
    KeyFactory kf = KeyFactory.getInstance("EC", "BC");
    return (BCECPublicKey)kf.generatePublic(eks);
  }
  
  public static String convertECPublicKeyX509ToPEM(byte[] encodedKey)
    throws IOException
  {
    return convertEncodedDataToPEM("PUBLIC KEY", encodedKey);
  }
  
  public static byte[] convertECPublicKeyPEMToX509(String pemString)
    throws IOException
  {
    return convertPEMToEncodedData(pemString);
  }
  
  public static X9ECParameters getDomainParametersFromGenSpec(ECGenParameterSpec genSpec)
  {
    return getDomainParametersFromName(genSpec.getName());
  }
  
  public static X9ECParameters getDomainParametersFromName(String curveName)
  {
    X9ECParameters domainParameters;
    try
    {
      if ((curveName.charAt(0) >= '0') && (curveName.charAt(0) <= '2'))
      {
        ASN1ObjectIdentifier oidID = new ASN1ObjectIdentifier(curveName);
        domainParameters = ECUtil.getNamedCurveByOid(oidID);
      }
      else
      {
        if (curveName.indexOf(' ') > 0)
        {
          curveName = curveName.substring(curveName.indexOf(' ') + 1);
          domainParameters = ECUtil.getNamedCurveByName(curveName);
        }
        else
        {
          domainParameters = ECUtil.getNamedCurveByName(curveName);
        }
      }
    }
    catch (IllegalArgumentException ex)
    {
      domainParameters = ECUtil.getNamedCurveByName(curveName);
    }
    return domainParameters;
  }
  
  public static X962Parameters getDomainParametersFromName(java.security.spec.ECParameterSpec ecSpec, boolean withCompression)
  {
    X962Parameters params;
    if ((ecSpec instanceof ECNamedCurveSpec))
    {
      ASN1ObjectIdentifier curveOid = ECUtil.getNamedCurveOid(((ECNamedCurveSpec)ecSpec).getName());
      if (curveOid == null) {
        curveOid = new ASN1ObjectIdentifier(((ECNamedCurveSpec)ecSpec).getName());
      }
      params = new X962Parameters(curveOid);
    }
    else
    {
      if (ecSpec == null)
      {
        params = new X962Parameters(DERNull.INSTANCE);
      }
      else
      {
        ECCurve curve = EC5Util.convertCurve(ecSpec.getCurve());
        





        X9ECParameters ecP = new X9ECParameters(curve, EC5Util.convertPoint(curve, ecSpec.getGenerator(), withCompression), ecSpec.getOrder(), BigInteger.valueOf(ecSpec.getCofactor()), ecSpec.getCurve().getSeed());
        
        params = new X962Parameters(ecP);
      }
    }
    return params;
  }
  
  private static String convertEncodedDataToPEM(String type, byte[] encodedData)
    throws IOException
  {
    ByteArrayOutputStream bOut = new ByteArrayOutputStream();
    PemWriter pWrt = new PemWriter(new OutputStreamWriter(bOut));
    try
    {
      PemObject pemObj = new PemObject(type, encodedData);
      pWrt.writeObject(pemObj);
    }
    finally
    {
      pWrt.close();
    }
    return new String(bOut.toByteArray());
  }
  
  private static byte[] convertPEMToEncodedData(String pemString)
    throws IOException
  {
    ByteArrayInputStream bIn = new ByteArrayInputStream(pemString.getBytes());
    PemReader pRdr = new PemReader(new InputStreamReader(bIn));
    try
    {
      PemObject pemObject = pRdr.readPemObject();
      return pemObject.getContent();
    }
    finally
    {
      pRdr.close();
    }
  }
}
