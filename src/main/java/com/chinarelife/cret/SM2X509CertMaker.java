package com.chinarelife.cret;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.Date;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;

import com.chinarelife.util.BCECUtil;

public class SM2X509CertMaker
{
  public static final String SIGN_ALGO_SM3WITHSM2 = "SM3withSM2";
  private long certExpire;
  private X500Name issuerDN;
  private CertSNAllocator snAllocator;
  private KeyPair issuerKeyPair;
  
  public SM2X509CertMaker(KeyPair issuerKeyPair, long certExpire, X500Name issuer, CertSNAllocator snAllocator)
  {
    this.issuerKeyPair = issuerKeyPair;
    this.certExpire = certExpire;
    this.issuerDN = issuer;
    this.snAllocator = snAllocator;
  }
  
  public X509Certificate makeCertificate(boolean isCA, KeyUsage keyUsage, byte[] csr)
    throws Exception
  {
    PKCS10CertificationRequest request = new PKCS10CertificationRequest(csr);
    PublicKey subPub = BCECUtil.createPublicKeyFromSubjectPublicKeyInfo(request.getSubjectPublicKeyInfo());
    PrivateKey issPriv = this.issuerKeyPair.getPrivate();
    PublicKey issPub = this.issuerKeyPair.getPublic();
    
    JcaX509ExtensionUtils extUtils = new JcaX509ExtensionUtils();
    

    X509v3CertificateBuilder v3CertGen = new JcaX509v3CertificateBuilder(this.issuerDN, this.snAllocator.incrementAndGet(), new Date(System.currentTimeMillis()), new Date(System.currentTimeMillis() + this.certExpire), request.getSubject(), subPub);
    v3CertGen.addExtension(Extension.subjectKeyIdentifier, false, extUtils
      .createSubjectKeyIdentifier(SubjectPublicKeyInfo.getInstance(subPub.getEncoded())));
    v3CertGen.addExtension(Extension.authorityKeyIdentifier, false, extUtils
      .createAuthorityKeyIdentifier(SubjectPublicKeyInfo.getInstance(issPub.getEncoded())));
    v3CertGen.addExtension(Extension.basicConstraints, false, new BasicConstraints(isCA));
    v3CertGen.addExtension(Extension.keyUsage, false, keyUsage);
    
    JcaContentSignerBuilder contentSignerBuilder = makeContentSignerBuilder(issPub);
    
    X509Certificate cert = new JcaX509CertificateConverter().setProvider("BC").getCertificate(v3CertGen.build(contentSignerBuilder.build(issPriv)));
    cert.checkValidity(new Date());
    cert.verify(issPub);
    
    return cert;
  }
  
  private JcaContentSignerBuilder makeContentSignerBuilder(PublicKey issPub)
    throws Exception
  {
    if (issPub.getAlgorithm().equals("EC"))
    {
      JcaContentSignerBuilder contentSignerBuilder = new JcaContentSignerBuilder("SM3withSM2");
      contentSignerBuilder.setProvider("BC");
      return contentSignerBuilder;
    }
    throw new Exception("Unsupported PublicKey Algorithm:" + issPub.getAlgorithm());
  }
}
