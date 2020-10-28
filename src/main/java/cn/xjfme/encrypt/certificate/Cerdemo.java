package cn.xjfme.encrypt.certificate;
import sun.misc.BASE64Encoder;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.security.PublicKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x509.X509CertificateStructure;

public class Cerdemo {
	
	 public static byte[] getCSPK(String path) throws FileNotFoundException
	    {
		    InputStream inStream = new FileInputStream(path);
		    ByteArrayOutputStream out = new ByteArrayOutputStream();
		    int ch;
		    String res = "";
		    try {
				while ((ch = inStream.read()) != - 1)
				{
				out.write(ch);
				}
			} catch (IOException e1) {
				// TODO Auto-generated catch block
				e1.printStackTrace();
			}
		    byte[] csCert=out.toByteArray();
	        InputStream ianStream = new ByteArrayInputStream(csCert);
	        ASN1Sequence seq = null;
	        ASN1InputStream aIn;
	        try
	        {
	            aIn = new ASN1InputStream(ianStream);
	            seq = (ASN1Sequence)aIn.readObject();
	            X509CertificateStructure cert = new X509CertificateStructure(seq);
	            SubjectPublicKeyInfo subjectPublicKeyInfo = cert.getSubjectPublicKeyInfo();
	            DERBitString publicKeyData = subjectPublicKeyInfo.getPublicKeyData();
	            byte[] publicKey = publicKeyData.getEncoded();
	            byte[] encodedPublicKey = publicKey;
	            byte[] eP = new byte[64];
	            System.arraycopy(encodedPublicKey, 4, eP, 0, eP.length);
	            return eP;
	        }
	        catch (Exception e)
	        {
	            // TODO Auto-generated catch block
	            e.printStackTrace();
	        }
	        return null;
	    }
	 
	 
    public static void main(String[] args) throws Exception{

//        CertificateFactory cf = CertificateFactory.getInstance("X.509");
//        X509Certificate cert = (X509Certificate)cf.generateCertificate(new FileInputStream("D:\\11111.sm2.cer"));
////        PublicKey publicKey = cert.getPublicKey();
////        BASE64Encoder base64Encoder=new BASE64Encoder();
////        String publicKeyString = base64Encoder.encode(publicKey.getEncoded());
////        System.out.println("-----------------公钥--------------------");
////        System.out.println(publicKeyString);
////        System.out.println("-----------------公钥--------------------");
    	byte[] a=getCSPK("D:\\11111.sm2.cer");
    	for (int i = 0; i < a.length; i++) {
    		System.out.println(a[i]);
		}
    	
    }
}