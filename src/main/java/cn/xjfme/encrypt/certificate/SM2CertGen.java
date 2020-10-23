package cn.xjfme.encrypt.certificate;

import java.io.FileOutputStream;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.text.SimpleDateFormat;
import java.util.Calendar;
import java.util.Date;

import javax.security.auth.x500.X500Principal;

import org.bouncycastle.asn1.gm.GMNamedCurves;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPrivateKey;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.x509.X509V3CertificateGenerator;

/**
 * 生成sm2证书
 * 
 * @author yjp
 *
 */
public class SM2CertGen {
	private static X9ECParameters x9ECParameters = GMNamedCurves.getByName("sm2p256v1");
	private static ECParameterSpec ecParameterSpec = new ECParameterSpec(x9ECParameters.getCurve(),
			x9ECParameters.getG(), x9ECParameters.getN());

	private static String SignAlgor = "1.2.156.10197.1.501";

	/**
	 * 生成国密ROOT证书方法
	 * 
	 * @param pageCert .getCn()+","+
	 * @throws Exception
	 */

	public static Date getYearLater(int later) {
		Date date = new Date();
		try {
			Calendar calendar = Calendar.getInstance();
			calendar.add(Calendar.YEAR, later);
			date = calendar.getTime();
		} catch (Exception e) {
			System.out.println(e.getMessage());
		}
		return date;
	}

	public static KeyPair generateKeyPair() {
		try {
			KeyPairGenerator kpGen = KeyPairGenerator.getInstance("EC", "BC");
			kpGen.initialize(ecParameterSpec, new SecureRandom());
			KeyPair kp = kpGen.generateKeyPair();
			return kp;
		} catch (Exception e) {
			throw new RuntimeException(e);
		}
	}

	public static void genSM2CertByRoot() throws Exception {
		SimpleDateFormat format = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
		org.bouncycastle.jce.provider.BouncyCastleProvider bouncyCastleProvider = new org.bouncycastle.jce.provider.BouncyCastleProvider();
		Security.addProvider(bouncyCastleProvider);
		// 证书的名称
		String rootCertPath = "d:/sm2.cer";
		try {
			KeyPair kp = generateKeyPair();// 这块就是生成SM2公私钥对
			System.out.println("=====公钥算法=====" + kp.getPublic().getAlgorithm());
			BCECPrivateKey bcecPrivateKey = (BCECPrivateKey) kp.getPrivate();// 使用ECPrivateKey
																			// PrivateKey都可以
			BCECPublicKey bcecPublicKey = (BCECPublicKey) kp.getPublic();    //使用ECPublicKey
																			// PublicKey都可以

			X500Principal principal = new X500Principal("CN=KK丶SS,O=DD丶OO");
			// X500Principal principal = new
			// X500Principal("CN="+pageCert.getCn()+",O="+pageCert.getO());
			X509V3CertificateGenerator certGen = new X509V3CertificateGenerator();
			certGen.setSerialNumber(BigInteger.valueOf(System.currentTimeMillis()));
			certGen.setIssuerDN(principal);
			certGen.setNotBefore(new Date());
			certGen.setNotAfter(getYearLater(5));
			certGen.setSubjectDN(principal);
			certGen.setSignatureAlgorithm(SignAlgor);
			certGen.setPublicKey(bcecPublicKey);
			X509Certificate rootCert = certGen.generateX509Certificate(bcecPrivateKey, "BC");
			FileOutputStream outputStream = new FileOutputStream(rootCertPath);
			outputStream.write(rootCert.getEncoded());
			outputStream.close();
			System.out.println("success");
		} catch (Exception e) {
			System.out.println("error generate sm2");
		}
	}

	public static void main(String[] args) throws Exception {
		genSM2CertByRoot();
	}
}
