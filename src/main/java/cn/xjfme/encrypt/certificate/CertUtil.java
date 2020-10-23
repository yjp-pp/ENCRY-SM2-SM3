package cn.xjfme.encrypt.certificate;

import java.io.FileInputStream;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.Enumeration;

import org.apache.log4j.Logger;

/**
 * @author 作者E-mail:杨建平 <784325705@qq.com>
 *
 * @version 创建时间: 2020年7月10日下午4:04:19
 *
 *          类说明 从证书中获取秘钥
 **/
public class CertUtil {
	private static final Logger logger = Logger.getLogger(CertUtil.class);

	/**
	 * 获取私钥别名等信息
	 * 
	 * @param privatePwd      私钥证书密码
	 * @param privagtePfxType 私钥证书类型PKCS12
	 * @param privatePath     私钥证书路径
	 * @return
	 */
	public static PrivateKey getPrivateKeyInfo(String privatePwd, String privagtePfxType, String privatePath) {

		PrivateKey prikey = null;

		try {
			KeyStore keyStore = KeyStore.getInstance(privagtePfxType);

			FileInputStream fileInputStream = new FileInputStream(privatePath);
			char[] nPassword = null;

			if (privatePwd == null || "".equals(privatePwd.trim())) {
				nPassword = null;
			} else {
				nPassword = privatePwd.toCharArray();
			}

			keyStore.load(fileInputStream, nPassword);
			fileInputStream.close();
			Enumeration<String> enumeration = keyStore.aliases();
			String keyAlias = "";

			if (enumeration.hasMoreElements()) {
				keyAlias = enumeration.nextElement();
			}

			prikey = (PrivateKey) keyStore.getKey(keyAlias, nPassword);
		} catch (Exception e) {
			e.printStackTrace();
			logger.error("获取私钥失败：" + e);
		}

		return prikey;
	}

	/**
	 * 读取公钥cer
	 * 
	 * @param cerPath cer文件路径
	 * @return
	 */
	public static PublicKey getPubKey(String cerPath) {
		PublicKey pubKey = null;
		try {
			InputStream inStream = new FileInputStream(cerPath);
			CertificateFactory cf = CertificateFactory.getInstance("X.509");
			X509Certificate cert = (X509Certificate) cf.generateCertificate(inStream);
			pubKey = cert.getPublicKey();
		} catch (Exception e) {
			e.printStackTrace();
			logger.error("读取公钥cer证书失败！！！" + e);
		}

		return pubKey;
	}

	/**
	 * 获取pfx的serialNumber
	 * 
	 * @param privatePwd      证书私钥密码
	 * @param privagtePfxType 私钥证书类型
	 * @param privatePath
	 * @return
	 */
	public static String getSerialNumberPfx(String privatePwd, String privagtePfxType, String privatePath) {

		String serialNumberPfx = "";

		try {
			KeyStore keyStore = KeyStore.getInstance(privagtePfxType);

			FileInputStream fileInputStream = new FileInputStream(privatePath);
			char[] nPassword = null;

			if (privatePwd == null || "".equals(privatePwd.trim())) {
				nPassword = null;
			} else {
				nPassword = privatePwd.toCharArray();
			}

			keyStore.load(fileInputStream, nPassword);
			fileInputStream.close();

			Enumeration<String> enumeration = keyStore.aliases();
			String keyAlias = "";

			if (enumeration.hasMoreElements()) {
				keyAlias = enumeration.nextElement();
			}
			X509Certificate cert = (X509Certificate) keyStore.getCertificate(keyAlias);
			serialNumberPfx = cert.getSerialNumber().toString();
		} catch (Exception e) {
			e.printStackTrace();
			logger.error("获取pfx序列号时失败：" + e);
		}

		return serialNumberPfx;
	}

	/**
	 * 获取cer的serialNumber
	 * 
	 * @param cerPath
	 * @return
	 */
	public static String getSerialNumberCer(String cerPath) {
		String serialNumberCer = "";
		try {
			InputStream inStream = new FileInputStream(cerPath);
			CertificateFactory cf = CertificateFactory.getInstance("X.509");
			X509Certificate cert = (X509Certificate) cf.generateCertificate(inStream);
			serialNumberCer = cert.getSerialNumber().toString();
		} catch (Exception e) {
			e.printStackTrace();
			logger.error("读取公钥cer证书失败！！！" + e);
		}

		return serialNumberCer;
	}

	/**
	 * 获取私钥别名等信息
	 * 
	 * @param privatePwd      私钥证书密码
	 * @param privagtePfxType 私钥证书类型PKCS12
	 * @param privatePath     私钥证书路径
	 * @return
	 */
	public static PublicKey getPublicKeyPfx(String privatePwd, String privagtePfxType, String privatePath) {

		PublicKey pubkey = null;

		try {
			KeyStore keyStore = KeyStore.getInstance(privagtePfxType);

			FileInputStream fileInputStream = new FileInputStream(privatePath);
			char[] nPassword = null;

			if (privatePwd == null || "".equals(privatePwd.trim())) {
				nPassword = null;
			} else {
				nPassword = privatePwd.toCharArray();
			}

			keyStore.load(fileInputStream, nPassword);
			fileInputStream.close();
			Enumeration<String> enumeration = keyStore.aliases();
			String keyAlias = "";

			if (enumeration.hasMoreElements()) {
				keyAlias = enumeration.nextElement();
			}

			X509Certificate cert = (X509Certificate) keyStore.getCertificate(keyAlias);
			pubkey = cert.getPublicKey(); // 获取对应的公钥

			String publicKeyStr = Base64.getEncoder().encodeToString(pubkey.getEncoded());
		} catch (Exception e) {
			e.printStackTrace();
			logger.error("获取公钥失败：" + e);
		}

		return pubkey;
	}
}
