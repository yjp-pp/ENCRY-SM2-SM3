package com.chinarelife;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.cert.CertPath;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Pattern;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1OutputStream;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPrivateKey;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;

import com.chinarelife.cret.CertSNAllocator;
import com.chinarelife.cret.CommonUtil;
import com.chinarelife.cret.DefaultSNAllocator;
import com.chinarelife.cret.SM2CertUtil;
import com.chinarelife.cret.SM2PrivateKey;
import com.chinarelife.cret.SM2PublicKey;
import com.chinarelife.cret.SM2X509CertMaker;
import com.chinarelife.cret.exception.InvalidX500NameException;
import com.chinarelife.util.BCECUtil;
import com.chinarelife.util.FileUtil;
import com.chinarelife.util.GMBaseUtil;
import com.chinarelife.util.SM2Util;

import cn.xjfme.encrypt.sm2cret.Utils;
import net.sf.json.JSONObject;

public class GMHelper extends GMBaseUtil {
	private static final String default_charset = "UTF-8";
	private static final int MAX_DECRYPT_BLOCK = 232;
	private static final int PADDING_SIZE = 4;
	private static final Map<String, BCECPublicKey> pubKeyCacheMap = new ConcurrentHashMap();
	private static final Map<String, BCECPrivateKey> priKeyCacheMap = new ConcurrentHashMap();

	/**
	 * 生成 SM2密钥证书
	 * @param filePath 证书文件存放路径
	 * @param fileName 文件名
	 * @param companyName 企业全称
	 * @param nature 组织性质
	 * @param country 国家
	 * @param province 省份
	 * @param city 城市
	 */
	public static void makeTestCertificate(String filePath, String fileName, String companyName, String nature,
			String country, String province, String city) {
		try {
			if (!filePath.endsWith("/")) {
				filePath = filePath + "/";
			}
			KeyPair subKP = SM2Util.generateKeyPair();
			X500Name subDN = buildSubjectDN(companyName, nature, country, province, city);

			SM2PublicKey sm2SubPub = new SM2PublicKey(subKP.getPublic().getAlgorithm(),
					(BCECPublicKey) subKP.getPublic());
			System.out.println("public key:\n" + base64Encode(sm2SubPub.getEncoded()));
			SM2PrivateKey sm2PrivateKey = new SM2PrivateKey((BCECPrivateKey) subKP.getPrivate(), sm2SubPub);
			System.out.println("private key:\n" + base64Encode(sm2PrivateKey.getEncoded()));

			byte[] csr = CommonUtil.createCSR(subDN, sm2SubPub, subKP.getPrivate(), "SM3withSM2").getEncoded();
			FileUtil.writeFile(filePath + fileName + ".sm2.csr", base64Encode(csr).getBytes());
			savePriKey(filePath + fileName + ".sm2.pri", (BCECPrivateKey) subKP.getPrivate(),
					(BCECPublicKey) subKP.getPublic());
			SM2X509CertMaker certMaker = buildCertMaker();
			X509Certificate cert = certMaker.makeCertificate(true, new KeyUsage(144), csr);

			FileUtil.writeFile(filePath + fileName + ".sm2.cer", cert.getEncoded());
		} catch (Exception ex) {
			ex.printStackTrace();
		}
	}

	public static String base64Encode(String data) {
		return base64Encode(data.getBytes());
	}

	/**
	 * Base64 编码
	 * @param data Base64编码数据
	 * @return
	 * @throws IOException
	 */
	public static String base64Encode(byte[] data) {
		return  Base64.getEncoder().encodeToString(data).replaceAll("\\n", "");
	}

	/**
	 * Base64解码
	 * @param data Base64编码数据
	 * @return
	 * @throws IOException
	 */
	public static byte[] base64Decode(String data) throws IOException {
		
		return Base64.getDecoder().decode(data.getBytes("utf-8"));
	}
	
	
	/**
	 * 签名 （私钥）
	 * @param data
	 * @param priKeyFilePath
	 * @return
	 */
	public static String sign(String data, String priKeyFilePath) {
		try {
			byte[] priKeyData = FileUtil.readFile(priKeyFilePath);
			BCECPrivateKey prikey = BCECUtil.convertSEC1ToBCECPrivateKey(priKeyData);
			byte[] sign = SM2Util.sign(prikey, data.getBytes("UTF-8"));
			// 第三步：对密文进行BASE64编码
			byte[] base64Str = Base64.getEncoder().encode(sign);
			String base64enCode = new String(base64Str, "utf-8");
			return base64enCode;
		} catch (Exception e) {
			e.printStackTrace();
		}
		return null;
	}

	/**
	 * 验签
	 * 
	 * @param data
	 * @param pubKeyFilePath
	 * @param sign
	 * @return
	 */
	public static boolean verifySign(JSONObject jsonObj, String pubKeyFilePath, String sign) {
		String signature = jsonObj.getString(sign); // 签名
		jsonObj.remove(sign); // 在原文里把签名去掉
		// 对返回报文中(不含signature域)的json串做排序处理拼接处理
		String data= Utils.splicingStr(jsonObj);
		try {
			if ((null == data) || ("".equals(data))) {
				return false;
			}
			data = data.replace("\\t", "");
			X509Certificate cert = SM2CertUtil.getX509Certificate(pubKeyFilePath);
			BCECPublicKey pubKey = SM2CertUtil.getBCECPublicKey(cert);
			return SM2Util.verify(pubKey, data.getBytes("UTF-8"), base64Decode(signature));
		} catch (Exception e) {
			e.printStackTrace();
		}
		return false;
	}

	public static X509Certificate getX509Certificate(InputStream inputStream)
			throws CertificateException, IOException, NoSuchProviderException {
		return SM2CertUtil.getX509Certificate(inputStream);
	}

	public static CertPath getCertPath(InputStream inputStream) throws CertificateException, NoSuchProviderException {
		return SM2CertUtil.getCertificateChain(inputStream);
	}

	/**
	 * 加密（公钥）
	 * @param data 加密数据
	 * @param pubKeyFilePath 公钥证书url
	 * @return
	 * @throws IOException
	 * @throws InvalidCipherTextException
	 * @throws CertificateException
	 * @throws NoSuchProviderException
	 */
	public static String encrypt(String data, String pubKeyFilePath)
			throws IOException, InvalidCipherTextException, CertificateException, NoSuchProviderException {
		if ((data == null) || ("".equals(data.trim()))) {
			return null;
		}
		BCECPublicKey pubKey = (BCECPublicKey) pubKeyCacheMap.get(pubKeyFilePath);
		if (pubKey == null) {
			synchronized (pubKeyFilePath.intern()) {
				if (!pubKeyCacheMap.containsKey(pubKeyFilePath)) {
					X509Certificate cert = SM2CertUtil.getX509Certificate(pubKeyFilePath);
					pubKey = SM2CertUtil.getBCECPublicKey(cert);
					pubKeyCacheMap.put(pubKeyFilePath, pubKey);
				} else {
					pubKey = (BCECPublicKey) pubKeyCacheMap.get(pubKeyFilePath);
				}
			}
		}
		for (int i = 0; i < 3; i++) {
			try {
				byte[] sm2Cipher = SM2Util.encrypt(pubKey, data.getBytes("UTF-8"));
				byte[] der = SM2Util.encodeSM2CipherToDER(sm2Cipher);
				return base64Encode(der);
			} catch (Throwable e) {
				if (i == 2) {
					throw e;
				}
			}
		}
		return null;
	}

	/**
	 * 解密（私钥）
	 * 
	 * @param encryptedData 加密数据
	 * @param priKeyFilePath 私钥证书url
	 * @return
	 */
	public static String decrypt(String encryptedData, String priKeyFilePath) {
		try {
			if ((encryptedData == null) || ("".equals(encryptedData.trim()))) {
				return null;
			}
			encryptedData = encryptedData.replace("\\t", "");
			BCECPrivateKey prikey = (BCECPrivateKey) priKeyCacheMap.get(priKeyFilePath);
			if (prikey == null) {
				synchronized (priKeyFilePath.intern()) {
					if (!priKeyCacheMap.containsKey(priKeyFilePath)) {
						byte[] priKeyData = FileUtil.readFile(priKeyFilePath);
						String base64Pattern = "^([A-Za-z0-9+/]{4})*([A-Za-z0-9+/]{4}|[A-Za-z0-9+/]{3}=|[A-Za-z0-9+/]{2}==)$";
						if (Pattern.matches(base64Pattern, new String(priKeyData))) {
							priKeyData = base64Decode(new String(priKeyData));
						}
						prikey = BCECUtil.convertSEC1ToBCECPrivateKey(priKeyData);
						priKeyCacheMap.put(priKeyFilePath, prikey);
					} else {
						prikey = (BCECPrivateKey) priKeyCacheMap.get(priKeyFilePath);
					}
				}
			}
			byte[] data = base64Decode(encryptedData);
			if (!isPartitioned(data)) {
				data = SM2Util.decodeDERSM2Cipher(data);
				return new String(SM2Util.decrypt(prikey, data), "UTF-8");
			}
			int inputLen = data.length;
			ByteArrayOutputStream out = new ByteArrayOutputStream();
			int i = 0;
			int offSet = 0;
			while (inputLen - offSet > 0) {
				byte[] cache;
				if (inputLen - offSet > 232) {
					cache = Arrays.copyOfRange(data, offSet, 232 + offSet);
				} else {
					cache = Arrays.copyOfRange(data, offSet, inputLen);
				}
				ASN1InputStream var1 = new ASN1InputStream(cache);
				try {
					ASN1Primitive var2 = var1.readObject();

					ByteArrayOutputStream os = new ByteArrayOutputStream();
					ASN1OutputStream asn1OutputStream = new ASN1OutputStream(os);
					asn1OutputStream.writeObject(var2);
					cache = os.toByteArray();
				} catch (ClassCastException var3) {
					throw new IOException("cannot recognise object in stream");
				}
				cache = SM2Util.decodeDERSM2Cipher(cache);
				out.write(SM2Util.decrypt(prikey, cache));
				i++;
				offSet = i * 232;
			}
			return new String(out.toByteArray(), "UTF-8");
		} catch (Exception e) {
			e.printStackTrace();
		}
		return null;
	}

	private static boolean isPartitioned(byte[] data) {
		if (data.length < 232) {
			return false;
		}
		for (int i = 232; i < data.length; i += 232) {
			if (data[i] != 48) {
				return false;
			}
		}
		return true;
	}

	/**
	 * 生成证书
	 * @param filePath
	 * @param priKey
	 * @param pubKey
	 * @throws IOException
	 */
	private static void savePriKey(String filePath, BCECPrivateKey priKey, BCECPublicKey pubKey) throws IOException {
		ECPrivateKeyParameters priKeyParam = BCECUtil.convertPrivateKeyToParameters(priKey);
		ECPublicKeyParameters pubKeyParam = BCECUtil.convertPublicKeyToParameters(pubKey);
		byte[] derPriKey = BCECUtil.convertECPrivateKeyToSEC1(priKeyParam, pubKeyParam);
		FileUtil.writeFile(filePath, derPriKey);
	}

	private static X500Name buildSubjectDN(String conpanyName, String nature, String country, String province,
			String city) {
		X500NameBuilder builder = new X500NameBuilder(BCStyle.INSTANCE);
		builder.addRDN(BCStyle.CN, conpanyName);
		builder.addRDN(BCStyle.C, country);
		builder.addRDN(BCStyle.ST, province);
		builder.addRDN(BCStyle.L, province);
		builder.addRDN(BCStyle.O, conpanyName);
		builder.addRDN(BCStyle.OU, conpanyName);
		return builder.build();
	}

	private static X500Name buildRootCADN() {
		X500NameBuilder builder = new X500NameBuilder(BCStyle.INSTANCE);
		builder.addRDN(BCStyle.CN, "ZZ Root CA");
		builder.addRDN(BCStyle.C, "CN");
		builder.addRDN(BCStyle.O, "org.zz");
		builder.addRDN(BCStyle.OU, "org.zz");
		return builder.build();
	}

	private static SM2X509CertMaker buildCertMaker() throws InvalidAlgorithmParameterException,
			NoSuchAlgorithmException, NoSuchProviderException, InvalidX500NameException {
		X500Name issuerName = buildRootCADN();
		KeyPair issKP = SM2Util.generateKeyPair();
		long certExpire = 630720000000L;
		CertSNAllocator snAllocator = new DefaultSNAllocator();
		SM2X509CertMaker sm2X509CertMaker = new SM2X509CertMaker(issKP, certExpire, issuerName, snAllocator);
		return sm2X509CertMaker;
	}
	
	/**
	 * 将字符串拼接
	 * @param params
	 * @return
	 */
	public static String generateSignParamsStr(Map<String, String> params) {
		params = paraFilter(params);
		List<String> keyValues = buildKeyValueList(params);
		Collections.sort(keyValues);
		StringBuilder preStr = new StringBuilder();
		for (int i = 0; i < keyValues.size(); i++) {
			preStr.append("&" + (String) keyValues.get(i));
		}
		if (preStr.length() == 0) {
			return "";
		}
		return preStr.substring(1);
	}

	private static List<String> buildKeyValueList(Map<String, String> sArray) {
		List<String> keyValues = new ArrayList();
		if ((sArray == null) || (sArray.isEmpty())) {
			return keyValues;
		}
		for (String key : sArray.keySet()) {
			Object value = sArray.get(key);
			keyValues.add(key + "=" + value);
		}
		return keyValues;
	}

	private static Map<String, String> paraFilter(Map<String, String> sArray) {
		Map<String, String> result = new HashMap();
		if ((sArray == null) || (sArray.isEmpty())) {
			return result;
		}
		for (String key : sArray.keySet()) {
			String value = (String) sArray.get(key);
			if ((value != null) && (!key.equalsIgnoreCase("_sign")) &&

					(!"".equals(value.replaceAll(" ", "")))) {
				result.put(key, value);
			}
		}
		return result;
	}
}
