package cn.xjfme.encrypt.utils.sm2;

import cn.xjfme.encrypt.utils.Util;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.math.ec.ECPoint;

import java.io.IOException;
import java.math.BigInteger;

public class SM2Utils {

	/**
	 * 生成随机秘钥对
	 * 
	 * @return
	 */
	public static SM2Key generateKeyPair() {
		SM2 sm2 = SM2.Instance();
		AsymmetricCipherKeyPair key = null;
		while (true) {
			key = sm2.ecc_key_pair_generator.generateKeyPair();
			if (((ECPrivateKeyParameters) key.getPrivate()).getD().toByteArray().length == 32) {
				break;
			}
		}
		ECPrivateKeyParameters ecpriv = (ECPrivateKeyParameters) key.getPrivate();
		ECPublicKeyParameters ecpub = (ECPublicKeyParameters) key.getPublic();
		BigInteger privateKey = ecpriv.getD();
		ECPoint publicKey = ecpub.getQ();
		SM2Key sm2KeyVO = new SM2Key();
		sm2KeyVO.setPublicKey(publicKey);
		sm2KeyVO.setPrivateKey(privateKey);
		// System.out.println("公钥: " + Util.byteToHex(publicKey.getEncoded()));
		// System.out.println("私钥: " + Util.byteToHex(privateKey.toByteArray()));
		return sm2KeyVO;
	}

	/**
	 * 数据加密
	 * @param publicKey 加密公钥
	 * @param data 加密数据
	 * @return
	 * @throws IOException
	 */
	public static String encrypt(byte[] publicKey, byte[] data) throws IOException {
		if (publicKey == null || publicKey.length == 0) {
			return null;
		}

		if (data == null || data.length == 0) {
			return null;
		}

		byte[] source = new byte[data.length];
		System.arraycopy(data, 0, source, 0, data.length);
		Cipher cipher = new Cipher();
		SM2 sm2 = SM2.Instance();
		ECPoint userKey = sm2.ecc_curve.decodePoint(publicKey);
		ECPoint c1 = cipher.Init_enc(sm2, userKey);
		cipher.Encrypt(source);
		byte[] c3 = new byte[32];
		cipher.Dofinal(c3);
		// C1 C2 C3拼装成加密字串
		// C1 | C2 | C3
		// return Util.byteToHex(c1.getEncoded()) + Util.byteToHex(source) +
		// Util.byteToHex(c3);
		// C1 | C3 | C2
		// 字节数组转换为十六进制字符串
		return Util.byteToHex(c1.getEncoded()) + Util.byteToHex(c3) + Util.byteToHex(source);
	}

	/**
	 * 数据解密
	 * 
	 * @param privateKey
	 * @param encryptedData
	 * @return
	 * @throws IOException
	 */
	public static byte[] decrypt(byte[] privateKey, byte[] encryptedData) throws IOException {
		if (privateKey == null || privateKey.length == 0) {
			return null;
		}

		if (encryptedData == null || encryptedData.length == 0) {
			return null;
		}
		// 加密字节数组转换为十六进制的字符串 长度变为encryptedData.length * 2
		String data = Util.byteToHex(encryptedData);
		/***
		 * 分解加密字串 C1 | C2 | C3 （C1 = C1标志位2位 + C1实体部分128位 = 130） （C3 = C3实体部分64位 = 64）
		 * （C2 = encryptedData.length * 2 - C1长度 - C2长度）
		 * 
		 * byte[] c1Bytes = Util.hexToByte(data.substring(0,130)); int c2Len =
		 * encryptedData.length - 97; byte[] c2 = Util.hexToByte(data.substring(130,130
		 * + 2 * c2Len)); byte[] c3 = Util.hexToByte(data.substring(130 + 2 * c2Len,194
		 * + 2 * c2Len));
		 */
		/***
		 * 分解加密字串 C1 | C3 | C2 （C1 = C1标志位2位 + C1实体部分128位 = 130） （C3 = C3实体部分64位 = 64）
		 * （C2 = encryptedData.length * 2 - C1长度 - C2长度）
		 */
		byte[] c1Bytes = Util.hexToByte(data.substring(0, 130));
		int c2Len = encryptedData.length - 97;
		byte[] c3 = Util.hexToByte(data.substring(130, 130 + 64));
		byte[] c2 = Util.hexToByte(data.substring(194, 194 + 2 * c2Len));

		SM2 sm2 = SM2.Instance();
		BigInteger userD = new BigInteger(1, privateKey);
		// 通过C1实体字节来生成ECPoint
		ECPoint c1 = sm2.ecc_curve.decodePoint(c1Bytes);
		Cipher cipher = new Cipher();
		cipher.Init_dec(userD, c1);
		cipher.Decrypt(c2);
		cipher.Dofinal(c3);
		// 返回解密结果
		return c2;
	}

	public static void main(String[] args) throws Exception {
		SM2Key sm2Key=generateKeyPair();
		System.out.println("这是我生成的公钥："+sm2Key.getPubHexInSoft());
		System.out.println("这是我生成的私钥："+sm2Key.getPrivateKey());
		String plainText = "ILoveYou11";
		// SM3测试
		// 生成密钥对
		// generateKeyPair();
		byte[] sourceData = plainText.getBytes();

		// 下面的秘钥可以使用generateKeyPair()生成的秘钥内容
		// 国密规范正式私钥
		// String prik =
		// "3690655E33D5EA3D9A4AE1A1ADD766FDEA045CDEAA43A9206FB8C430CEFE0D94";
		// 国密规范正式公钥
		// String pubk =
		// "04F6E0C3345AE42B51E06BF50B98834988D54EBC7460FE135A48171BC0629EAE205EEDE253A530608178A98F1E19BB737302813BA39ED3FA3C51639D7A20C7391A";

		String prik = "4cf170068e9c47ebdb521fb9fc62c4a55a5773fb9da33b0acf8129e28d09d205";
		String pubk = "04aabda53043e8dcb86d42f690b61a4db869821dadf9f851ec3c5c43d0c8f95a6677fdba984afc3bb010a8436b1d17cefc2011a34e01e9e801124d29ffa928d803";
		String publicKey = "04BB34D657EE7E8490E66EF577E6B3CEA28B739511E787FB4F71B7F38F241D87F18A5A93DF74E90FF94F4EB907F271A36B295B851F971DA5418F4915E2C1A23D6E";
		String privatekey = "0B1CE43098BC21B8E82B5C065EDB534CB86532B1900A49D49F3C53762D2997FA";
		prik = privatekey;
		pubk = publicKey;
		System.out.println("加密: ");
		String cipherText = SM2Utils.encrypt(Util.hexToByte(pubk), sourceData);
		System.out.println(cipherText);
		System.out.println("解密: ");
		plainText = new String(SM2Utils.decrypt(Util.hexToByte(prik), Util.hexToByte(cipherText)));
		System.out.println(plainText);

	}
}