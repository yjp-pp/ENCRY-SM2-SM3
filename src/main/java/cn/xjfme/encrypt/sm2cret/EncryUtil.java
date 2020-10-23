package cn.xjfme.encrypt.sm2cret;


import org.bouncycastle.util.encoders.Base64;

import cn.xjfme.encrypt.utils.Util;
import cn.xjfme.encrypt.utils.sm2.SM2Utils;


public class EncryUtil {

	/**
	 * 国密规范测试私钥
	 */
	private final static String PRKEY = "0B1CE43098BC21B8E82B5C065EDB534CB86532B1900A49D49F3C53762D2997FA";
	
	
	/**
	 * 国密规范测试公钥
	 */
	private final static String PUBKEY = "04BB34D657EE7E8490E66EF577E6B3CEA28B739511E787FB4F71B7F38F241D87F18A5A93DF74E90FF94F4EB907F271A36B295B851F971DA5418F4915E2C1A23D6E";
	
	/**
	 * 
	 * @param encryString 加密数据
	 * @param pubKey 公钥
	 * @return base64enCode 加密后的BASE64编码格式的字符串
	 * @throws Exception
	 */
	public static String encrypt(String encryString, String pubKey) throws Exception {
		// 第一步：将encryString值转化为UTF-8格式的字节数组
		byte[] reqDataText = encryString.getBytes("UTF-8");
		// 第二步：读取文件中的公钥
	//	final PublicKey publicKey = CertUtil.getPubKey(pubKey);
		// 第三步：使用公钥加密
		String reqDataRsa = SM2Utils.encrypt(Base64.decode(pubKey.getBytes()),reqDataText);
		// 第四步： 将加密后转换的十六进制字符串转化为UTF-8格式的字节数组
		byte[] reqEncryStr= reqDataRsa.getBytes("UTF-8");
		// 第五步：对密文进行BASE64编码
		byte[] base64Str = Base64.encode(reqEncryStr);
		
		String base64enCode = new String(base64Str, "UTF-8");

		return base64enCode;
	}
	
	
	/**
	 * 对加密部分解密（使用私钥解密）
	 * 
	 * @param returnJsonStr   需要解密的字符串
	 * @param privatePwd      私钥密码
	 * @param privagtePfxType 证书类型
	 * @param privatePath     私钥证书路径URL
	 * @return deRespDataStr
	 * @throws Exception 私钥解密后的结果
	 */
	public static String decrypt(String returnJsonStr,String priKey)
			throws Exception {
		// 第一步 ：将加密数据Base64 解码
		byte[] base64Decoded = Base64.decode(returnJsonStr.getBytes("utf-8"));
		// 第二步 ： 解码后转换为字符串（十六进制的）
		String encryStr= new String(base64Decoded, "UTF-8");
		// 第三步：使用私钥对密文进行解码
		// 读取文件中的私钥
	//	final PrivateKey privateKey = CertUtil.getPrivateKeyInfo(privatePwd, privagtePfxType, privatePath);
		// 第四步：使用私钥解密
		byte[] rsaDecode = SM2Utils.decrypt(Base64.decode(priKey.getBytes()), Util.hexToByte(encryStr));
		// 私钥解密后的结果
		String deRespDataStr = new String(rsaDecode, "utf-8");
		// 返回私钥解密后的结果
		return deRespDataStr;
	}

	
	public static void main(String[] args) {
		String aString="啊啊啊啊啊啊啊啊啊啊啊啊啊啊啊啊啊啊啊啊啊啊啊啊啊啊啊啊啊啊啊啊啊啊啊啊";
		String pubkS = new String(Base64.encode(Util.hexToByte(PUBKEY)));
		String prikS = new String(Base64.encode(Util.hexToByte(PRKEY)));
		try {
			String bbString=encrypt(aString,pubkS);
			System.out.println("加密结果："+bbString);
			System.out.println("解密结果:"+decrypt(bbString,prikS));
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
}
