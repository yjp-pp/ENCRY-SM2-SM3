package cn.xjfme.encrypt.sm2cret;

import org.bouncycastle.util.encoders.Base64;
import cn.xjfme.encrypt.utils.Util;
import cn.xjfme.encrypt.utils.sm2.SM2SignUtils;
import cn.xjfme.encrypt.utils.sm2.SM2SignVO;
import net.sf.json.JSONObject;

public class SignUtil {
	
	/**
	 * 私钥签名
	 * @param signString 需要签名的数据
	 * @param privatekey
	 * @return
	 * @throws Exception
	 */
	public static String sign(String signString,String privatekey) throws Exception  {
		SM2SignVO sign=null;
		try {
			sign = SM2SignUtils.Sign2SM2(Base64.decode(privatekey.getBytes()),signString.getBytes());
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		String getSm2_signForSoft=sign.getSm2_signForSoft();
		// 第四步：对密文进行BASE64编码
    	byte[] base64Str = Base64.encode(getSm2_signForSoft.getBytes("utf-8"));
		String base64enCode = new String(base64Str, "UTF-8");
		return base64enCode;
	}
	
	/**
	 * 使用公钥验签 
	 * @param summary 摘要 
	 * @param sign 签名对应的key
	 * @param pubk 公钥
	 * @return
	 * @throws Exception 
	 */
	public static boolean verify(JSONObject jsonObj,String sign,String publicKey) throws Exception {
		SM2SignVO verify=null;
		// 公钥解密 验签（拿到原文和签名串）
		String signature = jsonObj.getString(sign);
		// 在原文里把签名去掉
		jsonObj.remove(sign);
		// 对返回报文中(不含signature域)的json串做排序处理拼接处理
		String stringData = Utils.splicingStr(jsonObj);
		byte[] base64Decoded = Base64.decode(signature.getBytes("utf-8"));
		String getSm2_signForSoft = new String(base64Decoded, "UTF-8");
		try {
			verify = SM2SignUtils.VerifySignSM2(Base64.decode(publicKey.getBytes()),stringData.getBytes(),Util.hexStringToBytes(getSm2_signForSoft));
		} catch (Exception e) {
			// TODO: handle exception
		}
		return verify.isVerify();
	}
	
}
