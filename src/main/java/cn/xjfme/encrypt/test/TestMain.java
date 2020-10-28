package cn.xjfme.encrypt.test;

import java.text.SimpleDateFormat;
import java.util.Date;
import org.bouncycastle.util.encoders.Base64;

import cn.xjfme.encrypt.sm2cret.EncryUtil;
import cn.xjfme.encrypt.sm2cret.SignUtil;
import cn.xjfme.encrypt.sm2cret.Utils;
import cn.xjfme.encrypt.utils.Util;
import net.sf.json.JSONArray;
import net.sf.json.JSONObject;

public class TestMain {

	/**
	 * 国密规范测试私钥
	 */
	private final static String PRKEY = "0B1CE43098BC21B8E82B5C065EDB534CB86532B1900A49D49F3C53762D2997FA";

	/**
	 * 国密规范测试公钥
	 */
	private final static String PUBKEY = "04BB34D657EE7E8490E66EF577E6B3CEA28B739511E787FB4F71B7F38F241D87F18A5A93DF74E90FF94F4EB907F271A36B295B851F971DA5418F4915E2C1A23D6E";

	/**
	 * 组装报文（例子）
	 * 
	 * @return jsonObj 组装后的报文
	 * @throws Exception
	 */
	public static JSONObject reqJsonStr() throws Exception {
		// 组装成json字符串
		JSONObject jsonObj = new JSONObject();
		jsonObj.put("version", "1.0.0"); // 版本号
		String reqSeq = "12345678";
		jsonObj.put("orderId", reqSeq); // 订单号（具体是什么，需要确认一下）
		jsonObj.put("reqSeq", reqSeq); // 请求流水号

		SimpleDateFormat date = new SimpleDateFormat("yyyyMMddHHmmssSSS");
		jsonObj.put("reqTime", date.format(new Date())); // 请求时间
		JSONObject data2 = new JSONObject();
		data2.put("certifTp", "01"); // 证件类型（01：身份证）
		JSONArray array = new JSONArray();
		array.add(data2);
		JSONObject data = new JSONObject();
		data.put("customerInfo", array);

		/**
		 * 加密 虚加密部分 key 为reqData
		 */
		jsonObj.put("reqData", data);

		return jsonObj;
	}

	public static void main(String[] args) throws Exception {
		String pubkS = new String(Base64.encode(Util.hexToByte(PUBKEY)));
		String prikS = new String(Base64.encode(Util.hexToByte(PRKEY)));
		System.out.println("加密公钥："+pubkS);
		// 获取到组装的Json数据（此数据为须根据实际情况确定）
		JSONObject jsonObj = reqJsonStr();
		// -------------------------加密------------------------
		System.out.println("加密前的Json串：" + jsonObj);
		// 第一步 根据key获取到需要加密的value 这里以key=reqData为例
		String reqDataStr = jsonObj.get("reqData").toString();
		// 第二步 对需要加密的数据 进行加密 调用Encryption.encrypt(参数一:需要加密的字符串, 参数二:公钥证书的Url);
		reqDataStr = EncryUtil.encrypt(reqDataStr, pubkS);
		// 第三步 将加密后的数据重新组入Json串
		jsonObj.put("reqData", reqDataStr);
		System.out.println("加密后的Json串：");
		System.err.println(jsonObj);

		// ---------------------------生成签名-------------------------
		// 第一步 需先将报文按规则拼接后再加签 按规则拼接字符串(先按key的首字母进行排序，然后用&进行拼接)
		String generateSignatureStr = Utils.splicingStr(jsonObj);
		System.out.println("报文签名之前的字符串（不含signature域）：" + generateSignatureStr);
		// 第二步 生成签名（生成摘要后 ，将摘要转换成16进制 再进行加密 生成签名）
		// 调用Signature.generateSignature(参数一:拼接后的字符串,参数二:私钥证书密码,参数三:私钥证书类型,参数四:私钥证书URl)
		String signature = SignUtil.sign(generateSignatureStr, prikS);
		// 第三步 将签名串组装到报文中 "signature"
		jsonObj.put("signature", signature);
		System.out.println("发送给(请求)接口的请求报文(即加密了，也做签名了): \n" + jsonObj.toString());
		
		// ------------------------------验签-------------------------
		// 第一步 调用请求方接口 HttpUtil.connectionPostJson(参数一:请求接口URL,参数二:请求参数)
		// String JsonString = HttpUtil.connectionPostJson(ClientConfig.Url,jsonObj.toString());
		String JsonString = jsonObj.toString(); // 目前没有请求接口 所以无返回参数 所以 以JsonOjb为例
		if (JsonString != null && !"".equals(JsonString) && JsonString.length() > 0) {
			// 第二步 将接口返回的字符串转为Json格式 验签
			JSONObject returnJsonObj = JSONObject.fromObject(JsonString);
			String sign="signature"; //签名对应的key
			// 第三步 验签 调用 Signature.verifySignature(参数一:返回的Json串 ,参数二:签名对应的key,参数三：公钥证书的Path)
			boolean flag = SignUtil.verify(returnJsonObj,sign,pubkS);
			System.out.println("验签返回的结果：" + flag);
			if (flag) {
				// 验签成功
				System.out.println("应答报文验签成功");

			} else {
				// 验签失败
				System.out.println("应答报文验签失败！！！");
			}
		} else {
			System.out.println("应答报文为空，可能原因：超时");
		}
		
		// ---------------------------先验签后解密-------------------------
		// 以刚才JsonObj中加密的reqData为例进行解密
		// 第一步 根据Key获取返回数据Json数据需要解密的Value
		String encryDataStr = jsonObj.get("reqData").toString();
		// 第二步 调用 Encryption.decrypt(参数一:需要解密的字符串，参数二:私钥证书密码,参数三:私钥证书类型,参数四:私钥证书Path)解密
		String deRespDataStr = EncryUtil.decrypt(encryDataStr, prikS);
		// 第三步 将解密后的数据 重新组入Json串
		jsonObj.put("reqData", deRespDataStr);
		System.out.println("解密后的Json串：" + jsonObj);
	}

}
