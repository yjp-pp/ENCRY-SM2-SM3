package com.chinarelife.test;

public class ClientConfig {
	
    //数据使用方信息
    //todo 填充参数（参见邮件通知）
    public static final String cid = "11111";//分配的机构识别代码
    public static final String companyName = "aa";//企业全称
    public static final String nature = "11";//组织性质
    public static final String country = "11";//国家
    public static final String province = "11";//省份
    public static final String city = "11";//城市

	/**
	 * 请求接口地址
	 */
	public static final String Url = " http://www.baidu.com";

	/**
	 * 签名开关
	 */
	public static final boolean isSign = true;

	/**
	 * 私钥证书存放地址
	 */

	public static String filePath = "/SM2_SM3_SM4Encrypt-master/Keys/SM2/";

	/**
	 * 私钥证书
	 */
	public static String privatePath;
	/**
	 * 公钥证书
	 */
	public static String publicPath;
	/**
	 * 证书私钥密码
	 */
	public static final String privatePwd = "666666";
	/**
	 * 私钥证书类型
	 */
	public static final String privagtePfxType = "PKCS12";
	/**
	 * 是否需要SM3加密
	 */
	public static boolean isNeedSM3 = true;

	static {
		String path = Thread.currentThread().getContextClassLoader().getResource("").getPath();
		path = path.substring(0, path.indexOf("SM2_SM3_SM4Encrypt-master"));
		privatePath = path + filePath + "11111.sm2.pri";
		publicPath = path + filePath + "11111.sm2.cer";
	}
	public static void main(String[] args) {
		System.out.println(publicPath);
	}
}
