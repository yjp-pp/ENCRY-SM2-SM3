package cn.xjfme.encrypt.certificate;


/**
 * 获取证书 密钥方法测试
 * @author yjp
 *
 */
public class KeyTest {
	
	private final static String CREPATH="D:\\test1.cer" ;
	
	public static void main(String[] args) {
		String aString="16c877789aebdeb8ba150de1d78aa5c366d3033a";
		System.out.println(aString.length());
		System.out.println(CertUtil.getPubKey(CREPATH));
	}

}
