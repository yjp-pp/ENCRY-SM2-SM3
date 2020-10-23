package cn.xjfme.encrypt.sm2cret;

import java.util.Arrays;
import java.util.Set;

import net.sf.json.JSONObject;

/**
*@author 作者E-mail:杨建平 <784325705@qq.com>
*
*@version 创建时间: 2020年7月10日下午4:18:11
*
*类说明  签名拼接
**/
public class Utils {
	
	 /**
     * 按规则拼接字符串(先按key的首字母进行排序，然后用&进行拼接)
     * @param jsonObj
     * @return
     */
    public static String splicingStr(JSONObject jsonObj) {
        
        // 按key的首字母将key进行排序
        Set<?> set = jsonObj.keySet();
        Object[] arr = set.toArray();
        Arrays.sort(arr);
        
        // 用&进行拼接
        StringBuffer bufferStr = new StringBuffer();
        for(int i = 0;i < arr.length;i++) {
            if(i == 0) {
                bufferStr.append(arr[i]).append("=").append(jsonObj.get(arr[i]));
            }else {
                bufferStr.append("&").append(arr[i]).append("=").append(jsonObj.get(arr[i]));
            }
        }
        
        return bufferStr.toString();
    }
}
