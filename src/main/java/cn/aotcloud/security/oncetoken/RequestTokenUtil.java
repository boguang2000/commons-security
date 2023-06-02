package cn.aotcloud.security.oncetoken;

import org.apache.commons.lang3.StringUtils;

/**
 * @author xkxu
 */
public class RequestTokenUtil {

	public static boolean isValidRequestToken(RequestToken requestToken) {
		return requestToken.getCreateTime() != null 
				&& StringUtils.isNotBlank(requestToken.getSign()) 
				&& StringUtils.isNotBlank(requestToken.getToken());
	}
}
