package cn.aotcloud.security.oncetoken;

import javax.servlet.http.HttpServletRequest;

/**
 * @author xkxu
 */
public interface RequestTokenParser {

	public RequestToken parse(HttpServletRequest request);
}
