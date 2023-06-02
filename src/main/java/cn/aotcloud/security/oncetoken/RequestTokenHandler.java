package cn.aotcloud.security.oncetoken;

import javax.servlet.http.HttpServletRequest;

/**
 * 防重放请求处理器
 * 
 * @author xkxu
 */
public interface RequestTokenHandler {

	/**
	 * 检查防重放请求令牌
	 * 
	 * @param request
	 * @throws IllegalRequestTokenException    检查到请求是重发攻击，抛出异常。
	 */
	public void validate(HttpServletRequest request) throws IllegalRequestTokenException;
}
