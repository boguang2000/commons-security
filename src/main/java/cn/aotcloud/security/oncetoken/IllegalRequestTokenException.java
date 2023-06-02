package cn.aotcloud.security.oncetoken;

import cn.aotcloud.exception.BaseException;
import cn.aotcloud.exception.ErrorCode;

/**
 * @author xkxu
 */
public class IllegalRequestTokenException extends BaseException {
	
	private static final ErrorCode ILLEGAL_TOKEN_CODE = new ErrorCode("ac-request-token-illegal", "非法请求令牌。");

	private static final long serialVersionUID = 1L;

	public IllegalRequestTokenException() {
		super(ILLEGAL_TOKEN_CODE);
	}
}
