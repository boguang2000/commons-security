package cn.aotcloud.security.oncetoken.support.simple;

import javax.servlet.http.HttpServletRequest;

import org.apache.commons.lang3.StringUtils;
import org.apache.commons.text.StringEscapeUtils;
import org.springframework.util.NumberUtils;

import cn.aotcloud.security.oncetoken.OnceProtocol;
import cn.aotcloud.security.oncetoken.RequestToken;
import cn.aotcloud.security.oncetoken.RequestTokenParser;
import cn.aotcloud.security.oncetoken.RequestTokenUtil;
import cn.aotcloud.utils.HttpServletUtil;

/**
 * @author xkxu
 */
public class HeaderRequestTokenParser implements RequestTokenParser {

	private static final String TOKEN_HEADER_NAME = OnceProtocol.TOKEN_HEADER_NAME;

	private static final String TIME_HEADER_NAME = OnceProtocol.TIME_HEADER_NAME;

	private static final String SIGN_HEADER_NAME = OnceProtocol.SIGN_HEADER_NAME;

	@Override
	public RequestToken parse(HttpServletRequest request) {
		RequestToken requestToken = getRequestTokenV1(request);
		return RequestTokenUtil.isValidRequestToken(requestToken) ? requestToken : null;
	}

	protected RequestToken getRequestTokenV1(HttpServletRequest request) {
		RequestToken requestToken = new RequestToken();

		String createTime = HttpServletUtil.getHeader(request, TIME_HEADER_NAME);
		if (StringUtils.isNotBlank(createTime)) {
			requestToken.setCreateTime(NumberUtils.parseNumber(createTime, Long.class));
		}
		requestToken.setSign(StringEscapeUtils.escapeHtml4(HttpServletUtil.getHeader(request, SIGN_HEADER_NAME)));
		requestToken.setToken(StringEscapeUtils.escapeHtml4(HttpServletUtil.getHeader(request, TOKEN_HEADER_NAME)));

		return requestToken;
	}
}
