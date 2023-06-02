package cn.aotcloud.security.oncetoken.support.simple;

import javax.servlet.http.HttpServletRequest;

import org.apache.commons.lang3.StringUtils;
import org.apache.commons.text.StringEscapeUtils;
import org.springframework.util.NumberUtils;

import cn.aotcloud.security.oncetoken.OnceProtocol;
import cn.aotcloud.security.oncetoken.RequestToken;
import cn.aotcloud.security.oncetoken.RequestTokenParser;
import cn.aotcloud.security.oncetoken.RequestTokenUtil;
import cn.aotcloud.utils.HttpRequestUtil;

/**
 * @author xkxu
 */
public class ParameterRequestTokenParser implements RequestTokenParser {

	private static final String TOKEN_PARAM_NAME = OnceProtocol.TOKEN_PARAM_NAME;

	private static final String TIME_PARAM_NAME = OnceProtocol.TIME_PARAM_NAME;

	private static final String SIGN_PARAM_NAME = OnceProtocol.SIGN_PARAM_NAME;

	@Override
	public RequestToken parse(HttpServletRequest request) {
		RequestToken requestToken = getRequestTokenV1(request);
		return RequestTokenUtil.isValidRequestToken(requestToken) ? requestToken : null;
	}

	protected RequestToken getRequestTokenV1(HttpServletRequest request) {
		RequestToken requestToken = new RequestToken();
		String createTime = HttpRequestUtil.getParameterValue(request, TIME_PARAM_NAME);
		if (StringUtils.isNotBlank(createTime)) {
			requestToken.setCreateTime(NumberUtils.parseNumber(createTime, Long.class));
		}
		requestToken.setSign(StringEscapeUtils.escapeHtml4(HttpRequestUtil.getParameterValue(request, SIGN_PARAM_NAME)));
		requestToken.setToken(StringEscapeUtils.escapeHtml4(HttpRequestUtil.getParameterValue(request, TOKEN_PARAM_NAME)));
		return requestToken;
	}
}
