package cn.aotcloud.security.oncetoken.support.once2;

import cn.aotcloud.security.oncetoken.OnceProtocol;
import cn.aotcloud.security.oncetoken.RequestToken;
import cn.aotcloud.security.oncetoken.RequestTokenParser;
import cn.aotcloud.security.oncetoken.RequestTokenUtil;
import cn.aotcloud.utils.HttpServletUtil;

import org.apache.commons.lang3.StringUtils;
import org.springframework.util.Base64Utils;
import org.springframework.util.NumberUtils;

import javax.servlet.http.HttpServletRequest;
import java.nio.charset.StandardCharsets;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * @author xkxu
 */
public class Once2RequestTokenParser implements RequestTokenParser {

    private static final Pattern SIGN_HEADER = Pattern.compile("\\s*(\\w*)\\s+(.*)");

    @Override
    public RequestToken parse(HttpServletRequest request) {
        String token = getToken(request);
        if (StringUtils.isNotBlank(token)) {
            Matcher m = SIGN_HEADER.matcher(token);
            if (m.matches()) {
                if (OnceProtocol.once2.name().equalsIgnoreCase(m.group(1))) {
                    return parseToken(m.group(2));
                }
            } else {
                return RequestToken.ILLEGAL_REQUEST_TOKEN;
            }
        }
        return null;
    }

    protected String getToken(HttpServletRequest request) {
        String token = HttpServletUtil.getHeader(request, OnceProtocol.TOKEN_HEADER_NAME_V2);
        if (StringUtils.isBlank(token)) {
            token = HttpServletUtil.getParameter(request, OnceProtocol.TOKEN_PARAM_NAME_V2);
        }
        return token;
    }

    protected RequestToken parseToken(String token) {
        String tokenToUse = new String(Base64Utils.decodeFromString(token), StandardCharsets.UTF_8);
        String[] array = StringUtils.split(tokenToUse, ':');
        if (array.length == 3) {
            RequestToken requestToken = new RequestToken();
            requestToken.setProtocol(OnceProtocol.once2.name());

            requestToken.setToken(array[0]);
            requestToken.setCreateTime(NumberUtils.parseNumber(array[1], Long.class));
            requestToken.setSign(array[2]);

            return RequestTokenUtil.isValidRequestToken(requestToken) ? requestToken : RequestToken.ILLEGAL_REQUEST_TOKEN;
        }
        return RequestToken.ILLEGAL_REQUEST_TOKEN;
    }
}
