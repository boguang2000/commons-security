package cn.aotcloud.security.oncetoken.support.simple;

import javax.servlet.http.HttpServletRequest;

import cn.aotcloud.security.oncetoken.RequestToken;
import cn.aotcloud.security.oncetoken.RequestTokenParser;

import java.util.ArrayList;
import java.util.List;

/**
 * @author xkxu
 */
public class SimpleRequestTokenParser implements RequestTokenParser {

    private List<RequestTokenParser> requestTokenParsers = new ArrayList<>();

    public SimpleRequestTokenParser() {
        requestTokenParsers.add(new HeaderRequestTokenParser());
        requestTokenParsers.add(new ParameterRequestTokenParser());
    }

    @Override
    public RequestToken parse(HttpServletRequest request) {
        for (RequestTokenParser requestTokenParser : requestTokenParsers) {
            RequestToken requestToken = requestTokenParser.parse(request);
            if (requestToken != null) {
                return requestToken;
            }
        }
        return null;
    }
}
