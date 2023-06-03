package cn.aotcloud.security.oncetoken.support;

import cn.aotcloud.security.oncetoken.OnceProtocol;
import cn.aotcloud.security.oncetoken.RequestToken;
import cn.aotcloud.security.oncetoken.RequestTokenParser;
import cn.aotcloud.security.oncetoken.support.once2.Once2RequestTokenParser;
import cn.aotcloud.security.oncetoken.support.simple.SimpleRequestTokenParser;

import org.springframework.util.CollectionUtils;

import javax.servlet.http.HttpServletRequest;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * @author xkxu
 */
public class DelegateRequestTokenParser implements RequestTokenParser {

	private Map<OnceProtocol, RequestTokenParser> requestTokenParsers = new LinkedHashMap<>();

	private List<OnceProtocol> supportedProtocols;

	public DelegateRequestTokenParser(List<OnceProtocol> supportedProtocols) {
		this.supportedProtocols = supportedProtocols;

		requestTokenParsers.put(OnceProtocol.once2, new Once2RequestTokenParser());
		requestTokenParsers.put(OnceProtocol.simple, new SimpleRequestTokenParser());
	}

	@Override
	public RequestToken parse(HttpServletRequest request) {
		if (CollectionUtils.isEmpty(supportedProtocols)) {
			for (RequestTokenParser requestTokenParser : requestTokenParsers.values()) {
				RequestToken requestToken = requestTokenParser.parse(request);
				if (requestToken != null) {
					return requestToken;
				}
			}
		} else {
			for (OnceProtocol protocol : supportedProtocols) {
				RequestTokenParser requestTokenParser = requestTokenParsers.get(protocol);
				if (requestTokenParser != null) {
					RequestToken requestToken = requestTokenParser.parse(request);
					if (requestToken != null) {
						return requestToken;
					}
				}
			}
		}
		return null;
	}

}
