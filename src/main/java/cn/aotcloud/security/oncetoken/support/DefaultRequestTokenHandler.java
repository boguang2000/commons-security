package cn.aotcloud.security.oncetoken.support;

import cn.aotcloud.crypto.pcode.PcodeEncoder;
import cn.aotcloud.security.config.SgitgSafeProperties;
import cn.aotcloud.security.oncetoken.IllegalRequestTokenException;
import cn.aotcloud.security.oncetoken.RequestToken;
import cn.aotcloud.security.oncetoken.RequestTokenHandler;
import cn.aotcloud.security.oncetoken.RequestTokenParser;
import cn.aotcloud.security.oncetoken.RequestTokenStore;
import cn.aotcloud.security.oncetoken.RequestTokenValidator;
import cn.aotcloud.security.oncetoken.event.IllegalRequestTokenApplicationEvent;
import cn.aotcloud.security.oncetoken.support.simple.SimpleRequestTokenValidator;

import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.ApplicationEventPublisherAware;
import org.springframework.util.AntPathMatcher;
import org.springframework.util.PathMatcher;
import org.springframework.web.util.UrlPathHelper;

import javax.servlet.http.HttpServletRequest;

/**
 * 基于Timestamp和Nonce的方案。
 *
 * @author xkxu
 *
 * https://blog.csdn.net/koastal/article/details/53456696
 */
public class DefaultRequestTokenHandler implements RequestTokenHandler, ApplicationEventPublisherAware {

	//private LoggerHandle logger = LoggerHandle.Instance(getClass());

	private RequestTokenStore requestTokenStore;

	private SgitgSafeProperties sgitgSafeProperties;

	private PathMatcher pathMatcher = new AntPathMatcher();

	private UrlPathHelper urlPathHelper = new UrlPathHelper();

	private ApplicationEventPublisher applicationEventPublisher;

	private RequestTokenParser requestTokenParser;

	private RequestTokenValidator requestTokenValidator;

	@Deprecated
	public DefaultRequestTokenHandler(RequestTokenStore requestTokenStore,
									  SgitgSafeProperties sgitgSafeProperties,
									  PcodeEncoder pscodeEncoder) {
		this.requestTokenStore = requestTokenStore;
		this.sgitgSafeProperties = sgitgSafeProperties;
		this.requestTokenValidator = new SimpleRequestTokenValidator(requestTokenStore, sgitgSafeProperties, pscodeEncoder);

		requestTokenParser = new DelegateRequestTokenParser(sgitgSafeProperties);
	}

	public DefaultRequestTokenHandler(RequestTokenStore requestTokenStore,
									  SgitgSafeProperties sgitgSafeProperties,
									  RequestTokenValidator requestTokenValidator) {
		this.requestTokenStore = requestTokenStore;
		this.sgitgSafeProperties = sgitgSafeProperties;
		this.requestTokenValidator = requestTokenValidator;

		requestTokenParser = new DelegateRequestTokenParser(sgitgSafeProperties);
	}

	@Override
	public void setApplicationEventPublisher(ApplicationEventPublisher applicationEventPublisher) {
		this.applicationEventPublisher = applicationEventPublisher;
	}

	public boolean support(HttpServletRequest request) {
		return sgitgSafeProperties.getRequestToken().isEnabled() && matchRequest(request);
	}

	protected boolean matchRequest(HttpServletRequest request) {
		String requestUri = urlPathHelper.getLookupPathForRequest(request);
		return sgitgSafeProperties.getRequestToken().getUrls()
				.stream()
				.filter(url -> pathMatcher.match(url, requestUri))
				.findAny()
				.isPresent();
	}

	@Override
	public void validate(HttpServletRequest request) throws IllegalRequestTokenException {
		if (support(request)) {
			RequestToken requestTokenFromRequest = parseRequestToken(request);

			if (requestTokenFromRequest != RequestToken.ILLEGAL_REQUEST_TOKEN
					&& requestTokenValidator.validate(requestTokenFromRequest)) {
				requestTokenStore.save(requestTokenFromRequest);
			} else {
				applicationEventPublisher.publishEvent(new IllegalRequestTokenApplicationEvent(
						requestTokenFromRequest != null ? requestTokenFromRequest : RequestToken.ILLEGAL_REQUEST_TOKEN));
				throw new IllegalRequestTokenException();
			}
		}
	}

	protected RequestToken parseRequestToken(HttpServletRequest request) {
		return requestTokenParser.parse(request);
	}

}
