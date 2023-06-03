package cn.aotcloud.security.oncetoken.support;

import cn.aotcloud.security.oncetoken.IllegalRequestTokenException;
import cn.aotcloud.security.oncetoken.OnceProtocol;
import cn.aotcloud.security.oncetoken.RequestToken;
import cn.aotcloud.security.oncetoken.RequestTokenHandler;
import cn.aotcloud.security.oncetoken.RequestTokenParser;
import cn.aotcloud.security.oncetoken.RequestTokenStore;
import cn.aotcloud.security.oncetoken.RequestTokenValidator;
import cn.aotcloud.security.oncetoken.event.IllegalRequestTokenApplicationEvent;

import org.apache.commons.compress.utils.Lists;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.ApplicationEventPublisherAware;
import org.springframework.util.AntPathMatcher;
import org.springframework.util.PathMatcher;
import org.springframework.web.util.UrlPathHelper;

import java.util.List;

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

	private PathMatcher pathMatcher = new AntPathMatcher();

	private UrlPathHelper urlPathHelper = new UrlPathHelper();

	private ApplicationEventPublisher applicationEventPublisher;

	private RequestTokenParser requestTokenParser;

	private RequestTokenValidator requestTokenValidator;
	
	private List<OnceProtocol> supportedProtocols;
	
	private boolean requestTokenEnabled;
	
	private List<String> urls = Lists.newArrayList();
	
	public DefaultRequestTokenHandler(RequestTokenStore requestTokenStore,
									  RequestTokenValidator requestTokenValidator,
									  boolean requestTokenEnabled,
                                      List<String> urls) {
		this.requestTokenStore = requestTokenStore;
		this.requestTokenValidator = requestTokenValidator;
		this.requestTokenEnabled = requestTokenEnabled;
		this.urls.addAll(urls);
		
		requestTokenParser = new DelegateRequestTokenParser(supportedProtocols);
	}

	@Override
	public void setApplicationEventPublisher(ApplicationEventPublisher applicationEventPublisher) {
		this.applicationEventPublisher = applicationEventPublisher;
	}

	public boolean support(HttpServletRequest request) {
		return this.requestTokenEnabled && matchRequest(request);
	}

	protected boolean matchRequest(HttpServletRequest request) {
		String requestUri = urlPathHelper.getLookupPathForRequest(request);
		return this.urls.stream()
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
