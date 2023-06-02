package cn.aotcloud.security.tamperproofing;

import org.springframework.util.AntPathMatcher;
import org.springframework.util.PathMatcher;
import org.springframework.web.util.UrlPathHelper;

import javax.servlet.http.HttpServletRequest;
import java.util.List;

/**
 * HTTP请求匹配接口 HttpRequestMatcher 默认实现。
 *
 * 默认采用 ANT匹配模式。采用 UrlPathHelper 处理请求对象的URL路径。
 *
 * @author xkxu
 */
public class SimpleHttpRequestMatcher implements HttpRequestMatcher {

	/**
	 * 路径匹配处理器，默认使用 AntPathMatcher。
	 */
	private final PathMatcher pathMatcher;

	/**
	 * URL路径工具对象，处理URL请求路径
	 */
	private final UrlPathHelper urlPathHelper;

	public SimpleHttpRequestMatcher() {
		this(null, null);
	}

	/**
	 * 创建HTTP请求匹配对象
	 *
	 * @param pathMatcher
	 *            可能为空
	 * @param urlPathHelper
	 *            可能为空
	 */
	public SimpleHttpRequestMatcher(PathMatcher pathMatcher, UrlPathHelper urlPathHelper) {
		this.pathMatcher = pathMatcher != null ? pathMatcher : new AntPathMatcher();
		this.urlPathHelper = urlPathHelper != null ? urlPathHelper : new UrlPathHelper();
	}

	@Override
	public boolean match(List<String> patterns, HttpServletRequest request) {
		String requestUri = getUrlPathHelper().getLookupPathForRequest(request);
		return match(patterns, requestUri);
	}

	@Override
	public boolean match(List<String> patterns, String path) {
		return patterns.stream().anyMatch(pattern -> match(pattern, path));
	}

	@Override
	public boolean match(String pattern, HttpServletRequest request) {
		String requestUri = getUrlPathHelper().getLookupPathForRequest(request);
		return match(pattern, requestUri);
	}

	@Override
	public boolean match(String pattern, String path) {
		return getPathMatcher().match(pattern.trim(), path);
	}

	@Override
	public PathMatcher getPathMatcher() {
		return pathMatcher;
	}

	@Override
	public UrlPathHelper getUrlPathHelper() {
		return urlPathHelper;
	}
}
