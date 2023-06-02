package cn.aotcloud.security.tamperproofing.impl;

import cn.aotcloud.security.tamperproofing.AbstractTamperProofingChecker;
import cn.aotcloud.security.tamperproofing.SafeException;
import cn.aotcloud.utils.HttpServletUtil;

import org.apache.commons.lang3.StringUtils;
import org.springframework.security.crypto.encrypt.TextEncryptor;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.util.UriComponentsBuilder;

import javax.servlet.http.HttpServletRequest;

import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * 检查GET请求的查询参数的防篡改检查。对查询参数进行升序排序。
 *
 * 例如请求的查询参数：http://localhost/path?q1=dd&12=dd&a=s。
 *
 * 进行排序后的查询字符串是：12=dd&a=s&q1=dd。
 *
 * @author xkxu
 */
public class GetQueryTamperProofingChecker extends AbstractTamperProofingChecker {

	public GetQueryTamperProofingChecker(TextEncryptor textEncryptor) {
		super(textEncryptor);
	}

	@Override
	public boolean support(HttpServletRequest request) {
		return isGetQueryRequest(request) && !isRootRequest(request) && !isIgwClientRequest(request);
	}

	/**
	 * 是否GET查询请求，并存在URL查询参数。
	 *
	 * @param request
	 *            HTTP请求对象
	 * @return
	 * @see HttpServletRequest#getQueryString()
	 */
	protected boolean isGetQueryRequest(HttpServletRequest request) {
		return StringUtils.equalsIgnoreCase("GET", request.getMethod())
				&& StringUtils.isNotBlank(HttpServletUtil.getQueryString(request));
	}

	protected boolean isRootRequest(HttpServletRequest request) {
		return StringUtils.equalsAnyIgnoreCase(request.getServletPath(), "/", "");
	}
	
	protected boolean isIgwClientRequest(HttpServletRequest request) {
		return StringUtils.equalsIgnoreCase("/", request.getServletPath())
				&& StringUtils.containsAnyIgnoreCase(HttpServletUtil.getQueryString(request), "version=", "platform=");
	}
	
	@Override
	public void check(HttpServletRequest request) throws SafeException {
		String data = sortQueryString(request);
		doValdiate(request, data, getSignValue(request));
	}

	/**
	 * 对查询字符串根据KEY的进行排序。
	 *
	 * <code>
	 *     http://localhost/path?q1=dd&12=dd&a=s.
	 * </code>
	 *
	 * @param request
	 *            HTTP请求对象
	 * @return 排序后的查询参数字符串
	 * @see HttpServletRequest#getQueryString()
	 */
	protected String sortQueryString(HttpServletRequest request) {
		String queryString = HttpServletUtil.getQueryString(request);
		if (StringUtils.contains(queryString, "&")) {
			//MultiValueMap<String, String> queryParams = UriComponentsBuilder.fromHttpRequest(new ServletServerHttpRequest(request)).build().getQueryParams();
			MultiValueMap<String, String> queryParams = new LinkedMultiValueMap<String, String>();
			if(StringUtils.isNotBlank(queryString)) {
				String[] items = queryString.split("&");
				for(String item : items) {
					if(StringUtils.contains(item, "=")) {
						queryParams.add(StringUtils.substringBefore(item, "="), StringUtils.substringAfter(item, "="));
					}
				}
			}
			
			List<String> list = new ArrayList<String>(queryParams.keySet());
			Collections.sort(list);

			MultiValueMap<String, String> hashMap = new LinkedMultiValueMap<>();

			list.forEach(key -> {
				if (!StringUtils.equals(DATA_SIGN_HEAER_NAME, key)) {
					hashMap.put(key, queryParams.get(key));
				}
			});
			queryString = UriComponentsBuilder.fromHttpUrl("http://localhost").queryParams(hashMap).build().getQuery();
		}
		return urlDecode(queryString);
	}

	protected String urlDecode(String queryString) {
		try {
			return URLDecoder.decode(queryString, StandardCharsets.UTF_8.name());
		} catch (UnsupportedEncodingException e) {
			return queryString;
		}
	}
}
