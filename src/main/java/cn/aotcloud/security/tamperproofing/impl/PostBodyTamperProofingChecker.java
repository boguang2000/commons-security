package cn.aotcloud.security.tamperproofing.impl;

import cn.aotcloud.security.tamperproofing.SafeException;
import cn.aotcloud.utils.HttpServletUtil;

import org.apache.commons.lang3.StringUtils;
import org.springframework.http.HttpMethod;
import org.springframework.http.converter.json.MappingJackson2HttpMessageConverter;
import org.springframework.security.crypto.encrypt.TextEncryptor;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * POST请求Body数据防篡改实现基类，
 * 
 * Method; import
 * org.springframework.http.converter.json.MappingJackson2HttpMessageConverter;
 * import org.springframework.http.server.ServletServerHttpRequest; import
 * org.springframework.security.crypto.encrypt.TextEncryptor;
 * 
 * import javax.servlet.ServletException; import javax.servlet.http.HttpServletR
 * 
 * import
 * com.xxx.acloud.base.safe.filter.tamperproofing.SafeException;ST请求也使用URL查询参数。
 *
 * 将POST请求的数据封装成以下数据格式，并格式化成JSON字符串，并且JSON的KEY需要排序。
 *
 * <code>
 *     1. 存在查询参数和Body：
 *     {"body":"{\"d\": \"d\"}","query":"12=dd&a=s&q1=dd"}
 *     2. 只存在Body:
 *     {"body":"{\"d\": \"d\"}"}
 *     3. 只存在查询参数：
 *     {query":"12=dd&a=s&q1=dd"}
 * </code>
 *
 * 将上述JSON对象序列化成字符串，进行防篡改检查。
 *
 * 注意：Java中字符串都是采用双引号括起来的，没有空格和格式化，
 *
 * 而前端JavaScript可以采用单引号和双引号，前端需要采用双引号才能与后端保持一致。
 *
 * @author xkxu
 *
 * @see FormBodyTamperProofingChecker
 * @see JsonBodyTamperProofingChecker
 * @see MultipartBodyTamperProofingChecker
 */
public abstract class PostBodyTamperProofingChecker extends GetQueryTamperProofingChecker {

	/**
	 * 序列化JSON类型Body，将Body转换成JSON字符串。
	 */
	protected final MappingJackson2HttpMessageConverter jackson2HttpMessageConverter;

	/**
	 * @param textEncryptor
	 * @param jackson2HttpMessageConverter
	 */
	public PostBodyTamperProofingChecker(TextEncryptor textEncryptor,
			MappingJackson2HttpMessageConverter jackson2HttpMessageConverter) {
		super(textEncryptor);
		this.jackson2HttpMessageConverter = jackson2HttpMessageConverter;
	}

	@Override
	public boolean support(HttpServletRequest request) {
		return StringUtils.isNotBlank(request.getContentType()) 
				&& HttpMethod.resolve(request.getMethod()) == HttpMethod.POST 
				&& supportInternal(request)
				&& !super.isRootRequest(request);
	}

	@Override
	public void check(HttpServletRequest request) throws SafeException {
		String data = getBodyAndQueryAsJson(request);
		doValdiate(request, data, getSignValue(request));
	}

	/**
	 * 子类应该实现该抽象方法，判断是否需要检查HTTP请求。
	 *
	 * @param request
	 *            HTTP请求对象
	 * @return true需要检查请求，false不需要检查请求
	 */
	protected abstract boolean supportInternal(HttpServletRequest request);

	/**
	 * 将POST请求Body序列化成Object对象。根据媒体类型
	 * {@link HttpServletRequest#getContentType()}序列化Body。
	 *
	 * @param request
	 *            HTTP请求对象
	 * @return 序列化后的Body数据
	 * @throws IOException
	 *             操作IO错误
	 * @throws ServletException
	 *             系统错误异常
	 */
	protected abstract Object getBody(HttpServletRequest request) throws IOException, ServletException;

	/**
	 * 将请求数据根据序列化成JSON字符串
	 *
	 * @param request
	 *            HTTP请求对象
	 * @return 请求数据JSON字符串
	 */
	protected String getBodyAndQueryAsJson(HttpServletRequest request) {
		//ServletServerHttpRequest serverHttpRequest = new ServletServerHttpRequest(request);
		try {
			Object body = getBody(request);

			LinkedHashMap<String, Object> bodyAndQuery = new LinkedHashMap<>();
			if (body != null) {
				bodyAndQuery.put("body", body);
			}
			if (StringUtils.isNotBlank(HttpServletUtil.getQueryString(request))) {
				String query = sortQueryString(request);
				bodyAndQuery.put("query", query);
			}
			if (bodyAndQuery.isEmpty()) {
				return null;
			}
			return jackson2HttpMessageConverter.getObjectMapper().writeValueAsString(convertData(bodyAndQuery));
		} catch (IOException | ServletException e) {
			logger.error(e);
			throw new SafeException("防篡改异常：系统错误。");
		}
	}

	/**
	 * 对Map中的属性名称进行排序。
	 *
	 * @param value
	 *            需要排序的对象。
	 * @return 排序后的对象。
	 */
	@SuppressWarnings({ "rawtypes", "unchecked" })
	public Object convertData(Object value) {
		if (value instanceof Map) {
			Map<String, Object> json = (Map) value;
			LinkedHashMap<String, Object> data = new LinkedHashMap<>();
			List<String> keys = new ArrayList<String>(json.keySet());
			Collections.sort(keys);
			keys.forEach(key -> {
				data.put(key, convertData(json.get(key)));
			});
			return data;
		} else if (value instanceof List) {
			List<Object> array = (List) value;
			List<Object> list = new ArrayList<>();
			array.forEach(json -> {
				list.add(convertData(json));
			});
			return list;
		}
		return value;
	}
}
