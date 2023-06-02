package cn.aotcloud.security.tamperproofing.impl;

import org.apache.commons.lang3.StringUtils;
import org.springframework.http.MediaType;
import org.springframework.http.converter.json.MappingJackson2HttpMessageConverter;
import org.springframework.security.crypto.encrypt.TextEncryptor;
import org.springframework.web.util.UriComponents;
import org.springframework.web.util.UriComponentsBuilder;

import cn.aotcloud.utils.HttpServletUtil;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

/**
 * 处理表单提交的POST请求，媒体类型是 {@value MediaType#APPLICATION_FORM_URLENCODED_VALUE}。
 *
 * <p>
 * 将表单数据转换成 Map对象。根据KEY值排序，Value值是转换成单个值，不支持一个属性多个值的情况，因为排序后的字符串可能不一致。
 *
 * @author xkxu
 */
public class FormBodyTamperProofingChecker extends PostBodyTamperProofingChecker {

	public FormBodyTamperProofingChecker(TextEncryptor textEncryptor,
			MappingJackson2HttpMessageConverter jackson2HttpMessageConverter) {
		super(textEncryptor, jackson2HttpMessageConverter);
	}

	@Override
	public boolean supportInternal(HttpServletRequest request) {
		return MediaType.parseMediaType(request.getContentType()).includes(MediaType.APPLICATION_FORM_URLENCODED);
	}

	@Override
	protected Object getBody(HttpServletRequest request) throws IOException, ServletException {
		Map<String, String[]> parameters = request.getParameterMap();
		return toSimpleMap(parameters, request);
	}

	protected Map<String, String> toSimpleMap(Map<String, String[]> parameters, HttpServletRequest request) {
		Map<String, String> body = new HashMap<>();
		UriComponents uriComponents = UriComponentsBuilder
				.fromHttpUrl("http://localhost/dd?" + HttpServletUtil.getQueryString(request)).build();

		parameters.forEach((key, values) -> {
			if (StringUtils.equalsIgnoreCase(key, DATA_SIGN_HEAER_NAME)
					|| uriComponents.getQueryParams().containsKey(key)) {
				return;
			}
			if (values != null && values.length > 0) {
				body.put(key, values[0]);
			} else {
				body.put(key, null);
			}
		});
		return body;
	}
}
