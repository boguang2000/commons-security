package cn.aotcloud.security.tamperproofing.impl;

import org.springframework.http.MediaType;
import org.springframework.http.converter.json.MappingJackson2HttpMessageConverter;
import org.springframework.security.crypto.encrypt.TextEncryptor;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * 处理文件上传POST请求，媒体类型是 {@value MediaType#MULTIPART_FORM_DATA_VALUE}。
 *
 * <code>
 *     {"parameters": parameters,"parts": [{"name": "ddd.jpg","size": 123}]}
 * </code>
 *
 * @author xkxu
 */
public class MultipartBodyTamperProofingChecker extends FormBodyTamperProofingChecker {

	public MultipartBodyTamperProofingChecker(TextEncryptor textEncryptor,
			MappingJackson2HttpMessageConverter jackson2HttpMessageConverter) {
		super(textEncryptor, jackson2HttpMessageConverter);
	}

	@Override
	public boolean supportInternal(HttpServletRequest request) {
		return false;
		// return
		// MediaType.parseMediaType(request.getContentType()).includes(MediaType.MULTIPART_FORM_DATA);
	}

	@Override
	protected Object getBody(HttpServletRequest request) throws IOException, ServletException {
		Map<String, Object> body = new HashMap<>();
		Map<String, String> parameters = toSimpleMap(request.getParameterMap(), request);
		if (!parameters.isEmpty()) {
			body.put("parameters", parameters);
		}
		List<Map<String, Object>> parts = toMultipartInfos(request);
		if (!parts.isEmpty()) {
			body.put("parts", parts);
		}
		return null;
	}

	private List<Map<String, Object>> toMultipartInfos(HttpServletRequest request)
			throws IOException, ServletException {
		List<Map<String, Object>> list = new ArrayList<>();

		request.getParts().forEach(part -> {
			Map<String, Object> info = new HashMap<>();
			info.put("name", part.getName());
			info.put("size", part.getSize());
		});

		return list;
	}
}
