package cn.aotcloud.security.tamperproofing.impl;

import org.springframework.http.MediaType;
import org.springframework.http.converter.json.MappingJackson2HttpMessageConverter;
import org.springframework.http.server.ServletServerHttpRequest;
import org.springframework.security.crypto.encrypt.TextEncryptor;

import javax.servlet.http.HttpServletRequest;
import java.io.IOException;

/**
 * 处理JSON格式的Body，媒体类型是 {@value MediaType#APPLICATION_JSON_UTF8_VALUE}。
 *
 * 采用 {@link MappingJackson2HttpMessageConverter} 将Body序列化成 Object对象。
 *
 * @author xkxu
 *
 * @see MappingJackson2HttpMessageConverter
 */
public class JsonBodyTamperProofingChecker extends PostBodyTamperProofingChecker {

	public JsonBodyTamperProofingChecker(TextEncryptor textEncryptor,
			MappingJackson2HttpMessageConverter jackson2HttpMessageConverter) {
		super(textEncryptor, jackson2HttpMessageConverter);
	}

	@Override
	protected boolean supportInternal(HttpServletRequest request) {
		return MediaType.parseMediaType(request.getContentType()).includes(MediaType.APPLICATION_JSON);
	}

	@Override
	protected Object getBody(HttpServletRequest request) throws IOException {
		ServletServerHttpRequest serverHttpRequest = new ServletServerHttpRequest(request);
		// return a List or LinkedHashMap
		return jackson2HttpMessageConverter.read(Object.class, serverHttpRequest);
	}
}
