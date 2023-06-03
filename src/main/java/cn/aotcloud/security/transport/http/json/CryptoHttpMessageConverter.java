package cn.aotcloud.security.transport.http.json;

import java.io.IOException;
import java.util.Collections;
import java.util.List;

import javax.servlet.http.HttpServletRequest;

import org.apache.commons.lang3.StringUtils;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpInputMessage;
import org.springframework.http.HttpOutputMessage;
import org.springframework.http.MediaType;
import org.springframework.http.converter.AbstractHttpMessageConverter;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.http.converter.HttpMessageNotWritableException;
import org.springframework.http.converter.StringHttpMessageConverter;
import org.springframework.http.converter.json.MappingJackson2HttpMessageConverter;
import org.springframework.util.AntPathMatcher;
import org.springframework.web.util.UrlPathHelper;

import com.google.common.collect.Lists;

import cn.aotcloud.security.transport.CryptoMediaType;
import cn.aotcloud.security.transport.HttpCryptoSm4Certificate;
import cn.aotcloud.security.transport.Sm4KeyHolder;
import cn.aotcloud.utils.HttpRequestUtil;

/**
 * @author xkxu
 * @author xkxu
 * Order 不能动，否则影响json转换器业务逻辑，应为有2个json转换器
 */
@Order(value = 1)
public class CryptoHttpMessageConverter extends AbstractHttpMessageConverter<Object> {

	private final MappingJackson2HttpMessageConverter jacksonConverter;
	
    private final StringHttpMessageConverter stringHttpMessageConverter = new StringHttpMessageConverter();

    private AntPathMatcher antPathMatcher = new AntPathMatcher();
    
    private UrlPathHelper urlPathHelper = new UrlPathHelper();
    
    private List<String> urls = Lists.newArrayList();
    
    private boolean urlExclude = true;
    
    public CryptoHttpMessageConverter(
    		MappingJackson2HttpMessageConverter jacksonConverter,
    		List<String> urls,
    		boolean urlExclude) {
    	this.jacksonConverter = jacksonConverter;
        this.urls.addAll(urls);
        this.urlExclude = urlExclude;
    }
    
    @Override
    protected boolean supports(Class<?> clazz) {
    	// 升级到Springboot2.x ResponseBodyEmitterReturnValueHandler 响应body序列化处理
    	if (HttpRequestUtil.getHttpServletRequestFromThreadLocal() == null) {
    		return false;
    	} else {
    		return this.shouldCrypto(HttpRequestUtil.getHttpServletRequestFromThreadLocal());
    	}
    }

    public boolean shouldCrypto(HttpServletRequest request) {
    	String requestUri = urlPathHelper.getLookupPathForRequest(request);
    	return shouldCrypto(requestUri);
    }
    
    /**
     * @updater ZSQ	修改支持通配符
     * @param url
     * @return
     */
    private boolean shouldCrypto(String url) {
        if (urlExclude) {
            return !doPtternUri(url);
        } else {
            return doPtternUri(url);
        }
    }
    
    /**
     * 修改支持使用通配符过滤
     * 
     * @author ZSQ
     * @param uri
     * @return
     */
    private boolean doPtternUri(String uri) {
    	for (String pattern : urls) {
    		if(antPathMatcher.match(pattern, uri)) {
    			return true;
    		}
		}
    	return false;
    }
    
    @Override
    protected boolean canWrite(MediaType mediaType) {
        return true;
    }
    
    @Override
    protected Object readInternal(Class<?> clazz, HttpInputMessage inputMessage) throws IOException, HttpMessageNotReadableException {
    	return null;
    }

    @Override
    public List<MediaType> getSupportedMediaTypes() {
        return Collections.singletonList(CryptoMediaType.APPLICATION_SM4_PUBLIC_JSON_UTF8);
    }
//
//    @Override
//    protected MediaType getDefaultContentType(Object o) throws IOException {
//        return super.getDefaultContentType(o);
//    }

    @Override
    protected void writeInternal(Object o, HttpOutputMessage outputMessage) throws IOException, HttpMessageNotWritableException {
//        if (!sgitgSafeProperties.getHttp()
//                .getResponse()
//                .shouldResponseCrypto(HttpRequestUtil.getHttpServletRequestFromThreadLocal().getRequestURI())) {
//            super.write(o, CryptoMediaType.APPLICATION_JSON, outputMessage);
//        }
    	//String responseJsonText = o instanceof String ? (String) o : JSONObject.toJSONString(o);
    	String responseJsonText = o instanceof String ? (String) o : jacksonConverter.getObjectMapper().writeValueAsString(o);
    	HttpCryptoSm4Certificate httpCryptoSm4Certificate = StringUtils.isEmpty(Sm4KeyHolder.getSm4Key()) ? new HttpCryptoSm4Certificate() : new HttpCryptoSm4Certificate(Sm4KeyHolder.getSm4Key());
//        Sm4KeyHolder.clear();
        outputMessage.getHeaders().set("X-AC-ENCRYPTO", "true");
        String encryptedResponseText = httpCryptoSm4Certificate.getTextEncryptor().encrypt(responseJsonText);
//        CryptoServletServerHttpResponse outputMessageToUse = new CryptoServletServerHttpResponse(outputMessage) ;
        stringHttpMessageConverter.write(encryptedResponseText, CryptoMediaType.APPLICATION_SM4_PUBLIC_JSON_UTF8, outputMessage);
    }


//    static class CryptoServletServerHttpResponse implements  HttpOutputMessage{
//
//        private final HttpOutputMessage httpOutputMessage;
//
//        public CryptoServletServerHttpResponse(HttpOutputMessage httpOutputMessage) {
//            this.httpOutputMessage = httpOutputMessage;
//        }
//
//        @Override
//        public HttpHeaders getHeaders() {
//            HttpHeaders headers = httpOutputMessage.getHeaders();
//            headers.put("content-type", Collections.singletonList(CryptoMediaType.APPLICATION_SM4_PUBLIC_JSON_UTF8_VALUE));
//            return headers;
//        }
//
//        @Override
//        public OutputStream getBody() throws IOException {
//            return httpOutputMessage.getBody();
//        }
//    }
}
