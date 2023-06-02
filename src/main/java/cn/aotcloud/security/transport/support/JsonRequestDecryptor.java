package cn.aotcloud.security.transport.support;

import java.io.IOException;
import java.util.Map;

import org.springframework.http.HttpInputMessage;
import org.springframework.http.HttpMethod;
import org.springframework.http.converter.StringHttpMessageConverter;
import org.springframework.http.server.ServletServerHttpRequest;

import com.alibaba.fastjson.JSONObject;

import cn.aotcloud.security.transport.CryptoHttpInputMessage;
import cn.aotcloud.security.transport.CryptoMediaType;
import cn.aotcloud.security.transport.HttpCryptoSm2Certificate;

/**
 * 继承于 QueryParamtersRequestDecryptor 支持对请求参数解密，该实现只处理JSON格式和POST请求的加密请求数据。
 *
 * 客户端在提交加密数据时，需要遵守以下的JSON数据格式：
 * <code>
 *     {
 *          body: {
 *              data: 加密的数据
 *          }
 *     }
 * </code>
 *
 * 加密的数据的数据应该是一个JSON字符串，并且使用与后端解密匹配的加密方式。
 *
 * 该实现会将加密的数据的数据解密，转换成JSON格式的数据。
 *
 * @author xkxu
 */
public class JsonRequestDecryptor extends QueryParamsRequestDecryptor {

    private StringHttpMessageConverter stringHttpMessageConverter;

    public JsonRequestDecryptor(HttpCryptoSm2Certificate httpCryptoSm2Certificate,
                                StringHttpMessageConverter stringHttpMessageConverter) {
        super(httpCryptoSm2Certificate);
        this.stringHttpMessageConverter = stringHttpMessageConverter;
    }

    @Override
    public boolean support(HttpInputMessage inputMessage) {
        if (inputMessage instanceof ServletServerHttpRequest) {
            ServletServerHttpRequest httpRequest = (ServletServerHttpRequest) inputMessage;
            if(httpRequest != null && httpRequest.getHeaders().getContentType() != null) {
            	return httpRequest.getMethod().matches(HttpMethod.POST.name())
                        && httpRequest.getHeaders().getContentType().includes(CryptoMediaType.APPLICATION_SM4_PUBLIC_JSON_UTF8);
            }
        }
        return false;
    }

    @SuppressWarnings("unchecked")
	@Override
    public CryptoHttpInputMessage doDecrypt(HttpInputMessage inputMessage) throws IOException {
        CryptoHttpInputMessage cryptoHttpInputMessage = null;
        if (super.support(inputMessage)) {
            cryptoHttpInputMessage = super.doDecrypt(inputMessage);
        } else {
            cryptoHttpInputMessage = new CryptoHttpInputMessage();
        }
        String encryptedData = stringHttpMessageConverter.read(String.class, inputMessage);
        Map<String, Object> body = JSONObject.parseObject(encryptedData, Map.class);
        if (encryptedData != null) {
            String text = decryptData((String) body.get("data"));
            byte[] bytes = text.getBytes(getCharset(inputMessage));
            cryptoHttpInputMessage.setBody(bytes);
        } else {
            //logger.warn("加密的数据为空。");
        }
        return cryptoHttpInputMessage;
    }
}
