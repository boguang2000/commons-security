package cn.aotcloud.security.transport.support;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import org.apache.commons.lang3.StringUtils;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpInputMessage;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpOutputMessage;
import org.springframework.http.MediaType;
import org.springframework.http.converter.support.AllEncompassingFormHttpMessageConverter;
import org.springframework.http.server.ServletServerHttpRequest;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;

import cn.aotcloud.security.transport.CryptoHttpInputMessage;
import cn.aotcloud.security.transport.HttpCryptoSm2Certificate;
import cn.aotcloud.utils.HttpServletUtil;
import cn.aotcloud.utils.IOUtils;

/**
 * @author xkxu
 */
public class FormRequestDecryptor extends QueryParamsRequestDecryptor {

    private static final String FORM_ATTR_CRYPTO_DATA = "x_ac_form_attr_crypto_data";

    private AllEncompassingFormHttpMessageConverter formHttpMessageConverter;

    public FormRequestDecryptor(HttpCryptoSm2Certificate httpCryptoSm2Certificate,
                                AllEncompassingFormHttpMessageConverter formHttpMessageConverter) {
        super(httpCryptoSm2Certificate);
        this.formHttpMessageConverter = formHttpMessageConverter;
    }

    @Override
    public boolean support(HttpInputMessage inputMessage) {
        if (inputMessage instanceof ServletServerHttpRequest) {
            ServletServerHttpRequest httpRequest = (ServletServerHttpRequest) inputMessage;
            return httpRequest.getMethod().matches(HttpMethod.POST.name())
                    && isFormAndMultipart(inputMessage.getHeaders().getContentType())
                    && StringUtils.isNotBlank(HttpServletUtil.getParameter(httpRequest.getServletRequest(), FORM_ATTR_CRYPTO_DATA));
        }
        return false;
    }

    protected boolean isFormAndMultipart(MediaType contentType) {
        return contentType != null && (contentType.includes(MediaType.APPLICATION_FORM_URLENCODED)
                || contentType.includes(MediaType.MULTIPART_FORM_DATA));
    }

    @Override
    public CryptoHttpInputMessage doDecrypt(HttpInputMessage inputMessage) throws IOException {
        CryptoHttpInputMessage cryptoHttpInputMessage;
        if (super.support(inputMessage)) {
            cryptoHttpInputMessage = super.doDecrypt(inputMessage);
        } else {
            cryptoHttpInputMessage = new CryptoHttpInputMessage();
        }
        ServletServerHttpRequest httpRequest = (ServletServerHttpRequest) inputMessage;
//        HttpServletUtil.getParameter(httpRequest.getServletRequest(), "name");
        String encryptedData = HttpServletUtil.getParameter(httpRequest.getServletRequest(), FORM_ATTR_CRYPTO_DATA);
        setSm4KeyHolder(encryptedData);
//        String decryptedData = decryptData(encryptedData);
//        Map<String, Object> formData = JSONObject.parseObject(decryptedData, Map.class);
//        MultiValueMap<String, ?> form = parseDecryptedData(formData);

        HttpOutputMessage outputMessage = new ByteArrayHttpOutputMessage(httpRequest);
//        getFormHttpMessageConverter().write(form, httpRequest.getHeaders().getContentType(), outputMessage);
        ByteArrayOutputStream baos = (ByteArrayOutputStream) outputMessage.getBody();
        byte[] bytes = baos.toByteArray();
        cryptoHttpInputMessage.setBody(bytes);
        IOUtils.closeQuietly(baos);
        
        return cryptoHttpInputMessage;
    }

    protected MultiValueMap<String, ?> parseDecryptedData(Map<String, Object> decryptedData) {
        MultiValueMap<String, Object> form = new LinkedMultiValueMap<>();
        for (String key: decryptedData.keySet()) {
            List<Object>  tmp = new ArrayList<>();
            tmp.add(decryptedData.get(key));
            form.put(key, tmp);
        }
        return form;
    }

    public AllEncompassingFormHttpMessageConverter getFormHttpMessageConverter() {
        return formHttpMessageConverter;
    }

    private static class ByteArrayHttpOutputMessage implements HttpOutputMessage {

        ServletServerHttpRequest request;

        private ByteArrayOutputStream outputStream = new ByteArrayOutputStream();

        public ByteArrayHttpOutputMessage(ServletServerHttpRequest request) {
            this.request = request;
        }

        @Override
        public OutputStream getBody() throws IOException {
            return outputStream;
        }

        @Override
        public HttpHeaders getHeaders() {
            return request.getHeaders();
        }
    }
}
