package cn.aotcloud.security.transport.support;

import cn.aotcloud.security.transport.AbstractResponseEncryptor;
import cn.aotcloud.security.transport.CryptoHttpInputMessage;
import cn.aotcloud.security.transport.CryptoMediaType;
import cn.aotcloud.security.transport.HttpCryptoSm2Certificate;
import cn.aotcloud.utils.HttpServletUtil;

import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpInputMessage;
import org.springframework.util.StreamUtils;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.Charset;

/**
 * @author xkxu
 */
public class DefaultResponseEncryptor extends AbstractResponseEncryptor {

    private Charset charset = Charset.forName("UTF-8");

    public DefaultResponseEncryptor(HttpCryptoSm2Certificate sm2Key) {
        super(sm2Key);
    }

    @Override
    public InputStream encrypt(InputStream inputStream) throws IOException {
        String encryptedText = encryptToText(inputStream);
        return new ByteArrayInputStream(encryptedText.getBytes(charset));
    }

    @Override
    public String encryptToText(InputStream inputStream) throws IOException {
        String body = StreamUtils.copyToString(inputStream, charset);
        return getTextEncryptor().encrypt(body);
    }

    @Override
    public HttpInputMessage encrypt(HttpInputMessage inputMessage) throws IOException {
        HttpHeaders headers = new HttpHeaders();
        HttpServletUtil.putAllHeader(headers, inputMessage.getHeaders());
        HttpServletUtil.setHeader(headers, HttpHeaders.CONTENT_TYPE, CryptoMediaType.APPLICATION_SM4_PUBLIC_JSON_UTF8_VALUE);
        return new CryptoHttpInputMessage(encrypt(inputMessage.getBody()), headers);
    }

    public void setCharset(Charset charset) {
        this.charset = charset;
    }

    public Charset getCharset() {
        return charset;
    }

}
