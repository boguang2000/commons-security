package cn.aotcloud.security.transport;

import org.springframework.http.HttpInputMessage;

import java.io.IOException;
import java.io.InputStream;

/**
 * HTTP响应数据加密处理接口定义。
 *
 * @author xkxu
 */
public interface ResponseEncryptor {

    public InputStream encrypt(InputStream inputStream) throws IOException;

    public String encryptToText(InputStream inputStream) throws IOException;

    public HttpInputMessage encrypt(HttpInputMessage inputMessage) throws IOException;
}
