package cn.aotcloud.security.transport;

import org.springframework.http.HttpInputMessage;

import java.io.IOException;

/**
 * 请求数据解密处理器接口定义。
 *
 * @author xkxu
 */
public interface RequestDecryptor {
    public static final String CRYPTO_PREFIX = "{ac_crypto}";

    public static final String CRYPTO_SEPARATOR = "AAAA0000BBBB";

    /**
     * 返回请求数据解密处理器描述信息，主要用于安全检查报告中。
     *
     * @return  请求数据解密处理器描述信息
     */
    public String getDescription();

    /**
     * 检查是否需要解密请求数据
     *
     * @param inputMessage   HTTP请求对象
     * @return  true需要解密，false不需要解密
     */
    public boolean support(HttpInputMessage inputMessage);

    /**
     * {@link #support(HttpInputMessage)} 方法返回true，就执行该方法解密请求数据。
     *
     * @param inputMessage   HTTP请求对象
     * @throws IOException
     */
    public CryptoHttpInputMessage decrypt(HttpInputMessage inputMessage) throws IOException;

}
