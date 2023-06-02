package cn.aotcloud.security.transport;

import org.springframework.security.crypto.encrypt.TextEncryptor;

/**
 * @author xkxu
 */
public class HttpTextEncryptor {

    /**
     * 网络传输加密解密
     */
    private final HttpCryptoSm2Certificate sm2Key;

    public HttpTextEncryptor(HttpCryptoSm2Certificate sm2Key) {
        this.sm2Key = sm2Key;
    }

    public TextEncryptor getTextEncryptor() {
        return sm2Key.getTextEncryptor();
    }

}
