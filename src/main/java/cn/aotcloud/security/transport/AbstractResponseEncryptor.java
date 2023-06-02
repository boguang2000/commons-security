package cn.aotcloud.security.transport;

/**
 * @author xkxu
 */
public abstract class AbstractResponseEncryptor extends HttpTextEncryptor implements ResponseEncryptor {

    public AbstractResponseEncryptor(HttpCryptoSm2Certificate httpCryptoSm2Certificate) {
        super(httpCryptoSm2Certificate);
    }
}
