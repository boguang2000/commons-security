package cn.aotcloud.security.transport;

import org.springframework.security.crypto.encrypt.TextEncryptor;

import cn.aotcloud.crypto.sm.SMImplMode;
import cn.aotcloud.crypto.sm.delegate.SMCryptoFactory;

/**
 * @author xkxu
 */
public class HttpCryptoSm4Certificate {

    private String secretKey = "58b1463a76ca4bbc95fc1e255bbc9109";

    private TextEncryptor textEncryptor;

    public HttpCryptoSm4Certificate() {
    }

    public HttpCryptoSm4Certificate(String secretKey) {
        this.secretKey = secretKey;
    }

    public String getSecretKey() {
        return secretKey;
    }

    public void setSecretKey(String secretKey) {
        this.secretKey = secretKey;
    }

    public void setTextEncryptor(TextEncryptor textEncryptor) {
        this.textEncryptor = textEncryptor;
    }

    public TextEncryptor getTextEncryptor() {
        if (textEncryptor == null) {
            this.textEncryptor = SMCryptoFactory
                    .createSM4TextEncryptor(secretKey, SMImplMode.java);
        }
        return textEncryptor;
    }
}
