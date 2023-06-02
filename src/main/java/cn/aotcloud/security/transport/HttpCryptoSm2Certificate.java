package cn.aotcloud.security.transport;

import cn.aotcloud.crypto.sm.SMImplMode;
import cn.aotcloud.crypto.sm.delegate.SMCryptoFactory;
import org.springframework.security.crypto.encrypt.TextEncryptor;

/**
 * @author xkxu
 */
public class HttpCryptoSm2Certificate {

    private String pubKeyHex = "048825F83FE608DD68320FBFFE414485CC246445D1BEB21D3380E6862BD6F66E9C66CC8A08B59698651F4BBFF47D22E6275CD511CE967BE4712AA0D653FFF0DD8F";

    private String prvKeyHex = "00D437C318242C7DD29DC07712799725FE6BC9A5355DB2CD0A179FA23643333D06";

    private TextEncryptor textEncryptor;

    public HttpCryptoSm2Certificate() {
    }

    public HttpCryptoSm2Certificate(String pubKeyHex, String prvKeyHex) {
        this.pubKeyHex = pubKeyHex;
        this.prvKeyHex = prvKeyHex;
    }

    public String getPubKeyHex() {
        return pubKeyHex;
    }

    public void setPubKeyHex(String pubKeyHex) {
        this.pubKeyHex = pubKeyHex;
    }

    public String getPrvKeyHex() {
        return prvKeyHex;
    }

    public void setPrvKeyHex(String prvKeyHex) {
        this.prvKeyHex = prvKeyHex;
    }

    public TextEncryptor getTextEncryptor() {
        if (textEncryptor == null) {
            this.textEncryptor = SMCryptoFactory
                    .createSM2TextEncryptor(getPubKeyHex(), getPrvKeyHex(), SMImplMode.java);
        }
        return textEncryptor;
    }
}
