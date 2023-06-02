package cn.aotcloud.security.transport;

import java.io.IOException;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;

import org.apache.commons.lang3.StringUtils;
import org.springframework.http.HttpInputMessage;
import org.springframework.http.MediaType;
import org.springframework.security.crypto.encrypt.TextEncryptor;

import cn.aotcloud.exception.BaseException;
import cn.aotcloud.logger.LoggerHandle;

/**
 * 实现解耦 RequestDecryptor 的基类实现。
 *
 * @author xkxu
 */
public abstract class AbstractRequestDecryptor extends HttpTextEncryptor implements RequestDecryptor {

    protected LoggerHandle logger = new LoggerHandle(getClass());

    public AbstractRequestDecryptor(HttpCryptoSm2Certificate sm2Key) {
        super(sm2Key);
    }

    @Override
    public String getDescription() {
        return getTextEncryptor().getClass().getSimpleName() + "/" + getTextEncryptor().getClass().getSimpleName();
    }

    @Override
    public boolean support(HttpInputMessage inputMessage) {
        return true;
    }

    @Override
    public final CryptoHttpInputMessage decrypt(HttpInputMessage inputMessage) throws IOException {
        return doDecrypt(inputMessage);
    }

    /**
     *
     * @param inputMessage
     * @throws IOException
     */
    public abstract CryptoHttpInputMessage doDecrypt(HttpInputMessage inputMessage) throws IOException;

    protected String decryptData(String data) {
        String[] certificate = data.split(CRYPTO_SEPARATOR);
        if(certificate.length !=2 || StringUtils.isEmpty(certificate[0]) || StringUtils.isEmpty(certificate[1])) {
            throw new BaseException("数据完整性被破坏。");
        }
        String encryptedSm4RequestData = certificate[0];
        String sm4Key = getTextEncryptor().decrypt(certificate[1]);
        Sm4KeyHolder.setSm4Key(sm4Key);
        TextEncryptor sm4TextEncryptor = new HttpCryptoSm4Certificate(sm4Key).getTextEncryptor();
        return sm4TextEncryptor.decrypt(encryptedSm4RequestData);
    }

    protected String setSm4KeyHolder(String data) {
    	String[] certificate = data.split(CRYPTO_SEPARATOR);
        if(certificate.length !=2 || StringUtils.isEmpty(certificate[0]) || StringUtils.isEmpty(certificate[1])) {
            throw new BaseException("数据完整性被破坏。");
        }
        String sm4Key = getTextEncryptor().decrypt(certificate[1]);
        Sm4KeyHolder.setSm4Key(sm4Key);
        
        return Sm4KeyHolder.getSm4Key();
    }
    
    /**
     * @param inputMessage
     * @return
     */
    protected Charset getCharset(HttpInputMessage inputMessage) {
        MediaType mediaType = inputMessage.getHeaders().getContentType();
        Charset charset = mediaType.getCharset();
        if (charset == null) {
            charset = StandardCharsets.UTF_8;
        }
        return charset;
    }
}
