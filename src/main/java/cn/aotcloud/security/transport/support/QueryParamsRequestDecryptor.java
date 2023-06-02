package cn.aotcloud.security.transport.support;

import cn.aotcloud.security.transport.AbstractRequestDecryptor;
import cn.aotcloud.security.transport.CryptoHttpInputMessage;
import cn.aotcloud.security.transport.HttpCryptoSm2Certificate;
import cn.aotcloud.utils.HttpServletUtil;

import org.apache.commons.lang3.StringUtils;
import org.springframework.http.HttpInputMessage;
import org.springframework.http.server.ServletServerHttpRequest;

import java.io.IOException;

/**
 * 对请求参数解密，如果请求参数中存在属性名称 {@value CRYPTO_PARAM_DATA}，该参数的值就是加密的参数。
 *
 * 下面的请求演示了，查询参数的加密格式：
 * <code>
 *     http://localhost:8080/users/query?x_acloud_query_param_crypto_data=crypto(username=dd&orgId=dd)
 * </code>
 * 其中 crypto(username=dd&orgId=dd) 就是对查询参数进行加密，这里是对所有的查询参数进行加密。
 *
 * @author xkxu
 */
public class QueryParamsRequestDecryptor extends AbstractRequestDecryptor {

    /**
     * 加密的请求参数名称
     */
    public static final String CRYPTO_PARAM_DATA = "x_ac_query_param_crypto_data";

    /**
     * @param sm2Key
     */
    public QueryParamsRequestDecryptor(HttpCryptoSm2Certificate sm2Key) {
        super(sm2Key);
    }

    @Override
    public boolean support(HttpInputMessage inputMessage) {
        if (inputMessage instanceof ServletServerHttpRequest) {
            ServletServerHttpRequest httpRequest = (ServletServerHttpRequest) inputMessage;
            return StringUtils.isNotBlank(HttpServletUtil.getParameter(httpRequest.getServletRequest(), CRYPTO_PARAM_DATA));
        }
        return false;
    }

    @Override
    public CryptoHttpInputMessage doDecrypt(HttpInputMessage inputMessage) throws IOException {
        CryptoHttpInputMessage cryptoHttpInputMessage = new CryptoHttpInputMessage();
        ServletServerHttpRequest httpRequest = (ServletServerHttpRequest) inputMessage;
        String cryptoData = HttpServletUtil.getParameter(httpRequest.getServletRequest(), CRYPTO_PARAM_DATA);
        if (StringUtils.isNotBlank(cryptoData)) {
            String decryptedData = decryptData(cryptoData);
            cryptoHttpInputMessage.setQueryString(decryptedData);
        } else {
            logger.warn("加密的查询参数为空。");
        }
        return cryptoHttpInputMessage;
    }
}
