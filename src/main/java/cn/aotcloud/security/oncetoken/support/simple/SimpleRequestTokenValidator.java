package cn.aotcloud.security.oncetoken.support.simple;

import cn.aotcloud.crypto.pcode.PcodeEncoder;
import cn.aotcloud.logger.LoggerHandle;
import cn.aotcloud.security.oncetoken.OnceProtocol;
import cn.aotcloud.security.oncetoken.RequestToken;
import cn.aotcloud.security.oncetoken.RequestTokenStore;
import cn.aotcloud.security.oncetoken.RequestTokenValidator;

import org.apache.commons.lang3.StringUtils;

/**
 * @author xkxu
 */
public class SimpleRequestTokenValidator implements RequestTokenValidator {

    protected LoggerHandle logger = new LoggerHandle(getClass());

    protected final RequestTokenStore requestTokenStore;

    protected final PcodeEncoder pscodeEncoder;

    protected final long timeinterval;
    
    protected final String requestTokenSalt;
    
    // this.safeProperties.getRequestToken().getTimeintervalSeconds() * 1000
    public SimpleRequestTokenValidator(RequestTokenStore requestTokenStore,
                                       PcodeEncoder pscodeEncoder,
                                       long timeinterval,
                                       String requestTokenSalt) {
        this.requestTokenStore = requestTokenStore;
        this.pscodeEncoder = pscodeEncoder;
        this.timeinterval = timeinterval;
        this.requestTokenSalt = requestTokenSalt;
    }

    @Override
    public boolean support(RequestToken requestToken) {
        return requestToken != null && (StringUtils.isBlank(requestToken.getProtocol())
                || StringUtils.equalsIgnoreCase(requestToken.getProtocol(), OnceProtocol.simple.name()));
    }

    @Override
    public boolean validate(RequestToken requestToken) {
        if (requestToken != null &&
                isValidTimestamp(requestToken.getCreateTime())
                && isValidNonce(requestToken.getToken())
                && isValidSign(requestToken)) {
            return true;
        }
        return false;
    }

    /**
     * 时间戳是否合法
     * <p>
     * 请求的时间戳和当前时间的差，不超过60秒
     * </p>
     *
     * @author WangXianbing
     * @param timestamp
     *            the number of milliseconds since January 1, 1970, 00:00:00 GMT
     *            represented by this date
     * @return
     */
    protected boolean isValidTimestamp(Long timestamp) {
        boolean flag = timestamp != null && Math.abs(System.currentTimeMillis() - timestamp) <= timeinterval;
        if (!flag) {
            logger.error("请求令牌时间戳不合法。");
        }
        return flag;
    }

    /**
     * 随机数是否合法
     * <p>
     * 随机数是一次使用，使用过的会在缓存中暂存一段时间
     * </p>
     *
     * @author WangXianbing
     * @param nonce
     * @return
     */
    protected boolean isValidNonce(String nonce) {
        RequestToken requestTokenFromDb = requestTokenStore.getToken(nonce);
        boolean flag = StringUtils.isNotBlank(nonce)
                && (requestTokenFromDb == null || requestTokenFromDb.isExpired());
        if (!flag) {
            logger.error("请求令牌随机数不合法。");
        }
        return flag;
    }

    /**
     * 签名摘要是否合法
     * <p>
     * 随机数和时间错是否被篡改，默认算法为MD5，可配置国密SM3
     * </p>
     *
     * @author WangXianbing
     * @param requestTokenFromRequest
     * @return
     */
    protected boolean isValidSign(RequestToken requestTokenFromRequest) {
        boolean flag = pscodeEncoder.matches(
                getRequestTokenAsStr(requestTokenFromRequest), requestTokenFromRequest.getSign());
        if (!flag) {
            logger.error("请求令牌签名摘要不合法。");
        }
        return flag;
    }

    protected String getRequestTokenAsStr(RequestToken requestTokenFromRequest) {
        return String.join(",",
                requestTokenFromRequest.getCreateTime().toString(),
                requestTokenFromRequest.getToken());
    }
}
