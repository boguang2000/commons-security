package cn.aotcloud.security.oncetoken;

/**
 * 一次性请求令牌验证接口
 *
 * @author xkxu
 */
public interface RequestTokenValidator {

    /**
     * @param requestToken
     * @return
     */
    public boolean support(RequestToken requestToken);

    /**
     *
     * @param requestToken
     */
    public boolean validate(RequestToken requestToken);
}
