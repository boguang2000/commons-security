package cn.aotcloud.security.tamperproofing;



import javax.servlet.http.HttpServletRequest;

/**
 * 防篡改检查器接口定义。每个接口实现只实现一种请求数据的检查。
 *
 * 通过调用接口 {@link #support(HttpServletRequest)} 检查是否支持请求数据的检查，
 *
 * 如果返回true，在调用方法 {@link #check(HttpServletRequest)} 检查请求数据。
 *
 * 通过将请求数据序列化成有规律的字符串，然后对字符串生成消息摘要，与请求头中的消息再要进行比对。
 *
 * 如果消息摘要不一致，则请求数据被篡改，抛出异常 {@link cn.aotcloud.security.tamperproofing.SafeException}。
 *
 * 统一采用UTF-8字符编码。
 *
 * @author xkxu
 */
public interface TamperProofingChecker {

    /**
     * 请求数据消息摘要的消息头名称
     */
    public static final String DATA_SIGN_HEAER_NAME = "X-Ac-Data-Sign";

    /**
     * 检查是否需要支持请求数据。
     *
     * @param request   HTTP请求对象
     * @return  true支持检查，false不支持检查
     */
    public boolean support(HttpServletRequest request);

    /**
     * 当方法 {@link #support(HttpServletRequest)} 调用返回true，则需要执行该方法。
     *
     * 对请求数据进行防篡改检查。
     *
     * @param request   HTTP请求对象
     * @throws cn.aotcloud.security.tamperproofing.SafeException    检查失败抛出异常。
     */
    public void check(HttpServletRequest request) throws SafeException;
}
