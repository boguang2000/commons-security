package cn.aotcloud.security.tamperproofing;

import org.springframework.util.PathMatcher;
import org.springframework.web.util.UrlPathHelper;

import javax.servlet.http.HttpServletRequest;
import java.util.List;

/**
 * 请求URL匹配处理接口定义
 *
 * @author xkxu
 */
public interface HttpRequestMatcher {

    /**
     * 匹配请求对象，迭代匹配模式，如果匹配成功，返回true，否则返回false。
     *
     * @param patterns  匹配模式
     * @param request   请求对象
     * @return  true 匹配成功，false 匹配失败
     */
    public boolean match(List<String> patterns, HttpServletRequest request);

    /**
     * 匹配请求路径，迭代匹配模式，如果匹配成功，返回true，否则返回false。
     *
     * @param patterns  匹配模式
     * @param path   请求路径
     * @return  true 匹配成功，false 匹配失败
     */
    public boolean match(List<String> patterns, String path);

    /**
     * 匹配请求对象，如果匹配成功，返回true，否则返回false。
     *
     * @param pattern  匹配模式
     * @param request   请求对象
     * @return  true 匹配成功，false 匹配失败
     */
    public boolean match(String pattern, HttpServletRequest request);

    /**
     * 匹配请求路径，如果匹配成功，返回true，否则返回false。
     *
     * @param pattern  匹配模式
     * @param path   请求路径
     * @return  true 匹配成功，false 匹配失败
     */
    public boolean match(String pattern, String path);

    /**
     * @return 获得路径匹配处理器
     */
    public PathMatcher getPathMatcher();

    /**
     * @return  获得URL路径工具类对象
     */
    public UrlPathHelper getUrlPathHelper();
}
