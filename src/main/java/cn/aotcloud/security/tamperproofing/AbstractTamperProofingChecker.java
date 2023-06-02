package cn.aotcloud.security.tamperproofing;

import org.apache.commons.lang3.StringUtils;
import org.springframework.security.crypto.encrypt.TextEncryptor;

import cn.aotcloud.logger.LoggerHandle;
import cn.aotcloud.utils.HttpRequestUtil;

import javax.servlet.http.HttpServletRequest;

/**
 * 防篡改检查器接口的基类实现，具体的实现类应该继承于该基类。
 * <p>
 * 通过消息头 {@value DATA_SIGN_HEAER_NAME} 获得请求数据的消息摘要。
 * <p>
 * 调用 {@link TextEncryptor} 对请求数据的字符串生成消息摘要，与请求头中的消息摘要进行比对。
 *
 * @author xkxu
 */
public abstract class AbstractTamperProofingChecker implements TamperProofingChecker {

    protected LoggerHandle logger = new LoggerHandle(getClass());

    /**
     * 生成消息摘要，需要与客户端消息摘要生成方式保持一致。
     */
    protected final TextEncryptor textEncryptor;

    /**
     * @param textEncryptor
     */
    public AbstractTamperProofingChecker(TextEncryptor textEncryptor) {
        this.textEncryptor = textEncryptor;
    }

    /**
     * 验证请求数据的JSON字符串的消息摘要是否与提交的消息摘要一致。
     *
     * @param str  请求数据的JSON字符串
     * @param sign 请求头中的消息摘要
     */
    protected void doValdiate(HttpServletRequest request, String str, String sign) {
        if (StringUtils.isBlank(sign)) {
            throw new SafeException(request.getRequestURI() + "，消息摘要为空！");
        }
        String encryptedData = textEncryptor.encrypt(str);

//        if (logger.isDebugEnabled()) {
//            logger.debug("请求数据：" + str);
//            logger.debug("请求消息摘要：" + sign);
//            logger.debug("生成的摘要：" + encryptedData);
//        }

        if (!StringUtils.equalsIgnoreCase(encryptedData, sign)) {
            throw new SafeException(request.getRequestURI() + "，防篡改异常：非法参数！");
        }
    }

    /**
     * 默认从请求中获得消息摘要信息。
     *
     * @param request HTTP请求对象
     * @return 消息头中的消息摘要
     */
    protected String getSignValue(HttpServletRequest request) {
    	String sign = HttpRequestUtil.getHeaderValue(request, DATA_SIGN_HEAER_NAME);
    	if (StringUtils.isBlank(sign)) {
    		sign = HttpRequestUtil.getParameterValue(request, DATA_SIGN_HEAER_NAME);
    	}
        return sign;
    }
}
