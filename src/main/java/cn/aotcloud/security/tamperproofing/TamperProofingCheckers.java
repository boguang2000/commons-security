package cn.aotcloud.security.tamperproofing;


import javax.servlet.http.HttpServletRequest;
import java.util.List;
import java.util.Optional;

/**
 * 防篡改检查器代理类，持有多个防篡改检查器实现。
 *
 * @author xkxu
 */
public class TamperProofingCheckers {

    /**
     * 支持的所有检查实现
     */
    private List<TamperProofingChecker> tamperProofingCheckers;

    public TamperProofingCheckers(List<TamperProofingChecker> tamperProofingCheckers) {
        this.tamperProofingCheckers = tamperProofingCheckers;
    }

    public boolean support(HttpServletRequest request) {
        return getTamperProofingChecker(request).isPresent();
    }

    /**
     * 尝试获得防篡改检查器对象。
     *
     * @param request   HTTP请求对象。
     * @return  支持的防篡改检查器对象，可能为空。
     */
    protected Optional<TamperProofingChecker> getTamperProofingChecker(HttpServletRequest request) {
        return tamperProofingCheckers.stream()
                .filter(tamperProofingChecker -> tamperProofingChecker.support(request))
                .findFirst();
    }

    public void check(HttpServletRequest request) throws SafeException {
        getTamperProofingChecker(request).get().check(request);
    };
}
