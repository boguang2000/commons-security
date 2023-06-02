package cn.aotcloud.security.oncetoken.support;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import cn.aotcloud.security.oncetoken.RequestToken;
import cn.aotcloud.security.oncetoken.RequestTokenValidator;

/**
 * @author xkxu
 */
public class DelegateRequestTokenValidator implements RequestTokenValidator {

    private List<RequestTokenValidator> requestTokenValidators = new ArrayList<>();

    public DelegateRequestTokenValidator(RequestTokenValidator... requestTokenValidators) {
        this.requestTokenValidators.addAll(Arrays.asList(requestTokenValidators));
    }

    @Override
    public boolean support(RequestToken requestToken) {
        return true;
    }

    @Override
    public boolean validate(RequestToken requestToken) {
        RequestTokenValidator requestTokenValidator = getRequestTokenValidator(requestToken);
        if (requestTokenValidator != null) {
            return requestTokenValidator.validate(requestToken);
        }
        return false;
    }

    protected RequestTokenValidator getRequestTokenValidator(RequestToken requestToken) {
        return requestTokenValidators.stream()
                .filter(requestTokenValidator -> requestTokenValidator.support(requestToken))
                .findFirst().orElse(null);
    }
}
