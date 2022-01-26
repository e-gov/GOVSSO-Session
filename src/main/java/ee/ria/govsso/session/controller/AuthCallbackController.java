package ee.ria.govsso.session.controller;

import com.nimbusds.jwt.SignedJWT;
import ee.ria.govsso.session.error.ErrorCode;
import ee.ria.govsso.session.error.exceptions.SsoException;
import ee.ria.govsso.session.service.hydra.HydraService;
import ee.ria.govsso.session.service.hydra.LoginRequestInfo;
import ee.ria.govsso.session.service.tara.TaraService;
import ee.ria.govsso.session.session.SsoCookie;
import ee.ria.govsso.session.session.SsoCookieValue;
import lombok.RequiredArgsConstructor;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Controller;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.view.RedirectView;
import org.thymeleaf.util.ArrayUtils;

import javax.validation.constraints.Pattern;
import java.util.Map;

@Slf4j
@Validated
@Controller
@RequiredArgsConstructor
public class AuthCallbackController {

    public static final String CALLBACK_REQUEST_MAPPING = "/login/taracallback";
    private final TaraService taraService;
    private final HydraService hydraService;

    @GetMapping(value = CALLBACK_REQUEST_MAPPING, produces = MediaType.TEXT_HTML_VALUE)
    public RedirectView loginCallback(
            @RequestParam(name = "code") @Pattern(regexp = "^[A-Za-z0-9\\-_.]{6,87}$") String code,
            @RequestParam(name = "state") @Pattern(regexp = "^[A-Za-z0-9\\-_]{43}$") String state,
            @SsoCookieValue SsoCookie ssoCookie) {

        validateLoginRequestInfo(state, ssoCookie);
        LoginRequestInfo loginRequestInfo = hydraService.fetchLoginRequestInfo(ssoCookie.getLoginChallenge());

        SignedJWT idToken = taraService.requestIdToken(code);
        verifyAcr(idToken, loginRequestInfo);
        taraService.verifyIdToken(ssoCookie.getTaraAuthenticationRequestNonce(), idToken);
        String redirectUrl = hydraService.acceptLogin(ssoCookie.getLoginChallenge(), idToken);
        return new RedirectView(redirectUrl);
    }

    @SneakyThrows
    private void verifyAcr(SignedJWT idToken, LoginRequestInfo loginRequestInfo) {
        String idTokenAcr = idToken.getJWTClaimsSet().getStringClaim("acr");
        String loginRequestAcr = "high";

        if (loginRequestInfo.getOidcContext() != null
                && !ArrayUtils.isEmpty(loginRequestInfo.getOidcContext().getAcrValues())
                && !loginRequestInfo.getOidcContext().getAcrValues()[0].isEmpty()) {
            loginRequestAcr = loginRequestInfo.getOidcContext().getAcrValues()[0];
        }

        Map<String, Integer> acrMap = Map.of("low", 1, "substantial", 2, "high", 3);
        if (acrMap.get(idTokenAcr) < acrMap.get(loginRequestAcr)) {
            throw new SsoException(ErrorCode.USER_INPUT, "ID Token acr value must be equal to or higher than hydra login request acr");
        }
    }

    private void validateLoginRequestInfo(String state, SsoCookie ssoCookie) {
        if (ssoCookie.getTaraAuthenticationRequestState() == null || ssoCookie.getTaraAuthenticationRequestState().isBlank()) {
            throw new SsoException(ErrorCode.USER_INPUT, "Session tara authentication request state must not be null");
        }
        if (!ssoCookie.getTaraAuthenticationRequestState().equals(state)) {
            throw new SsoException(ErrorCode.USER_INPUT, "Invalid TARA callback state");
        }
        if (ssoCookie.getTaraAuthenticationRequestNonce() == null || ssoCookie.getTaraAuthenticationRequestNonce().isBlank()) {
            throw new SsoException(ErrorCode.USER_INPUT, "Session tara authentication request nonce must not be null");
        }
    }
}
