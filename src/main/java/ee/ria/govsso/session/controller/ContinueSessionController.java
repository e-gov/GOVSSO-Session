package ee.ria.govsso.session.controller;

import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import ee.ria.govsso.session.error.ErrorCode;
import ee.ria.govsso.session.error.exceptions.SsoException;
import ee.ria.govsso.session.logging.StatisticsLogger;
import ee.ria.govsso.session.logging.StatisticsLogger.AuthenticationRequestType;
import ee.ria.govsso.session.service.hydra.HydraService;
import ee.ria.govsso.session.service.hydra.LevelOfAssurance;
import ee.ria.govsso.session.service.hydra.LoginAcceptResponse;
import ee.ria.govsso.session.service.hydra.LoginRequestInfo;
import ee.ria.govsso.session.service.hydra.OidcContext;
import ee.ria.govsso.session.service.hydra.Prompt;
import ee.ria.govsso.session.util.PromptUtil;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Controller;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.servlet.view.RedirectView;
import org.thymeleaf.util.ArrayUtils;

import javax.servlet.http.HttpServletRequest;
import javax.validation.constraints.Pattern;
import java.text.ParseException;
import java.util.Arrays;

import static ee.ria.govsso.session.error.ErrorCode.TECHNICAL_GENERAL;
import static ee.ria.govsso.session.logging.StatisticsLogger.AUTHENTICATION_REQUEST_TYPE;
import static ee.ria.govsso.session.logging.StatisticsLogger.AuthenticationRequestType.CONTINUE_SESSION;
import static ee.ria.govsso.session.logging.StatisticsLogger.LOGIN_REQUEST_INFO;

@Slf4j
@Validated
@Controller
@RequiredArgsConstructor
public class ContinueSessionController {
    public static final String CONTINUE_SESSION_REQUEST_MAPPING = "/login/continuesession";

    private final HydraService hydraService;
    private final StatisticsLogger statisticsLogger;

    @PostMapping(value = CONTINUE_SESSION_REQUEST_MAPPING, produces = MediaType.TEXT_HTML_VALUE)
    public RedirectView continueSession(
            @ModelAttribute("loginChallenge")
            @Pattern(regexp = "^[a-f0-9]{32}$", message = "Incorrect login_challenge format") String loginChallenge,
            HttpServletRequest request) {

        LoginRequestInfo loginRequestInfo = hydraService.fetchLoginRequestInfo(loginChallenge);
        request.setAttribute(LOGIN_REQUEST_INFO, loginRequestInfo);
        request.setAttribute(AUTHENTICATION_REQUEST_TYPE, CONTINUE_SESSION);

        OidcContext oidcContext = loginRequestInfo.getOidcContext();
        if (oidcContext != null && ArrayUtils.isEmpty(oidcContext.getAcrValues())) {
            oidcContext.setAcrValues(new String[]{LevelOfAssurance.HIGH.getAcrName()});
        }

        validateLoginRequestInfo(loginRequestInfo);

        JWT idToken = hydraService.getTaraIdTokenFromConsentContext(loginRequestInfo.getSubject(), loginRequestInfo.getSessionId());
        if (idToken == null) {
            throw new SsoException(ErrorCode.TECHNICAL_GENERAL, "No valid consent requests found");
        }

        validateIdToken(loginRequestInfo, idToken);
        LoginAcceptResponse response = hydraService.acceptLogin(loginChallenge, idToken);
        statisticsLogger.logAccept(loginRequestInfo, idToken, AuthenticationRequestType.CONTINUE_SESSION);
        return new RedirectView(response.getRedirectTo().toString());
    }

    private void validateLoginRequestInfo(LoginRequestInfo loginRequestInfo) {
        OidcContext oidcContext = loginRequestInfo.getOidcContext();
        String[] requestedScopes = loginRequestInfo.getRequestedScope();
        if (loginRequestInfo.getSubject().isEmpty()) {
            throw new SsoException(ErrorCode.USER_INPUT, "Login request subject must not be empty");
        }
        if (!loginRequestInfo.isSkip()) {
            throw new SsoException(TECHNICAL_GENERAL, "Subject exists, therefore login response skip value can not be false");
        }
        if (!Arrays.asList(requestedScopes).contains("openid") || requestedScopes.length != 1) {
            throw new SsoException(ErrorCode.USER_INPUT, "Requested scope must contain openid and nothing else");
        }
        if (oidcContext != null && !ArrayUtils.isEmpty(oidcContext.getAcrValues())) {
            if (oidcContext.getAcrValues().length > 1) {
                throw new SsoException(ErrorCode.USER_INPUT, "acrValues must contain only 1 value");

            } else if (LevelOfAssurance.findByAcrName(oidcContext.getAcrValues()[0]) == null) {
                throw new SsoException(ErrorCode.USER_INPUT, "acrValues must be one of low/substantial/high");
            }
        }

        Prompt prompt = PromptUtil.getAndValidatePromptFromRequestUrl(loginRequestInfo.getRequestUrl());
        if (prompt != Prompt.CONSENT) {
            throw new SsoException(ErrorCode.USER_INPUT, "Request URL must contain prompt=consent");
        }
        if (oidcContext != null && oidcContext.getIdTokenHintClaims() != null) {
            throw new SsoException(ErrorCode.USER_INPUT, "Login request ID token hint claim must be null");
        }
    }

    private void validateIdToken(LoginRequestInfo loginRequestInfo, JWT idToken) {
        try {
            JWTClaimsSet claimsSet = idToken.getJWTClaimsSet();
            String acrValue = loginRequestInfo.getOidcContext().getAcrValues()[0];
            if (!isIdTokenAcrHigherOrEqualToLoginRequestAcr(claimsSet.getStringClaim("acr"), acrValue)) {
                throw new SsoException(ErrorCode.TECHNICAL_GENERAL, "ID Token acr value must be equal to or higher than hydra login request acr");
            }
        } catch (ParseException ex) {
            throw new SsoException(ErrorCode.TECHNICAL_GENERAL, "Failed to parse claim set from Id token");
        }
    }

    private boolean isIdTokenAcrHigherOrEqualToLoginRequestAcr(String idTokenAcr, String loginRequestInfoAcr) {
        return LevelOfAssurance.findByAcrName(idTokenAcr).getAcrLevel() >= LevelOfAssurance.findByAcrName(loginRequestInfoAcr).getAcrLevel();
    }
}
