package ee.ria.govsso.session.controller;

import co.elastic.apm.api.ElasticApm;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import ee.ria.govsso.session.error.ErrorCode;
import ee.ria.govsso.session.error.exceptions.SsoException;
import ee.ria.govsso.session.logging.StatisticsLogger;
import ee.ria.govsso.session.service.alerts.AlertsService;
import ee.ria.govsso.session.service.hydra.HydraService;
import ee.ria.govsso.session.service.hydra.LevelOfAssurance;
import ee.ria.govsso.session.service.hydra.LoginAcceptResponse;
import ee.ria.govsso.session.service.hydra.LoginRequestInfo;
import ee.ria.govsso.session.service.hydra.OidcContext;
import ee.ria.govsso.session.service.hydra.Prompt;
import ee.ria.govsso.session.service.tara.TaraService;
import ee.ria.govsso.session.session.SsoCookie;
import ee.ria.govsso.session.session.SsoCookieSigner;
import ee.ria.govsso.session.util.CookieUtil;
import ee.ria.govsso.session.util.LocaleUtil;
import ee.ria.govsso.session.util.PromptUtil;
import lombok.RequiredArgsConstructor;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.codec.digest.DigestUtils;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.MDC;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Controller;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.CookieValue;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.ModelAndView;
import org.thymeleaf.util.ArrayUtils;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.validation.constraints.Pattern;
import java.text.ParseException;
import java.time.Instant;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

import static ee.ria.govsso.session.error.ErrorCode.TECHNICAL_GENERAL;
import static ee.ria.govsso.session.filter.RequestCorrelationFilter.MDC_ATTRIBUTE_GOVSSO_SESSION_ID;
import static ee.ria.govsso.session.filter.RequestCorrelationFilter.MDC_ATTRIBUTE_GOVSSO_TRACE_ID;
import static ee.ria.govsso.session.logging.StatisticsLogger.AUTHENTICATION_REQUEST_TYPE;
import static ee.ria.govsso.session.logging.StatisticsLogger.AuthenticationRequestType.UPDATE_SESSION;
import static ee.ria.govsso.session.logging.StatisticsLogger.LOGIN_REQUEST_INFO;
import static ee.ria.govsso.session.session.SsoCookie.COOKIE_NAME_GOVSSO;

@Slf4j
@Validated
@Controller
@RequiredArgsConstructor
public class LoginInitController {

    public static final String LOGIN_INIT_REQUEST_MAPPING = "/login/init";
    public static final String REQUEST_PARAM_LOGIN_CHALLENGE = "login_challenge";

    private final SsoCookieSigner ssoCookieSigner;
    private final HydraService hydraService;
    private final TaraService taraService;
    private final StatisticsLogger statisticsLogger;
    @Autowired(required = false)
    private AlertsService alertsService;

    @GetMapping(value = LOGIN_INIT_REQUEST_MAPPING, produces = MediaType.TEXT_HTML_VALUE)
    public ModelAndView loginInit(
            @RequestParam(name = REQUEST_PARAM_LOGIN_CHALLENGE)
            @Pattern(regexp = "^[a-f0-9]{32}$", message = "Incorrect login_challenge format") String loginChallenge,
            @RequestParam(name = "lang", required = false) String language,
            @CookieValue(value = "__Host-LOCALE", required = false) String localeCookie,
            HttpServletRequest request,
            HttpServletResponse response) {

        Cookie cookie = CookieUtil.getCookie(request, COOKIE_NAME_GOVSSO);
        SsoCookie ssoCookie = ssoCookieSigner.getVerifiedSsoCookieOrNull(cookie);
        setTraceContexts(loginChallenge, ssoCookie);

        LoginRequestInfo loginRequestInfo = hydraService.fetchLoginRequestInfo(loginChallenge);
        request.setAttribute(LOGIN_REQUEST_INFO, loginRequestInfo);

        // Set locale as early as possible, so it could be used by error messages as much as possible.
        if (language == null && localeCookie == null) {
            LocaleUtil.setLocale(loginRequestInfo);
        }

        validateLoginRequestInfo(loginRequestInfo);

        OidcContext oidcContext = loginRequestInfo.getOidcContext();
        if (oidcContext != null && ArrayUtils.isEmpty(oidcContext.getAcrValues())) {
            oidcContext.setAcrValues(new String[]{LevelOfAssurance.HIGH.getAcrName()});
        }

        Prompt prompt = PromptUtil.getAndValidatePromptFromRequestUrl(loginRequestInfo.getRequestUrl());
        if (prompt == Prompt.NONE) {
            request.setAttribute(AUTHENTICATION_REQUEST_TYPE, UPDATE_SESSION);
            return updateSession(loginRequestInfo, ssoCookie, response);
        }

        validateLoginRequestInfoForAuthenticationAndContinuation(loginRequestInfo, prompt);
        if (StringUtils.isEmpty(loginRequestInfo.getSubject())) {
            return authenticateWithTara(loginRequestInfo, response);
        } else {
            JWT idToken = hydraService.getTaraIdTokenFromConsentContext(loginRequestInfo.getSubject(), loginRequestInfo.getSessionId());
            if (idToken == null) {
                return reauthenticate(loginRequestInfo, request, response);
            } else {
                return sessionContinuationView(loginRequestInfo, idToken);
            }
        }
    }

    private void setTraceContexts(String loginChallenge, SsoCookie ssoCookie) {
        if (ssoCookie != null) {
            MDC.put(MDC_ATTRIBUTE_GOVSSO_SESSION_ID, ssoCookie.getSessionId());
            ElasticApm.currentTransaction().setLabel(MDC_ATTRIBUTE_GOVSSO_SESSION_ID, ssoCookie.getSessionId());
        } else {
            String sessionId = DigestUtils.sha256Hex(loginChallenge);
            MDC.put(MDC_ATTRIBUTE_GOVSSO_SESSION_ID, sessionId);
            ElasticApm.currentTransaction().setLabel(MDC_ATTRIBUTE_GOVSSO_SESSION_ID, sessionId);
        }
        MDC.put(MDC_ATTRIBUTE_GOVSSO_TRACE_ID, loginChallenge);
        ElasticApm.currentTransaction().setLabel(MDC_ATTRIBUTE_GOVSSO_TRACE_ID, loginChallenge);
    }

    private void validateLoginRequestInfo(LoginRequestInfo loginRequestInfo) {
        OidcContext oidcContext = loginRequestInfo.getOidcContext();
        String[] requestedScopes = loginRequestInfo.getRequestedScope();

        if (StringUtils.isEmpty(loginRequestInfo.getSubject())) {
            if (loginRequestInfo.isSkip()) {
                throw new SsoException(TECHNICAL_GENERAL, "Subject is null, therefore login response skip value can not be true");
            }
        } else {
            if (!loginRequestInfo.isSkip()) {
                throw new SsoException(TECHNICAL_GENERAL, "Subject exists, therefore login response skip value can not be false");
            }
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
    }

    private ModelAndView updateSession(LoginRequestInfo loginRequestInfo, SsoCookie ssoCookie, HttpServletResponse response) {
        validateLoginRequestInfoAgainstToken(loginRequestInfo);
        JWT idToken = hydraService.getTaraIdTokenFromConsentContext(loginRequestInfo.getSubject(), loginRequestInfo.getSessionId());
        if (idToken == null) {
            throw new SsoException(ErrorCode.TECHNICAL_GENERAL, "No valid consent requests found");
        }

        validateIdToken(loginRequestInfo, idToken);
        LoginAcceptResponse loginAcceptResponse = hydraService.acceptLogin(loginRequestInfo.getChallenge(), idToken);
        statisticsLogger.logAccept(loginRequestInfo, idToken, UPDATE_SESSION);

        if (ssoCookie == null) {
            throw new SsoException(ErrorCode.USER_COOKIE_MISSING, "Missing or expired cookie");
        }
        SsoCookie updatedSsoCookie = ssoCookie.withLoginChallenge(loginRequestInfo.getChallenge());
        response.addHeader(HttpHeaders.SET_COOKIE, ssoCookieSigner.getSignedCookieValue(updatedSsoCookie));
        return new ModelAndView("redirect:" + loginAcceptResponse.getRedirectTo());
    }

    private void validateLoginRequestInfoAgainstToken(LoginRequestInfo loginRequestInfo) {
        if (StringUtils.isEmpty(loginRequestInfo.getSubject())) {
            throw new SsoException(ErrorCode.USER_INPUT, "Subject cannot be empty for session update");
        }
        if (loginRequestInfo.getOidcContext() == null) {
            throw new SsoException(ErrorCode.USER_INPUT, "Oidc context cannot be empty for session update");
        }

        Map<String, Object> idTokenHintClaims = loginRequestInfo.getOidcContext().getIdTokenHintClaims();
        if (idTokenHintClaims == null || idTokenHintClaims.isEmpty()) {
            throw new SsoException(ErrorCode.USER_INPUT, "Id token cannot be empty for session update");
        }

        @SuppressWarnings("unchecked")
        List<String> audiences = (List<String>) idTokenHintClaims.get("aud");
        if (!audiences.contains(loginRequestInfo.getClient().getClientId())) {
            throw new SsoException(ErrorCode.USER_INPUT, "Id token audiences must contain request client id");
        }
        if (!idTokenHintClaims.get("sid").equals(loginRequestInfo.getSessionId())) {
            throw new SsoException(ErrorCode.USER_INPUT, "Id token session id must equal request session id"); // TODO: Re-Authenticate?
        }

        Integer tokenExpirationDateInSeconds = (Integer) idTokenHintClaims.get("exp");
        Instant tokenExpirationTime = Instant.ofEpochSecond(tokenExpirationDateInSeconds);
        if (Instant.now().isAfter(tokenExpirationTime)) {
            throw new SsoException(ErrorCode.USER_INPUT, "Id token must not be expired");
        }
    }

    private void validateLoginRequestInfoForAuthenticationAndContinuation(LoginRequestInfo loginRequestInfo, Prompt prompt) {
        OidcContext oidcContext = loginRequestInfo.getOidcContext();
        if (oidcContext != null && oidcContext.getIdTokenHintClaims() != null) {
            throw new SsoException(ErrorCode.USER_INPUT, "id_token_hint_claims must be null");
        }

        if (prompt != Prompt.CONSENT) {
            throw new SsoException(ErrorCode.USER_INPUT, "Request URL must contain prompt=consent");
        }
    }

    private ModelAndView authenticateWithTara(LoginRequestInfo loginRequestInfo, HttpServletResponse response) {
        String acrValue = loginRequestInfo.getOidcContext().getAcrValues()[0];
        String loginChallenge = loginRequestInfo.getChallenge();
        AuthenticationRequest authenticationRequest = taraService.createAuthenticationRequest(acrValue, loginChallenge);

        String sessionId = DigestUtils.sha256Hex(loginChallenge);
        SsoCookie ssoCookie = SsoCookie.builder()
                .sessionId(sessionId)
                .loginChallenge(loginChallenge)
                .taraAuthenticationRequestState(authenticationRequest.getState().getValue())
                .taraAuthenticationRequestNonce(authenticationRequest.getNonce().getValue())
                .build();

        response.addHeader(HttpHeaders.SET_COOKIE, ssoCookieSigner.getSignedCookieValue(ssoCookie));
        return new ModelAndView("redirect:" + authenticationRequest.toURI().toString());
    }

    @SneakyThrows
    private ModelAndView sessionContinuationView(LoginRequestInfo loginRequestInfo, JWT idToken) {
        if (!isIdTokenAcrHigherOrEqualToLoginRequestAcr(loginRequestInfo, idToken)) {
            ModelAndView model = new ModelAndView("acrView");
            model.addObject("clientName", LocaleUtil.getTranslatedClientName(loginRequestInfo.getClient()));
            model.addObject("loginChallenge", loginRequestInfo.getChallenge());
            model.addObject("logo", loginRequestInfo.getClient().getMetadata().getOidcClient().getLogo());
            if (alertsService != null) {
                model.addObject("alerts", alertsService.getStaticAndActiveAlerts());
                model.addObject("hasStaticAlert", alertsService.hasStaticAlert());
            }
            return model;
        }

        ModelAndView model = new ModelAndView("authView");
        JWTClaimsSet claimsSet = idToken.getJWTClaimsSet();
        if (claimsSet.getClaims().get("profile_attributes") instanceof Map profileAttributes) {
            model.addObject("givenName", profileAttributes.get("given_name"));
            model.addObject("familyName", profileAttributes.get("family_name"));
            if (profileAttributes.get("date_of_birth") != null)
                model.addObject("dateOfBirth", LocaleUtil.formatDateWithLocale((String) profileAttributes.get("date_of_birth")));
            model.addObject("subject", loginRequestInfo.getSubject());
            model.addObject("clientName", LocaleUtil.getTranslatedClientName(loginRequestInfo.getClient()));
            model.addObject("loginChallenge", loginRequestInfo.getChallenge());
            model.addObject("logo", loginRequestInfo.getClient().getMetadata().getOidcClient().getLogo());
            if (alertsService != null) {
                model.addObject("alerts", alertsService.getStaticAndActiveAlerts());
                model.addObject("hasStaticAlert", alertsService.hasStaticAlert());
            }
        }
        return model;
    }

    private ModelAndView reauthenticate(LoginRequestInfo loginRequestInfo, HttpServletRequest request, HttpServletResponse response) {
        hydraService.deleteConsentBySubjectSession(loginRequestInfo.getSubject(), loginRequestInfo.getSessionId());
        hydraService.deleteLoginSessionAndRelatedLoginRequests(loginRequestInfo.getSessionId());
        CookieUtil.deleteHydraSessionCookie(request, response);
        return new ModelAndView("redirect:" + loginRequestInfo.getRequestUrl());
    }

    private void validateIdToken(LoginRequestInfo loginRequestInfo, JWT idToken) {
        if (!isIdTokenAcrHigherOrEqualToLoginRequestAcr(loginRequestInfo, idToken)) {
            throw new SsoException(ErrorCode.TECHNICAL_GENERAL, "ID Token acr value must be equal to or higher than hydra login request acr");
        }
    }

    private boolean isIdTokenAcrHigherOrEqualToLoginRequestAcr(LoginRequestInfo loginRequestInfo, JWT idToken) {
        String loginRequestInfoAcr = loginRequestInfo.getOidcContext().getAcrValues()[0];
        String idTokenAcr;

        try {
            idTokenAcr = idToken.getJWTClaimsSet().getStringClaim("acr");
        } catch (ParseException ex) {
            throw new SsoException(ErrorCode.TECHNICAL_GENERAL, "Failed to parse claim set from Id token");
        }

        return LevelOfAssurance.findByAcrName(idTokenAcr).getAcrLevel()
                >= LevelOfAssurance.findByAcrName(loginRequestInfoAcr).getAcrLevel();
    }
}
