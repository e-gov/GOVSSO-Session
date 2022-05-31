package ee.ria.govsso.session.filter;

import co.elastic.apm.api.ElasticApm;
import ee.ria.govsso.session.error.ErrorCode;
import ee.ria.govsso.session.error.exceptions.SsoException;
import ee.ria.govsso.session.session.SsoCookie;
import ee.ria.govsso.session.session.SsoCookieSigner;
import ee.ria.govsso.session.util.CookieUtil;
import lombok.RequiredArgsConstructor;
import org.apache.commons.lang3.RandomStringUtils;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.MDC;
import org.springframework.boot.info.BuildProperties;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Set;

import static ee.ria.govsso.session.controller.AuthCallbackController.CALLBACK_REQUEST_MAPPING;
import static ee.ria.govsso.session.controller.ConsentInitController.CONSENT_INIT_REQUEST_MAPPING;
import static ee.ria.govsso.session.controller.ContinueSessionController.CONTINUE_SESSION_REQUEST_MAPPING;
import static ee.ria.govsso.session.controller.LoginReauthenticateController.LOGIN_REAUTHENTICATE_REQUEST_MAPPING;
import static ee.ria.govsso.session.controller.LoginRejectController.LOGIN_REJECT_REQUEST_MAPPING;
import static ee.ria.govsso.session.controller.LogoutController.LOGOUT_CONTINUE_SESSION_REQUEST_MAPPING;
import static ee.ria.govsso.session.controller.LogoutController.LOGOUT_END_SESSION_REQUEST_MAPPING;
import static ee.ria.govsso.session.controller.LogoutController.LOGOUT_INIT_REQUEST_MAPPING;
import static ee.ria.govsso.session.session.SsoCookie.COOKIE_NAME_GOVSSO;

@RequiredArgsConstructor
public class RequestCorrelationFilter extends OncePerRequestFilter {
    public static final String MDC_ATTRIBUTE_NAME_VERSION = "service.version";
    public static final String MDC_ATTRIBUTE_CLIENT_IP = "client.ip";
    public static final String MDC_ATTRIBUTE_TRACE_ID = "trace.id";
    public static final String MDC_ATTRIBUTE_GOVSSO_TRACE_ID = "govsso_trace_id";
    public static final String MDC_ATTRIBUTE_GOVSSO_SESSION_ID = "govsso_session_id";
    public static final String REQUEST_ATTRIBUTE_NAME_REQUEST_ID = "requestId";

    public static final Set<String> VERIFIED_GOVSSO_COOKIE_EXPECTING_ENDPOINTS = Set.of(
            CALLBACK_REQUEST_MAPPING,
            CONSENT_INIT_REQUEST_MAPPING,
            CONTINUE_SESSION_REQUEST_MAPPING,
            LOGIN_REAUTHENTICATE_REQUEST_MAPPING,
            LOGIN_REJECT_REQUEST_MAPPING,
            LOGOUT_INIT_REQUEST_MAPPING,
            LOGOUT_END_SESSION_REQUEST_MAPPING,
            LOGOUT_CONTINUE_SESSION_REQUEST_MAPPING);
    public static final String REQUEST_ATTRIBUTE_VERIFIED_SSO_COOKIE = "VERIFIED_SSO_COOKIE";
    private final BuildProperties buildProperties;
    private final SsoCookieSigner ssoCookieSigner;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {

        if (buildProperties != null) {
            MDC.put(MDC_ATTRIBUTE_NAME_VERSION, buildProperties.getVersion());
        }

        String ipAddress = request.getRemoteAddr();
        if (StringUtils.isNotEmpty(ipAddress)) {
            MDC.put(MDC_ATTRIBUTE_CLIENT_IP, ipAddress);
        }

        String traceId = MDC.get(MDC_ATTRIBUTE_TRACE_ID);
        if (StringUtils.isEmpty(traceId)) {
            MDC.put(MDC_ATTRIBUTE_TRACE_ID, RandomStringUtils.random(32, "0123456789abcdef").toLowerCase());
        }

        // NB! Set traceId also as HttpServletRequest attribute to make it accessible for Tomcat's AccessLogValve
        request.setAttribute(REQUEST_ATTRIBUTE_NAME_REQUEST_ID, traceId);

        if (VERIFIED_GOVSSO_COOKIE_EXPECTING_ENDPOINTS.contains(request.getRequestURI())) {
            Cookie sessionCookie = CookieUtil.getCookie(request, COOKIE_NAME_GOVSSO);
            if (sessionCookie == null) {
                throw new SsoException(ErrorCode.USER_COOKIE_MISSING, "Missing or expired cookie"); // TODO: Wrong status 500 in error controller! response.sendError?
            }
            SsoCookie ssoCookie = ssoCookieSigner.getVerifiedSsoCookie(sessionCookie.getValue()); // TODO: Wrong status 500 in error controller! response.sendError?
            request.setAttribute(REQUEST_ATTRIBUTE_VERIFIED_SSO_COOKIE, ssoCookie);
            MDC.put(MDC_ATTRIBUTE_GOVSSO_SESSION_ID, ssoCookie.getSessionId());
            MDC.put(MDC_ATTRIBUTE_GOVSSO_TRACE_ID, ssoCookie.getLoginChallenge());
            ElasticApm.currentTransaction().setLabel(MDC_ATTRIBUTE_GOVSSO_SESSION_ID, ssoCookie.getSessionId());
            ElasticApm.currentTransaction().setLabel(MDC_ATTRIBUTE_GOVSSO_TRACE_ID, ssoCookie.getLoginChallenge());
        }

        filterChain.doFilter(request, response);
    }
}
