package ee.ria.govsso.session.logging;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.nimbusds.jwt.JWT;
import ee.ria.govsso.session.error.ErrorCode;
import ee.ria.govsso.session.service.hydra.LoginRequestInfo;
import lombok.Builder;
import lombok.Data;
import lombok.NonNull;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;
import org.thymeleaf.util.ArrayUtils;

import java.time.Instant;
import java.util.Date;
import java.util.Map;

import static ee.ria.govsso.session.logging.StatisticsLogger.AuthenticationState.AUTHENTICATION_CANCELED;
import static ee.ria.govsso.session.logging.StatisticsLogger.AuthenticationState.AUTHENTICATION_FAILED;
import static ee.ria.govsso.session.logging.StatisticsLogger.AuthenticationState.AUTHENTICATION_SUCCESS;
import static java.util.Arrays.stream;
import static net.logstash.logback.marker.Markers.appendFields;

@Slf4j
@Component
public class StatisticsLogger {
    public static final String LOGIN_REQUEST_INFO = "LOGIN_REQUEST_INFO";
    public static final String AUTHENTICATION_REQUEST_TYPE = "AUTHENTICATION_REQUEST_TYPE";
    private final Map<String, String> authenticationTypes = Map.of(
            "smartid", "SMART_ID",
            "mID", "MOBILE_ID",
            "idcard", "ID_CARD",
            "eidas", "EIDAS");

    @SneakyThrows
    public void logAccept(@NonNull LoginRequestInfo loginRequestInfo, @NonNull JWT taraIdToken, @NonNull AuthenticationRequestType requestType) {
        var client = loginRequestInfo.getClient();
        var institution = client.getMetadata().getOidcClient().getInstitution();
        var claims = taraIdToken.getJWTClaimsSet();
        var subject = claims.getSubject();
        var country = subject.substring(0, 2);
        var idCode = subject.substring(2);
        var sid = loginRequestInfo.getSessionId();
        var iat = claims.getIssueTime();
        var sessionTime = Instant.now().getEpochSecond() - iat.toInstant().getEpochSecond();
        var oidcContext = loginRequestInfo.getOidcContext();
        var acrValues = oidcContext != null ? oidcContext.getAcrValues() : null;
        var grantedAcr = claims.getStringClaim("acr").toUpperCase();
        var amr = stream(claims.getStringArrayClaim("amr"))
                .filter(authenticationTypes::containsKey)
                .map(authenticationTypes::get)
                .findFirst();

        SessionStatistics sessionStatistics = SessionStatistics.builder()
                .clientId(client.getClientId())
                .registryCode(institution.getRegistryCode())
                .sector(institution.getSector())
                .sessionId(sid)
                .sessionStartTime(iat)
                .sessionDuration(sessionTime)
                .country(country)
                .idCode(idCode)
                .authenticationRequestType(requestType)
                .authenticationState(AUTHENTICATION_SUCCESS)
                .grantedAcr(grantedAcr)
                .build();
        amr.ifPresent(sessionStatistics::setAuthenticationType);
        if (acrValues != null && !ArrayUtils.isEmpty(acrValues)) {
            sessionStatistics.setRequestedAcr(acrValues[0]);
        }

        log.info(appendFields(sessionStatistics), "Statistics");
    }

    public void logReject(@NonNull LoginRequestInfo loginRequestInfo, AuthenticationRequestType requestType) {
        var client = loginRequestInfo.getClient();
        var institution = client.getMetadata().getOidcClient().getInstitution();
        var sid = loginRequestInfo.getSessionId();

        SessionStatistics sessionStatistics = SessionStatistics.builder()
                .clientId(client.getClientId())
                .registryCode(institution.getRegistryCode())
                .sector(institution.getSector())
                .sessionId(sid)
                .authenticationRequestType(requestType)
                .authenticationState(AUTHENTICATION_CANCELED)
                .build();

        log.info(appendFields(sessionStatistics), "Statistics");
    }

    public void logError(@NonNull Exception ex, @NonNull ErrorCode errorCode, @NonNull LoginRequestInfo loginRequestInfo, AuthenticationRequestType requestType) {
        var client = loginRequestInfo.getClient();
        var institution = client.getMetadata().getOidcClient().getInstitution();
        var sid = loginRequestInfo.getSessionId();

        SessionStatistics sessionStatistics = SessionStatistics.builder()
                .clientId(client.getClientId())
                .registryCode(institution.getRegistryCode())
                .sector(institution.getSector())
                .sessionId(sid)
                .authenticationRequestType(requestType)
                .authenticationState(AUTHENTICATION_FAILED)
                .errorCode(errorCode)
                .build();

        log.error(appendFields(sessionStatistics), "Statistics", ex);
    }

    enum AuthenticationState {AUTHENTICATION_SUCCESS, AUTHENTICATION_CANCELED, AUTHENTICATION_FAILED}

    public enum AuthenticationRequestType {START_SESSION, CONTINUE_SESSION, UPDATE_SESSION}

    @Builder
    @Data
    static class SessionStatistics {
        @JsonProperty("client.id")
        private String clientId;

        @JsonProperty("institution.registry_code")
        private String registryCode;

        @JsonProperty("institution.sector")
        private String sector;

        @JsonProperty("session_id")
        private String sessionId;

        @JsonProperty("session_start_time")
        private Date sessionStartTime;

        @JsonProperty("session_duration")
        private Long sessionDuration;

        @JsonProperty("authentication.country")
        private String country;

        @JsonProperty("authentication.id_code")
        private String idCode;

        @JsonProperty("authentication.request_type")
        private AuthenticationRequestType authenticationRequestType;

        @JsonProperty("authentication.type")
        private String authenticationType;

        @JsonProperty("authentication.state")
        private AuthenticationState authenticationState;

        @JsonProperty("authentication.requested_acr")
        private String requestedAcr;

        @JsonProperty("authentication.granted_acr")
        private String grantedAcr;

        @JsonProperty("authentication.error_code")
        private ErrorCode errorCode;
    }
}
