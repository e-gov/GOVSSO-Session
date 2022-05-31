package ee.ria.govsso.session.session;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.crypto.MACVerifier;
import com.nimbusds.jose.util.StandardCharset;
import ee.ria.govsso.session.configuration.properties.SecurityConfigurationProperties;
import ee.ria.govsso.session.error.ErrorCode;
import ee.ria.govsso.session.error.exceptions.SsoException;
import lombok.NonNull;
import org.apache.commons.lang3.StringUtils;
import org.springframework.http.ResponseCookie;
import org.springframework.stereotype.Component;

import javax.servlet.http.Cookie;
import java.text.ParseException;
import java.util.AbstractMap.SimpleImmutableEntry;
import java.util.Map;
import java.util.TreeMap;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static ee.ria.govsso.session.session.SsoCookie.COOKIE_NAME_GOVSSO;
import static ee.ria.govsso.session.session.SsoCookie.COOKIE_VALUE_LOGIN_CHALLENGE;
import static ee.ria.govsso.session.session.SsoCookie.COOKIE_VALUE_SESSION_ID;
import static ee.ria.govsso.session.session.SsoCookie.COOKIE_VALUE_TARA_NONCE;
import static ee.ria.govsso.session.session.SsoCookie.COOKIE_VALUE_TARA_STATE;
import static org.springframework.boot.web.server.Cookie.SameSite.NONE;

@Component
public class SsoCookieSigner {
    private final SecurityConfigurationProperties securityProperties;
    private final JWSSigner signer;

    public SsoCookieSigner(SecurityConfigurationProperties securityProperties) {
        this.securityProperties = securityProperties;
        this.signer = setUpSigner(securityProperties);
    }

    private MACSigner setUpSigner(SecurityConfigurationProperties securityProperties) {
        try {
            return new MACSigner(securityProperties.getCookieSigningSecret());
        } catch (Exception ex) {
            throw new SsoException(ErrorCode.TECHNICAL_GENERAL, "Unable to setup cookie signer", ex);
        }
    }

    public SsoCookie getVerifiedSsoCookieOrNull(Cookie ssoCookieValue) {
        return ssoCookieValue != null ? verifyCookie(ssoCookieValue.getValue(), false) : null;
    }

    public SsoCookie getVerifiedSsoCookieOrNull(String ssoCookieValue) {
        return ssoCookieValue != null ? verifyCookie(ssoCookieValue, false) : null;
    }

    public SsoCookie getVerifiedSsoCookie(String ssoCookieValue) {
        return verifyCookie(ssoCookieValue, true);
    }

    private SsoCookie verifyCookie(@NonNull String ssoCookieValue, boolean throwInvalidSignatureException) {
        try {
            JWSObject jwsObject = JWSObject.parse(ssoCookieValue);
            String signingSecret = securityProperties.getCookieSigningSecret();
            JWSVerifier verifier = new MACVerifier(signingSecret.getBytes(StandardCharset.UTF_8));
            if (!jwsObject.verify(verifier)) {
                if (throwInvalidSignatureException) {
                    throw new SsoException(ErrorCode.USER_INPUT, "Invalid SsoCookie signature");
                } else {
                    return null;
                }
            }

            Payload payload = jwsObject.getPayload();
            Map<String, Object> ssoObjectMap = payload.toJSONObject();
            String sessionId = (String) ssoObjectMap.get(COOKIE_VALUE_SESSION_ID);
            String loginChallenge = (String) ssoObjectMap.get(COOKIE_VALUE_LOGIN_CHALLENGE);
            String taraState = (String) ssoObjectMap.get(COOKIE_VALUE_TARA_STATE);
            String taraNonce = (String) ssoObjectMap.get(COOKIE_VALUE_TARA_NONCE);

            if (StringUtils.isBlank(sessionId)) {
                throw new SsoException(ErrorCode.USER_INPUT, "Invalid SsoCookie session id");
            }
            if (StringUtils.isBlank(loginChallenge)) {
                throw new SsoException(ErrorCode.USER_INPUT, "Invalid SsoCookie challenge id");
            }

            return new SsoCookie(sessionId, loginChallenge, taraState, taraNonce);
        } catch (ParseException ex) {
            throw new SsoException(ErrorCode.USER_INPUT, "Unable to parse SsoCookie", ex);
        } catch (IllegalStateException | JOSEException ex) {
            throw new SsoException(ErrorCode.USER_INPUT, "Unable to verify SsoCookie signature", ex);
        }
    }

    public String getSignedCookieValue(SsoCookie ssoCookie) {
        Map<String, Object> cookieValues = Stream.of(
                        new SimpleImmutableEntry<>(COOKIE_VALUE_SESSION_ID, ssoCookie.getSessionId()),
                        new SimpleImmutableEntry<>(COOKIE_VALUE_LOGIN_CHALLENGE, ssoCookie.getLoginChallenge()),
                        new SimpleImmutableEntry<>(COOKIE_VALUE_TARA_STATE, ssoCookie.getTaraAuthenticationRequestState()),
                        new SimpleImmutableEntry<>(COOKIE_VALUE_TARA_NONCE, ssoCookie.getTaraAuthenticationRequestNonce()))
                .filter(m -> m.getValue() != null)
                .collect(Collectors.toMap(Map.Entry::getKey, Map.Entry::getValue, (v1, v2) -> v2, TreeMap::new));

        Payload payload = new Payload(cookieValues);
        JWSObject jwsObject = signPayload(payload);

        return ResponseCookie
                .from(COOKIE_NAME_GOVSSO, jwsObject.serialize())
                .sameSite(NONE.attributeValue()) // TODO: Update session filters Lax cookies!
                .maxAge(securityProperties.getCookieMaxAgeSeconds())
                .path("/")
                .httpOnly(true)
                .secure(true)
                .build().toString();
    }

    private JWSObject signPayload(Payload payload) {
        try {
            JWSObject jwsObject = new JWSObject(new JWSHeader(JWSAlgorithm.HS256), payload);
            jwsObject.sign(signer);
            return jwsObject;
        } catch (Exception ex) {
            throw new SsoException(ErrorCode.TECHNICAL_GENERAL, "Unable to sign SsoCookie", ex);
        }
    }
}
