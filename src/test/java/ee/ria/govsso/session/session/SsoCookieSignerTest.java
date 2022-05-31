package ee.ria.govsso.session.session;

import com.nimbusds.jose.KeyLengthException;
import ee.ria.govsso.session.BaseTest;
import ee.ria.govsso.session.configuration.properties.SecurityConfigurationProperties;
import ee.ria.govsso.session.error.exceptions.SsoException;
import lombok.RequiredArgsConstructor;
import org.apache.commons.codec.digest.DigestUtils;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.beans.factory.annotation.Autowired;

import java.util.AbstractMap.SimpleImmutableEntry;
import java.util.Collections;
import java.util.Map;
import java.util.TreeMap;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static ee.ria.govsso.session.error.ErrorCode.TECHNICAL_GENERAL;
import static ee.ria.govsso.session.error.ErrorCode.USER_INPUT;
import static ee.ria.govsso.session.session.SsoCookie.COOKIE_VALUE_LOGIN_CHALLENGE;
import static ee.ria.govsso.session.session.SsoCookie.COOKIE_VALUE_SESSION_ID;
import static ee.ria.govsso.session.session.SsoCookie.COOKIE_VALUE_TARA_NONCE;
import static ee.ria.govsso.session.session.SsoCookie.COOKIE_VALUE_TARA_STATE;
import static java.lang.String.format;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.instanceOf;
import static org.hamcrest.Matchers.matchesRegex;
import static org.junit.jupiter.api.Assertions.assertThrows;

@RequiredArgsConstructor(onConstructor_ = @Autowired)
class SsoCookieSignerTest extends BaseTest {

    public static final SsoCookie SSO_COOKIE = SsoCookie.builder()
            .sessionId(DigestUtils.sha256Hex("9eeb3fc335e246879377098bfdc91d2f"))
            .loginChallenge("9eeb3fc335e246879377098bfdc91d2f")
            .taraAuthenticationRequestState("uol5UdH_QLuKNvT-FlU-Ykmb_tzNhF02nr5clm-q1sc")
            .taraAuthenticationRequestNonce("CLJka9zYBh9cSlkFTGXItNoznEheueIgq-zm3BiDz0s")
            .build();
    public static final Map<String, Object> SSO_COOKIE_VALUES = Stream.of(
                    new SimpleImmutableEntry<>(COOKIE_VALUE_SESSION_ID, DigestUtils.sha256Hex(SSO_COOKIE.getLoginChallenge())),
                    new SimpleImmutableEntry<>(COOKIE_VALUE_LOGIN_CHALLENGE, SSO_COOKIE.getLoginChallenge()),
                    new SimpleImmutableEntry<>(COOKIE_VALUE_TARA_STATE, SSO_COOKIE.getTaraAuthenticationRequestState()),
                    new SimpleImmutableEntry<>(COOKIE_VALUE_TARA_NONCE, SSO_COOKIE.getTaraAuthenticationRequestNonce()))
            .collect(Collectors.toMap(Map.Entry::getKey, Map.Entry::getValue, (v1, v2) -> v2, TreeMap::new));
    private static final String SSO_COOKIE_HS256_HEADER = "eyJhbGciOiJIUzI1NiJ9";
    private static final String SSO_COOKIE_HS384_HEADER = "eyJhbGciOiJIUzM4NCJ9";
    private static final String SSO_COOKIE_HS512_HEADER = "eyJhbGciOiJIUzUxMiJ9";
    private static final String SSO_COOKIE_RS256_HEADER = "eyJhbGciOiJSUzI1NiJ9";
    private static final String SSO_COOKIE_EMPTY_ALG_HEADER = "eyJhbGciOiIifQ==";
    private static final String SSO_COOKIE_NO_ALG_HEADER = "e30=";
    private static final String SSO_COOKIE_PAYLOAD = "eyJ0YXJhX3N0YXRlIjoidW9sNVVkSF9RTHVLTnZULUZsVS1Za21iX3R6TmhGMDJucjVjbG0tcTFzYyIsInNlc3Npb25faWQiOiIxNDRiZWYzMWIxMzZhOWIzZTg3ZWRlNDkwMGJjODMxY2Y2MWRkYjJhOWEzOTZjMGRjZjFjMjhlMDM4ZGY4OTJmIiwibG9naW5fY2hhbGxlbmdlIjoiOWVlYjNmYzMzNWUyNDY4NzkzNzcwOThiZmRjOTFkMmYiLCJ0YXJhX25vbmNlIjoiQ0xKa2E5ellCaDljU2xrRlRHWEl0Tm96bkVoZXVlSWdxLXptM0JpRHowcyJ9";
    private static final String SSO_COOKIE_HS256_SIGNATURE = "lER7S9OxMPTMwCtcCdCGkUkmXqUnWkpLQ3R7Wvv3-kk";
    private static final String VALID_SIGNATURE_SSO_COOKIE_VALUE = format("%s.%s.%s", SSO_COOKIE_HS256_HEADER, SSO_COOKIE_PAYLOAD, SSO_COOKIE_HS256_SIGNATURE);
    private static final String SSO_COOKIE_SIGNING_SECRET = "fec1e8ee45b84f7f66824f7797f759f191c696020f5187744a1a3532935bd5ec";
    private final SsoCookieSigner ssoCookieSigner;
    private final SecurityConfigurationProperties securityConfigurationProperties;

    @Test
    void parseAndVerifyCookie_WhenValidSignature_ReturnsSsoCookieObject() {

        SsoCookie ssoCookie = ssoCookieSigner.getVerifiedSsoCookie(VALID_SIGNATURE_SSO_COOKIE_VALUE);

        assertThat(ssoCookie.getLoginChallenge(), equalTo(SSO_COOKIE.getLoginChallenge()));
        assertThat(ssoCookie.getTaraAuthenticationRequestState(), equalTo(SSO_COOKIE.getTaraAuthenticationRequestState()));
        assertThat(ssoCookie.getTaraAuthenticationRequestNonce(), equalTo(SSO_COOKIE.getTaraAuthenticationRequestNonce()));
    }

    @ParameterizedTest
    @ValueSource(strings = {"", " ", ".", "..", SSO_COOKIE_HS256_HEADER, SSO_COOKIE_HS256_HEADER + ".",
            SSO_COOKIE_HS256_HEADER + "." + SSO_COOKIE_PAYLOAD,
            SSO_COOKIE_NO_ALG_HEADER + "." + SSO_COOKIE_PAYLOAD + "." + SSO_COOKIE_HS256_SIGNATURE
    })
    void parseAndVerifyCookie_WhenParseException_ThrowsUserInputError(String ssoCookieValue) {

        SsoException ex = assertThrows(SsoException.class,
                () -> ssoCookieSigner.getVerifiedSsoCookie(ssoCookieValue));

        assertThat(ex.getErrorCode(), equalTo(USER_INPUT));
        assertThat(ex.getMessage(), equalTo("Unable to parse SsoCookie"));
    }

    @ParameterizedTest
    @ValueSource(strings = {
            SSO_COOKIE_HS256_HEADER + "." + SSO_COOKIE_PAYLOAD + ".",
            SSO_COOKIE_HS256_HEADER + "." + SSO_COOKIE_PAYLOAD + ".1VkCp8iizvHS2syiuLW3Dsg2ePeX7OIu1WIK1F9uWcQ",
            SSO_COOKIE_HS256_HEADER + ".¤." + SSO_COOKIE_HS256_SIGNATURE,
            SSO_COOKIE_HS384_HEADER + "." + SSO_COOKIE_PAYLOAD + "." + SSO_COOKIE_HS256_SIGNATURE,
            SSO_COOKIE_HS512_HEADER + "." + SSO_COOKIE_PAYLOAD + "." + SSO_COOKIE_HS256_SIGNATURE
    })
    void parseAndVerifyCookie_WhenInvalidSignature_ThrowsUserInputError(String ssoCookieValue) {

        SsoException ex = assertThrows(SsoException.class,
                () -> ssoCookieSigner.getVerifiedSsoCookie(ssoCookieValue));

        assertThat(ex.getErrorCode(), equalTo(USER_INPUT));
        assertThat(ex.getMessage(), equalTo("Invalid SsoCookie signature"));
    }

    @ParameterizedTest
    @ValueSource(strings = {
            SSO_COOKIE_EMPTY_ALG_HEADER + "." + SSO_COOKIE_PAYLOAD + "." + SSO_COOKIE_HS256_SIGNATURE,
            SSO_COOKIE_RS256_HEADER + "." + SSO_COOKIE_PAYLOAD + "." + SSO_COOKIE_HS256_SIGNATURE
    })
    void parseAndVerifyCookie_WhenInvalidAlg_ThrowsUserInputError(String ssoCookieValue) {

        SsoException ex = assertThrows(SsoException.class,
                () -> ssoCookieSigner.getVerifiedSsoCookie(ssoCookieValue));

        assertThat(ex.getErrorCode(), equalTo(USER_INPUT));
        assertThat(ex.getMessage(), equalTo("Unable to verify SsoCookie signature"));
    }

    @Test
    void getSignedCookieValue_ReturnsValidSignedCookie() {

        var ssoCookieValue = ssoCookieSigner.getSignedCookieValue(SSO_COOKIE);

        String cookieWithCorrectParameters = "__Host-GOVSSO=%s; Path=/; Max-Age=%s; Expires=.*; Secure; HttpOnly; SameSite=None"
                .formatted(VALID_SIGNATURE_SSO_COOKIE_VALUE, securityConfigurationProperties.getCookieMaxAgeSeconds());
        assertThat(ssoCookieValue, matchesRegex(cookieWithCorrectParameters));
    }

    @Test
    void constructorSsoCookieSigner_WhenInvalidSigningKeyLength_ThrowsTechnicalGeneralError() {

        var securityProperties = new SecurityConfigurationProperties("", "x".repeat(31), 3600, Collections.emptySet());


        SsoException ex = assertThrows(SsoException.class,
                () -> new SsoCookieSigner(securityProperties));

        assertThat(ex.getErrorCode(), equalTo(TECHNICAL_GENERAL));
        assertThat(ex.getMessage(), equalTo("Unable to setup cookie signer"));
        Throwable cause = ex.getCause();
        assertThat(cause, instanceOf(KeyLengthException.class));
        assertThat(cause.getMessage(), equalTo("The secret length must be at least 256 bits"));
    }

    @Test
    void constructorSsoCookieSigner_WhenNullSigningKey_ThrowsTechnicalGeneralError() {

        var securityProperties = new SecurityConfigurationProperties("", null, 3600, Collections.emptySet());

        SsoException ex = assertThrows(SsoException.class,
                () -> new SsoCookieSigner(securityProperties));

        assertThat(ex.getErrorCode(), equalTo(TECHNICAL_GENERAL));
        assertThat(ex.getMessage(), equalTo("Unable to setup cookie signer"));
        Throwable cause = ex.getCause();
        assertThat(cause, instanceOf(NullPointerException.class));
        assertThat(cause.getMessage(), equalTo("Cannot invoke \"String.getBytes(java.nio.charset.Charset)\" because \"secretString\" is null"));
    }
}
