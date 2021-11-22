package ee.ria.govsso.session.service.tara;

import com.nimbusds.langtag.LangTag;
import com.nimbusds.oauth2.sdk.auth.ClientAuthenticationMethod;
import com.nimbusds.oauth2.sdk.id.Identifier;
import com.nimbusds.openid.connect.sdk.op.OIDCProviderMetadata;
import com.nimbusds.openid.connect.sdk.validators.IDTokenValidator;
import ee.ria.govsso.session.BaseTest;
import ee.ria.govsso.session.configuration.properties.TaraConfigurationProperties;
import ee.ria.govsso.session.error.exceptions.SsoException;
import ee.ria.govsso.session.error.exceptions.TaraException;
import lombok.RequiredArgsConstructor;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.MethodOrderer;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.mock.mockito.SpyBean;
import org.springframework.test.context.TestPropertySource;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static com.github.tomakehurst.wiremock.client.WireMock.urlEqualTo;
import static com.nimbusds.jose.JWSAlgorithm.RS256;
import static com.nimbusds.oauth2.sdk.GrantType.AUTHORIZATION_CODE;
import static com.nimbusds.oauth2.sdk.ResponseType.CODE;
import static com.nimbusds.openid.connect.sdk.SubjectType.PUBLIC;
import static com.nimbusds.openid.connect.sdk.claims.ClaimType.NORMAL;
import static ee.ria.govsso.session.error.ErrorCode.TARA_ERROR;
import static java.util.List.of;
import static java.util.stream.Collectors.toList;
import static org.awaitility.Awaitility.await;
import static org.awaitility.Durations.FIVE_SECONDS;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.contains;
import static org.hamcrest.Matchers.equalTo;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.atLeast;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;

@Slf4j
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
@TestPropertySource(properties = {
        "govsso.tara.metadata-interval=100",
        "govsso.tara.metadata-max-attempts=3",
        "govsso.tara.metadata-backoff-delay-milliseconds=100",
        "govsso.tara.metadata-backoff-multiplier=1.0"})
@RequiredArgsConstructor(onConstructor_ = @Autowired)
class TaraMetadataServiceTest extends BaseTest {

    private final TaraConfigurationProperties taraConfigurationProperties;

    @SpyBean
    private TaraMetadataService taraMetadataService;

    @Value("${govsso.tara.metadata-max-attempts}")
    private Integer metadataUpdateMaxAttempts;

    @BeforeAll
    static void setUpTaraMetadataNotAvailable() {
        wireMockServer.resetAll();
    }

    @Test
    @Order(1)
    void getMetadata_WhenMetadataNotUpdated_ThrowsTaraException() {
        TaraException taraException = assertThrows(TaraException.class, taraMetadataService::getMetadata);

        assertThat(taraException.getErrorCode(), equalTo(TARA_ERROR));
        assertThat(taraException.getMessage(), equalTo("TARA metadata not available"));
    }

    @Test
    @Order(2)
    void getIDTokenValidator_WhenMetadataNotUpdated_ThrowsTaraException() {
        TaraException taraException = assertThrows(TaraException.class, taraMetadataService::getIDTokenValidator);

        assertThat(taraException.getErrorCode(), equalTo(TARA_ERROR));
        assertThat(taraException.getMessage(), equalTo("TARA metadata not available"));
    }

    @Test
    @Order(3)
    @SneakyThrows
    void updateMetadata_WhenTaraMetadataNotAvailable_RetriesMetadataRequest() {
        int nextScheduledInvocationCall = metadataUpdateMaxAttempts + 1;

        await().atMost(FIVE_SECONDS)
                .untilAsserted(() -> verify(taraMetadataService, atLeast(nextScheduledInvocationCall)).updateMetadata());

        verify(taraMetadataService, atLeast(nextScheduledInvocationCall)).requestMetadata();
        verify(taraMetadataService, never()).requestJWKSet(any());
        assertThrows(TaraException.class, taraMetadataService::getMetadata);
        assertThrows(TaraException.class, taraMetadataService::getIDTokenValidator);
    }

    @Test
    @Order(4)
    @SneakyThrows
    void updateMetadata_WhenTaraJwkSetNotAvailable_RetriesMetadataRequest() {
        setUpMetadataWithoutJwkSet();
        int nextScheduledInvocationCall = metadataUpdateMaxAttempts + 1;

        await().atMost(FIVE_SECONDS)
                .untilAsserted(() -> verify(taraMetadataService, atLeast(nextScheduledInvocationCall)).updateMetadata());

        verify(taraMetadataService, atLeast(metadataUpdateMaxAttempts)).requestMetadata();
        verify(taraMetadataService, atLeast(metadataUpdateMaxAttempts)).requestJWKSet(any());
        verify(taraMetadataService, never()).createIdTokenValidator(any(), any());
        assertThrows(TaraException.class, taraMetadataService::getMetadata);
        assertThrows(TaraException.class, taraMetadataService::getIDTokenValidator);
    }

    @Test
    @Order(5)
    @SneakyThrows
    void updateMetadata_WhenTaraMetadataAndJwkSetAvailable_SucceedsAndCachesResult() {
        setUpTaraMetadataMocks();

        await().atMost(FIVE_SECONDS)
                .untilAsserted(() -> verify(taraMetadataService, atLeast(1)).createIdTokenValidator(any(), any()));

        // TODO: GSSO-111 Remove irrelevant assertions
        verify(taraMetadataService, atLeast(1)).requestMetadata();
        verify(taraMetadataService, atLeast(1)).requestJWKSet(any());
        verify(taraMetadataService, atLeast(1)).createIdTokenValidator(any(), any());
        OIDCProviderMetadata metadata = taraMetadataService.getMetadata();
        assertThat(metadata.getIssuer().getValue(), equalTo(taraConfigurationProperties.getIssuerUrl().toString()));
        assertThat(metadata.getTokenEndpointURI().toString(), equalTo("https://localhost:9877/oidc/token"));
        assertThat(metadata.getUserInfoEndpointURI().toString(), equalTo("https://localhost:9877/oidc/profile"));
        assertThat(metadata.getAuthorizationEndpointURI().toString(), equalTo("https://localhost:9877/oidc/authorize"));
        assertThat(metadata.getJWKSetURI().toString(), equalTo("https://localhost:9877/oidc/jwks"));
        assertThat(metadata.getTokenEndpointAuthMethods(), equalTo(of(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)));
        assertThat(metadata.getSubjectTypes(), contains(PUBLIC));
        assertThat(metadata.getResponseTypes(), contains(CODE));
        assertThat(metadata.getGrantTypes(), contains(AUTHORIZATION_CODE));
        assertThat(metadata.getIDTokenJWSAlgs(), contains(RS256));
        assertThat(metadata.getUILocales(), contains(LangTag.parse("et"), LangTag.parse("en"), LangTag.parse("ru")));
        assertThat(metadata.getClaimTypes(), contains(NORMAL));
        assertThat(metadata.getClaims(), contains(
                "sub",
                "email",
                "email_verified",
                "phonenumber",
                "phonenumber_verified",
                "given_name",
                "family_name",
                "date_of_birth",
                "represents_legal_person.name",
                "represents_legal_person.registry_code"));
        assertThat(metadata.getScopes().stream().map(Identifier::getValue).collect(toList()), contains(
                "openid",
                "idcard",
                "mid",
                "smartid",
                "email",
                "phone",
                "eidas",
                "eidasonly",
                "eidas:country:es",
                "eidas:country:de",
                "eidas:country:it",
                "eidas:country:be",
                "eidas:country:lu",
                "eidas:country:hr",
                "eidas:country:lv",
                "eidas:country:pt",
                "eidas:country:lt",
                "eidas:country:nl",
                "eidas:country:cz",
                "eidas:country:sk",
                "eidas:country:pl"));
        IDTokenValidator idTokenValidator = taraMetadataService.getIDTokenValidator();
        assertThat(idTokenValidator.getClientID().getValue(), equalTo(taraConfigurationProperties.getClientId()));
        assertThat(idTokenValidator.getExpectedIssuer().getValue(), equalTo(taraConfigurationProperties.getIssuerUrl().toString()));
        assertThat(idTokenValidator.getMaxClockSkew(), equalTo(taraConfigurationProperties.getMaxClockSkewSeconds()));
    }

    @Test
    void updateMetadata_WhenInvalidIssuer_ThrowsSsoException() {
        setUpTaraMetadataMocks("mock_tara_oidc_metadata_invalid_issuer.json");

        assertCauseMessage("Expected OIDC Issuer 'https://localhost:9877' does not match published issuer 'https://localhost:9877/'");
    }

    @Test
    void updateMetadata_WhenMissingJwksUri_ThrowsSsoException() {
        setUpTaraMetadataMocks("mock_tara_oidc_metadata_missing_jwks_uri.json");

        assertCauseMessage("The public JWK set URI must not be null");
    }

    @Test
    void updateMetadata_WhenMissingAuthorizationEndpoint_ThrowsSsoException() {
        setUpTaraMetadataMocks("mock_tara_oidc_metadata_missing_authorization_endpoint.json");

        assertCauseMessage("The public authorization endpoint URI must not be null");
    }

    @Test
    void updateMetadata_WhenBlankAuthorizationEndpoint_ThrowsSsoException() {
        setUpTaraMetadataMocks("mock_tara_oidc_metadata_blank_authorization_endpoint.json");

        assertCauseMessage("The public authorization endpoint URI must not be null");
    }

    @Test
    void updateMetadata_WhenMissingTokenEndpoint_ThrowsSsoException() {
        setUpTaraMetadataMocks("mock_tara_oidc_metadata_missing_token_endpoint.json");

        assertCauseMessage("The public token endpoint URI must not be null");
    }

    @Test
    void updateMetadata_WhenBlankTokenEndpoint_ThrowsSsoException() {
        setUpTaraMetadataMocks("mock_tara_oidc_metadata_blank_token_endpoint.json");

        assertCauseMessage("The public token endpoint URI must not be null");
    }

    private void assertCauseMessage(String causeMessage) {
        SsoException exception = assertThrows(SsoException.class, () -> taraMetadataService.updateMetadata());
        assertThat(exception.getMessage(), equalTo("Unable to update TARA metadata"));
        Throwable cause = exception.getCause();
        assertThat(cause.getMessage(), equalTo(causeMessage));
    }

    private void setUpMetadataWithoutJwkSet() {
        wireMockServer.stubFor(get(urlEqualTo("/.well-known/openid-configuration"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_tara_oidc_metadata.json")));

        wireMockServer.stubFor(get(urlEqualTo("/oidc/jwks"))
                .willReturn(aResponse()
                        .withStatus(404)));
    }
}