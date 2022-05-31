package ee.ria.govsso.session.controller;

import ee.ria.govsso.session.BaseTest;
import ee.ria.govsso.session.session.SsoCookie;
import ee.ria.govsso.session.session.SsoCookieSigner;
import io.restassured.RestAssured;
import io.restassured.builder.ResponseSpecBuilder;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.codec.digest.DigestUtils;
import org.hamcrest.Matchers;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.beans.factory.annotation.Autowired;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static com.github.tomakehurst.wiremock.client.WireMock.put;
import static com.github.tomakehurst.wiremock.client.WireMock.urlEqualTo;
import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.equalTo;

@Slf4j
@RequiredArgsConstructor(onConstructor_ = @Autowired)
class ConsentInitControllerTest extends BaseTest {
    private static final String TEST_LOGIN_CHALLENGE = "abcdeff098aadfccabcdeff098aadfcc";
    public static final String TEST_CONSENT_CHALLENGE = "abcdeff098aadfccabcdeff098aadfcc";

    private final SsoCookieSigner ssoCookieSigner;

    @BeforeEach
    public void setupExpectedResponseSpec() {
        RestAssured.responseSpecification = new ResponseSpecBuilder()
                .expectHeaders(EXPECTED_RESPONSE_HEADERS_WITH_CORS).build();
    }

    @ParameterizedTest
    @ValueSource(strings = {"", "......", "123456789012345678901234567890123456789012345678900"})
    void consentInit_WhenConsentChallengeInvalid_ThrowsUserInputError(String consentChallenge) {
        String ssoCookie = createSignedSsoCookie();

        given()
                .param("consent_challenge", consentChallenge)
                .cookie(ssoCookie)
                .when()
                .get("/consent/init")
                .then()
                .assertThat()
                .statusCode(400)
                .body("error", equalTo("USER_INPUT"));

        assertErrorIsLogged("User input exception: consentInit.consentChallenge: must match \"^[a-f0-9]{32}$\"");
    }

    @Test
    void consentInit_WhenConsentChallengeParamIsMissing_ThrowsUserInputError() {
        String ssoCookie = createSignedSsoCookie();

        given()
                .cookie(ssoCookie)
                .when()
                .get("/consent/init")
                .then()
                .assertThat()
                .statusCode(400)
                .body("error", equalTo("USER_INPUT"));

        assertErrorIsLogged("User input exception: Required request parameter 'consent_challenge' for method parameter type String is not present");
    }

    @Test
    void consentInit_WhenConsentChallengeParamIsDuplicate_ThrowsUserInputError() {
        String ssoCookie = createSignedSsoCookie();

        given()
                .param("consent_challenge", TEST_CONSENT_CHALLENGE)
                .param("consent_challenge", TEST_CONSENT_CHALLENGE)
                .cookie(ssoCookie)
                .when()
                .get("/consent/init")
                .then()
                .assertThat()
                .statusCode(400)
                .body("error", equalTo("USER_INPUT"));

        assertErrorIsLogged("Duplicate parameters not allowed in request. Found multiple parameters with name: consent_challenge");
    }

    @Test
    void consentInit_WhenAcceptConsentIsSuccessful_Redirects() {
        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/oauth2/auth/requests/consent?consent_challenge=" + TEST_CONSENT_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_consent_request.json")));

        HYDRA_MOCK_SERVER.stubFor(put(urlEqualTo("/oauth2/auth/requests/consent/accept?consent_challenge=" + TEST_CONSENT_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_consent_accept.json")));
        String ssoCookie = createSignedSsoCookie();

        given()
                .param("consent_challenge", TEST_CONSENT_CHALLENGE)
                .cookie(ssoCookie)
                .when()
                .get("/consent/init")
                .then()
                .assertThat()
                .statusCode(302)
                .header("Location", Matchers.containsString("auth/consent/test"));
    }

    @Test
    void consentInit_WhenGetConsentRequestInfoRespondswith404_ThrowsUserInputError() {
        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/oauth2/auth/requests/consent?consent_challenge=" + TEST_CONSENT_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(404)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")));
        String ssoCookie = createSignedSsoCookie();

        given()
                .param("consent_challenge", TEST_CONSENT_CHALLENGE)
                .cookie(ssoCookie)
                .when()
                .get("/consent/init")
                .then()
                .assertThat()
                .statusCode(400)
                .body("error", equalTo("USER_INPUT"));

        assertErrorIsLogged("SsoException: Failed to fetch Hydra consent request info --> 404 Not Found from GET");
    }

    @Test
    void consentInit_WhenGetConsentRequestInfoRespondswith410_ThrowsUserInputError() {
        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/oauth2/auth/requests/consent?consent_challenge=" + TEST_CONSENT_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(410)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")));
        String ssoCookie = createSignedSsoCookie();

        given()
                .param("consent_challenge", TEST_CONSENT_CHALLENGE)
                .cookie(ssoCookie)
                .when()
                .get("/consent/init")
                .then()
                .assertThat()
                .statusCode(400)
                .body("error", equalTo("USER_INPUT"));

        assertErrorIsLogged("SsoException: Failed to fetch Hydra consent request info --> 410 Gone from GET");
    }

    @Test
    void consentInit_WhenGetConsentRequestInfoRespondswith500_ThrowsTechnicalGeneralError() {
        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/oauth2/auth/requests/consent?consent_challenge=" + TEST_CONSENT_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(500)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")));
        String ssoCookie = createSignedSsoCookie();

        given()
                .param("consent_challenge", TEST_CONSENT_CHALLENGE)
                .cookie(ssoCookie)
                .when()
                .get("/consent/init")
                .then()
                .assertThat()
                .statusCode(500)
                .body("error", equalTo("TECHNICAL_GENERAL"));

        assertErrorIsLogged("SsoException: Failed to fetch Hydra consent request info --> 500 Internal Server Error from GET");
    }

    @Test
    void consentInit_WhenAcceptConsentRespondsWith500_ThrowsTechnicalGeneralError() {
        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/oauth2/auth/requests/consent?consent_challenge=" + TEST_CONSENT_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_consent_request.json")));

        HYDRA_MOCK_SERVER.stubFor(put(urlEqualTo("/oauth2/auth/requests/consent/accept?consent_challenge=" + TEST_CONSENT_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(500)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")));
        String ssoCookie = createSignedSsoCookie();

        given()
                .param("consent_challenge", TEST_CONSENT_CHALLENGE)
                .cookie(ssoCookie)
                .when()
                .get("/consent/init")
                .then()
                .assertThat()
                .statusCode(500)
                .body("error", equalTo("TECHNICAL_GENERAL"));

        assertErrorIsLogged("Unexpected error: 500 Internal Server Error from PUT");
    }

    private String createSignedSsoCookie() {
        SsoCookie ssoCookie = SsoCookie.builder()
                .sessionId(DigestUtils.sha256Hex(TEST_LOGIN_CHALLENGE))
                .loginChallenge(TEST_LOGIN_CHALLENGE)
                .build();
        return ssoCookieSigner.getSignedCookieValue(ssoCookie);
    }
}
