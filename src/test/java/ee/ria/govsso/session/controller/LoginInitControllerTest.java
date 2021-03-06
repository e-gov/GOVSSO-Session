package ee.ria.govsso.session.controller;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import ee.ria.govsso.session.BaseTest;
import ee.ria.govsso.session.configuration.properties.SecurityConfigurationProperties;
import ee.ria.govsso.session.session.SsoCookie;
import ee.ria.govsso.session.session.SsoCookieSigner;
import io.restassured.RestAssured;
import io.restassured.builder.ResponseSpecBuilder;
import io.restassured.http.ContentType;
import io.restassured.http.Cookie;
import io.restassured.matcher.DetailedCookieMatcher;
import io.restassured.matcher.RestAssuredMatchers;
import lombok.RequiredArgsConstructor;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.hamcrest.Matchers;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.test.context.NestedTestConfiguration;
import org.springframework.test.context.TestPropertySource;

import java.time.Instant;
import java.util.Date;
import java.util.Map;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.delete;
import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static com.github.tomakehurst.wiremock.client.WireMock.put;
import static com.github.tomakehurst.wiremock.client.WireMock.urlEqualTo;
import static com.nimbusds.jose.JWSAlgorithm.RS256;
import static ee.ria.govsso.session.configuration.SecurityConfiguration.COOKIE_NAME_XSRF_TOKEN;
import static ee.ria.govsso.session.controller.LoginInitController.LOGIN_INIT_REQUEST_MAPPING;
import static ee.ria.govsso.session.session.SsoCookie.COOKIE_NAME_GOVSSO;
import static io.restassured.RestAssured.given;
import static java.util.Collections.emptyMap;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.not;
import static org.springframework.test.context.NestedTestConfiguration.EnclosingConfiguration.OVERRIDE;

@Slf4j
@RequiredArgsConstructor(onConstructor_ = @Autowired)
public class LoginInitControllerTest extends BaseTest {

    private final SsoCookieSigner ssoCookieSigner;
    private final SecurityConfigurationProperties securityConfigurationProperties;

    @BeforeEach
    public void setupExpectedResponseSpec() {
        RestAssured.responseSpecification = new ResponseSpecBuilder()
                .expectHeaders(EXPECTED_RESPONSE_HEADERS_WITH_CORS).build();
    }

    @Test
    void loginInit_WhenFetchLoginRequestInfoIsSuccessful_CreatesSessionAndRedirects() {

        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/oauth2/auth/requests/login?login_challenge=" + TEST_LOGIN_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_login_request.json")));

        String ssoCookieValue = given()
                .param("login_challenge", TEST_LOGIN_CHALLENGE)
                .when()
                .get(LOGIN_INIT_REQUEST_MAPPING)
                .then()
                .assertThat()
                .statusCode(302)
                .header("Location", Matchers.matchesRegex("https:\\/\\/tara.localhost:10000\\/oidc\\/authorize\\?ui_locales=et&scope=openid\\+phone&acr_values=high&response_type=code&govsso_login_challenge=abcdeff098aadfccabcdeff098aadfcc&redirect_uri=https%3A%2F%2Fgateway.localhost%3A8000%2Flogin%2Ftaracallback&state=.*&nonce=.*&client_id=testclient123"))
                .extract().cookie(COOKIE_NAME_GOVSSO);

        SsoCookie ssoCookie = ssoCookieSigner.parseAndVerifyCookie(ssoCookieValue);
        assertThat(ssoCookie.getLoginChallenge(), equalTo(TEST_LOGIN_CHALLENGE));
    }

    @Test
    void loginInit_WhenPromptEncoded_CreatesSessionAndRedirects() {

        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/oauth2/auth/requests/login?login_challenge=" + TEST_LOGIN_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_login_request_with_encoded_prompt.json")));

        String ssoCookieValue = given()
                .param("login_challenge", TEST_LOGIN_CHALLENGE)
                .when()
                .get(LOGIN_INIT_REQUEST_MAPPING)
                .then()
                .assertThat()
                .statusCode(302)
                .header("Location", Matchers.matchesRegex("https:\\/\\/tara.localhost:10000\\/oidc\\/authorize\\?ui_locales=et&scope=openid\\+phone&acr_values=high&response_type=code&govsso_login_challenge=abcdeff098aadfccabcdeff098aadfcc&redirect_uri=https%3A%2F%2Fgateway.localhost%3A8000%2Flogin%2Ftaracallback&state=.*&nonce=.*&client_id=testclient123"))
                .extract().cookie(COOKIE_NAME_GOVSSO);

        SsoCookie ssoCookie = ssoCookieSigner.parseAndVerifyCookie(ssoCookieValue);
        assertThat(ssoCookie.getLoginChallenge(), equalTo(TEST_LOGIN_CHALLENGE));
    }

    @Test
    void loginInit_WhenFetchLoginRequestInfoAcrIsSubstantial_CreatesSessionAndRedirects() {

        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/oauth2/auth/requests/login?login_challenge=" + TEST_LOGIN_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_login_request_with_substantial_acr.json")));

        String ssoCookieValue = given()
                .param("login_challenge", TEST_LOGIN_CHALLENGE)
                .when()
                .get(LOGIN_INIT_REQUEST_MAPPING)
                .then()
                .assertThat()
                .statusCode(302)
                .header("Location", Matchers.matchesRegex("https:\\/\\/tara.localhost:10000\\/oidc\\/authorize\\?ui_locales=et&scope=openid\\+phone&acr_values=substantial&response_type=code&govsso_login_challenge=abcdeff098aadfccabcdeff098aadfcc&redirect_uri=https%3A%2F%2Fgateway.localhost%3A8000%2Flogin%2Ftaracallback&state=.*&nonce=.*&client_id=testclient123"))
                .extract().cookie(COOKIE_NAME_GOVSSO);

        SsoCookie ssoCookie = ssoCookieSigner.parseAndVerifyCookie(ssoCookieValue);

        assertThat(ssoCookie.getLoginChallenge(), equalTo(TEST_LOGIN_CHALLENGE));
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "mock_sso_oidc_login_request_with_subject.json",
            "mock_sso_oidc_login_request_with_subject_without_acr.json"})
    void loginInit_WhenFetchLoginRequestInfoWithSubjectIsSuccessful_CreatesSessionAndOpensView(String loginRequestMockFile) {

        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/oauth2/auth/requests/login?login_challenge=" + TEST_LOGIN_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/" + loginRequestMockFile)));

        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/oauth2/auth/sessions/consent?subject=test1234"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_consents.json")));

        given()
                .param("login_challenge", TEST_LOGIN_CHALLENGE)
                .when()
                .get(LOGIN_INIT_REQUEST_MAPPING)
                .then()
                .assertThat()
                .statusCode(200)
                .header(HttpHeaders.CONTENT_TYPE, MediaType.TEXT_HTML_VALUE + ";charset=UTF-8")
                .body(containsString("Teenusesse <span translate=\"no\">Teenusenimi A&lt;1&gt;2&amp;3</span> sisselogimine"))
                .body(containsString("kasutab ??hekordse sisselogimise"))
                .body(containsString("Eesnimi3"))
                .body(containsString("test1234"))
                .body(containsString("Perekonnanimi3"))
                .body(containsString("12.07.1961"))
                .body(not(containsString("12345")))
                .body(containsString("data:image/svg+xml;base64,testlogo"));
    }

    @Test
    void loginInit_WhenFetchLoginRequestInfoWithSubjectAndPhoneScopeIsSuccessful_CreatesSessionAndOpensViewWIthPhoneNumber() {

        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/oauth2/auth/requests/login?login_challenge=" + TEST_LOGIN_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_login_request_scope_with_openid_and_phone.json")));

        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/oauth2/auth/sessions/consent?subject=test1234"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_consents_idtoken_with_phone.json")));

        given()
                .param("login_challenge", TEST_LOGIN_CHALLENGE)
                .when()
                .get(LOGIN_INIT_REQUEST_MAPPING)
                .then()
                .assertThat()
                .statusCode(200)
                .header(HttpHeaders.CONTENT_TYPE, MediaType.TEXT_HTML_VALUE + ";charset=UTF-8")
                .body(containsString("Teenusesse <span translate=\"no\">Teenusenimi A</span> sisselogimine"))
                .body(containsString("kasutab ??hekordse sisselogimise"))
                .body(containsString("Eesnimi3"))
                .body(containsString("test1234"))
                .body(containsString("Perekonnanimi3"))
                .body(containsString("12.07.1961"))
                .body(containsString("12345"))
                .body(containsString("data:image/svg+xml;base64,testlogo"));
    }

    @Test
    void loginInit_WhenTaraIdTokenContainsPhoneNumber_CreatesSessionAndOpensViewWithPhoneNumber() {

        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/oauth2/auth/requests/login?login_challenge=" + TEST_LOGIN_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_login_request_with_subject.json")));

        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/oauth2/auth/sessions/consent?subject=test1234"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_consents_with_phone.json")));

        given()
                .param("login_challenge", TEST_LOGIN_CHALLENGE)
                .when()
                .get(LOGIN_INIT_REQUEST_MAPPING)
                .then()
                .assertThat()
                .statusCode(200)
                .header(HttpHeaders.CONTENT_TYPE, MediaType.TEXT_HTML_VALUE + ";charset=UTF-8")
                .body(containsString("Teenusesse <span translate=\"no\">Teenusenimi A&lt;1&gt;2&amp;3</span> sisselogimine"))
                .body(containsString("kasutab ??hekordse sisselogimise"))
                .body(containsString("Eesnimi3"))
                .body(containsString("test1234"))
                .body(containsString("Perekonnanimi3"))
                .body(containsString("12.07.1961"))
                .body(containsString("12345"))
                .body(containsString("data:image/svg+xml;base64,testlogo"));
    }

    @Test
    void loginInit_WhenQueryParamPresentWithPromptNoneAsValue_IgnoresGivenQueryParamAndCreatesSessionAndRedirects() {

        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/oauth2/auth/requests/login?login_challenge=" + TEST_LOGIN_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_login_request_with_query_param_value_as_prompt_none.json")));

        String ssoCookieValue = given()
                .param("login_challenge", TEST_LOGIN_CHALLENGE)
                .when()
                .get(LOGIN_INIT_REQUEST_MAPPING)
                .then()
                .assertThat()
                .statusCode(302)
                .header("Location", Matchers.matchesRegex("https:\\/\\/tara.localhost:10000\\/oidc\\/authorize\\?ui_locales=et&scope=openid\\+phone&acr_values=high&response_type=code&govsso_login_challenge=abcdeff098aadfccabcdeff098aadfcc&redirect_uri=https%3A%2F%2Fgateway.localhost%3A8000%2Flogin%2Ftaracallback&state=.*&nonce=.*&client_id=testclient123"))
                .extract().cookie(COOKIE_NAME_GOVSSO);

        SsoCookie ssoCookie = ssoCookieSigner.parseAndVerifyCookie(ssoCookieValue);
        assertThat(ssoCookie.getLoginChallenge(), equalTo(TEST_LOGIN_CHALLENGE));
    }

    @Test
    void loginInit_WhenFetchLoginRequestInfoWithoutLogoIsSuccessful_CreatesSessionAndOpensView() {

        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/oauth2/auth/requests/login?login_challenge=" + TEST_LOGIN_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_login_request_with_subject_without_logo.json")));

        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/oauth2/auth/sessions/consent?subject=test1234"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_consents.json")));

        given()
                .param("login_challenge", TEST_LOGIN_CHALLENGE)
                .when()
                .get(LOGIN_INIT_REQUEST_MAPPING)
                .then()
                .assertThat()
                .statusCode(200)
                .header(HttpHeaders.CONTENT_TYPE, MediaType.TEXT_HTML_VALUE + ";charset=UTF-8")
                .body(containsString("Teenusesse <span translate=\"no\">Teenusenimi A</span> sisselogimine"))
                .body(containsString("kasutab ??hekordse sisselogimise"))
                .body(containsString("Eesnimi3"))
                .body(containsString("test1234"))
                .body(containsString("Perekonnanimi3"))
                .body(containsString("12.07.1961"))
                .body(not(containsString("data:image/svg+xml;base64")));
    }

    @Test
    void loginInit_WhenLocaleFromHydraIsRussian_OpensViewInRussian() {
        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/oauth2/auth/requests/login?login_challenge=" + TEST_LOGIN_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_login_request_with_russian_locale.json")));

        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/oauth2/auth/sessions/consent?subject=test1234"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_consents.json")));

        given()
                .param("login_challenge", TEST_LOGIN_CHALLENGE)
                .when()
                .get("/login/init")
                .then()
                .assertThat()
                .statusCode(200)
                .header(HttpHeaders.CONTENT_TYPE, MediaType.TEXT_HTML_VALUE + ";charset=UTF-8")
                .body(containsString("???????? ?? ???????????? <span translate=\"no\">???????????????? ???????????? A</span>"))
                .body(containsString("?????????????????? ???????????????????? ?????????????? ?????????? (<span lang=\"en\" translate=\"no\">SSO - single sign-on</span>)"))
                .body(containsString("12.07.1961"))
                .body(containsString("html lang=\"ru\""));
    }

    @Test
    void loginInit_WhenLocaleFromHydraIsRussian_ErrorMessageIsInRussian() {
        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/oauth2/auth/requests/login?login_challenge=" + TEST_LOGIN_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_login_request_with_russian_locale.json")));

        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/oauth2/auth/sessions/consent?subject=test1234"))
                .willReturn(aResponse()
                        .withStatus(500)));

        given()
                .param("login_challenge", TEST_LOGIN_CHALLENGE)
                .when()
                .header(HttpHeaders.ACCEPT, ContentType.HTML)
                .get("/login/init")
                .then()
                .assertThat()
                .statusCode(500)
                .body(containsString("???????????? ????????????????????????????."))
                .body(containsString("?????????????????????? ???????? ????????????. ????????????????????, ???????????????????? ??????????."))
                .body(containsString("html lang=\"ru\""));

        assertErrorIsLogged("SsoException: Failed to fetch Hydra consents list --> 500 Internal Server Error from GET");
    }

    @Test
    void loginInit_WhenLocaleFromParameterIsEnglishAndLocaleFromCookieIsEstonianAndLocaleFromHydraIsRussian_OpensViewInEnglish() {
        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/oauth2/auth/requests/login?login_challenge=" + TEST_LOGIN_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_login_request_with_russian_locale.json")));

        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/oauth2/auth/sessions/consent?subject=test1234"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_consents.json")));

        given()
                .param("login_challenge", TEST_LOGIN_CHALLENGE)
                .when()
                .param("lang", "en")
                .cookie("__Host-LOCALE", "et")
                .get("/login/init")
                .then()
                .assertThat()
                .statusCode(200)
                .header(HttpHeaders.CONTENT_TYPE, MediaType.TEXT_HTML_VALUE + ";charset=UTF-8")
                .body(containsString("Logging in to <span translate=\"no\">Service name A</span>"))
                .body(containsString("service uses a single sign-on (<span translate=\"no\">SSO</span>) solution"))
                .body(containsString("7/12/1961"))
                .body(containsString("html lang=\"en\""));
    }

    @Test
    void loginInit_WhenLocaleFromParameterIsEnglishAndLocaleFromCookieIsEstonianAndLocaleFromHydraIsRussian_ErrorMessageIsInEnglish() {
        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/oauth2/auth/requests/login?login_challenge=" + TEST_LOGIN_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_login_request_with_russian_locale.json")));

        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/oauth2/auth/sessions/consent?subject=test1234"))
                .willReturn(aResponse()
                        .withStatus(500)));

        given()
                .param("login_challenge", TEST_LOGIN_CHALLENGE)
                .when()
                .header(HttpHeaders.ACCEPT, ContentType.HTML)
                .param("lang", "en")
                .cookie("__Host-LOCALE", "et")
                .get("/login/init")
                .then()
                .assertThat()
                .statusCode(500)
                .body(containsString("Authentication error."))
                .body(containsString("An unexpected error occurred. Please try again later."))
                .body(containsString("html lang=\"en\""));

        assertErrorIsLogged("SsoException: Failed to fetch Hydra consents list --> 500 Internal Server Error from GET");
    }

    @Test
    void loginInit_WhenLocaleFromParameterIsUnknownAndLocaleFromCookieIsUnknownAndLocaleFromHydraIsUnknown_OpensViewInEstonian() {

        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/oauth2/auth/requests/login?login_challenge=" + TEST_LOGIN_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_login_request_with_unknown_locale.json")));

        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/oauth2/auth/sessions/consent?subject=test1234"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_consents.json")));

        given()
                .param("login_challenge", TEST_LOGIN_CHALLENGE)
                .when()
                .param("lang", "unknown")
                .cookie("__Host-LOCALE", "unknown")
                .get("/login/init")
                .then()
                .assertThat()
                .statusCode(200)
                .header(HttpHeaders.CONTENT_TYPE, MediaType.TEXT_HTML_VALUE + ";charset=UTF-8")
                .body(containsString("kasutab ??hekordse sisselogimise"))
                .body(containsString("html lang=\"unknown\""));
    }

    @Test
    void loginInit_WhenLocaleFromParameterIsUnknownAndLocaleFromCookieIsUnknownAndLocaleFromHydraIsUnknown_ErrorMessageIsInEstonian() {
        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/oauth2/auth/requests/login?login_challenge=" + TEST_LOGIN_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_login_request_with_unknown_locale.json")));

        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/oauth2/auth/sessions/consent?subject=test1234"))
                .willReturn(aResponse()
                        .withStatus(500)));

        given()
                .param("login_challenge", TEST_LOGIN_CHALLENGE)
                .when()
                .header(HttpHeaders.ACCEPT, ContentType.HTML)
                .param("lang", "unknown")
                .cookie("__Host-LOCALE", "unknown")
                .get("/login/init")
                .then()
                .assertThat()
                .statusCode(500)
                .body(containsString("Kasutaja tuvastamine eba??nnestus."))
                .body(containsString("Protsess eba??nnestus tehnilise vea t??ttu. Palun proovige m??ne aja p??rast uuesti."))
                .body(containsString("html lang=\"unknown\""));

        assertErrorIsLogged("SsoException: Failed to fetch Hydra consents list --> 500 Internal Server Error from GET");
    }

    @Test
    void loginInit_WhenLocaleFromCookieIsEnglishAndLocaleFromHydraIsRussian_OpensViewInEnglish() {
        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/oauth2/auth/requests/login?login_challenge=" + TEST_LOGIN_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_login_request_with_russian_locale.json")));

        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/oauth2/auth/sessions/consent?subject=test1234"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_consents.json")));

        given()
                .param("login_challenge", TEST_LOGIN_CHALLENGE)
                .when()
                .cookie("__Host-LOCALE", "en")
                .get("/login/init")
                .then()
                .assertThat()
                .statusCode(200)
                .header(HttpHeaders.CONTENT_TYPE, MediaType.TEXT_HTML_VALUE + ";charset=UTF-8")
                .body(containsString("service uses a single sign-on (<span translate=\"no\">SSO</span>) solution"))
                .body(containsString("html lang=\"en\""));
    }

    @Test
    void loginInit_WhenLocaleFromCookieIsEnglishAndLocaleFromHydraIsRussian_ErrorMessageIsInEnglish() {
        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/oauth2/auth/requests/login?login_challenge=" + TEST_LOGIN_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_login_request_with_russian_locale.json")));

        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/oauth2/auth/sessions/consent?subject=test1234"))
                .willReturn(aResponse()
                        .withStatus(500)));

        given()
                .param("login_challenge", TEST_LOGIN_CHALLENGE)
                .when()
                .header(HttpHeaders.ACCEPT, ContentType.HTML)
                .cookie("__Host-LOCALE", "en")
                .get("/login/init")
                .then()
                .assertThat()
                .statusCode(500)
                .body(containsString("Authentication error."))
                .body(containsString("An unexpected error occurred. Please try again later."))
                .body(containsString("html lang=\"en\""));

        assertErrorIsLogged("SsoException: Failed to fetch Hydra consents list --> 500 Internal Server Error from GET");
    }

    @Test
    void loginInit_WhenMultipleLocalesFromHydra_OpensViewInRussian() {
        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/oauth2/auth/requests/login?login_challenge=" + TEST_LOGIN_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_login_request_with_multiple_locales.json")));

        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/oauth2/auth/sessions/consent?subject=test1234"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_consents.json")));

        given()
                .param("login_challenge", TEST_LOGIN_CHALLENGE)
                .when()
                .get("/login/init")
                .then()
                .assertThat()
                .statusCode(200)
                .header(HttpHeaders.CONTENT_TYPE, MediaType.TEXT_HTML_VALUE + ";charset=UTF-8")
                .body(containsString("???????? ?? ???????????? <span translate=\"no\">???????????????? ???????????? A</span>"))
                .body(containsString("?????????????????? ???????????????????? ?????????????? ?????????? (<span lang=\"en\" translate=\"no\">SSO - single sign-on</span>)"))
                .body(containsString("12.07.1961"))
                .body(containsString("html lang=\"ru\""));
    }

    @Test
    void loginInit_WhenConsentsAreNotIdentical_ThrowsTechnicalGeneralError() {
        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/oauth2/auth/requests/login?login_challenge=" + TEST_LOGIN_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_login_request_with_subject.json")));

        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/oauth2/auth/sessions/consent?subject=test1234"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_consents_not_identical.json")));

        given()
                .param("login_challenge", TEST_LOGIN_CHALLENGE)
                .when()
                .get(LOGIN_INIT_REQUEST_MAPPING)
                .then()
                .assertThat()
                .statusCode(500)
                .cookies(emptyMap())
                .body("error", equalTo("TECHNICAL_GENERAL"));

        assertErrorIsLogged("SsoException: Valid consents did not have identical tara_id_token values");
    }

    @Test
    void loginInit_WhenConsentsIdTokenAcrValueLowerThanLoginRequestInfoAcrValue_OpensAcrView() {
        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/oauth2/auth/requests/login?login_challenge=" + TEST_LOGIN_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_login_request_with_subject.json")));

        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/oauth2/auth/sessions/consent?subject=test1234"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_consents_first_acr_value_low.json")));

        given()
                .param("login_challenge", TEST_LOGIN_CHALLENGE)
                .when()
                .get(LOGIN_INIT_REQUEST_MAPPING)
                .then()
                .assertThat()
                .statusCode(200)
                .header(HttpHeaders.CONTENT_TYPE, MediaType.TEXT_HTML_VALUE + ";charset=UTF-8")
                .body(containsString("Teenusesse <strong translate=\"no\">Teenusenimi A&lt;1&gt;2&amp;3</strong> sisselogimine"))
                .body(containsString("Teenusesse <strong translate=\"no\">Teenusenimi A&lt;1&gt;2&amp;3</strong> sisselogimine n??uab k??rgema tasemega autentimisvahendiga uuesti autentimist."))
                .body(containsString("data:image/svg+xml;base64,testlogo"));
    }

    @Test
    void loginInit_WhenConsentsIdTokenAcrValueLowerThanLoginRequestInfoAcrValueWithoutLogo_OpensAcrView() {
        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/oauth2/auth/requests/login?login_challenge=" + TEST_LOGIN_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_login_request_with_subject_without_logo.json")));

        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/oauth2/auth/sessions/consent?subject=test1234"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_consents_first_acr_value_low.json")));

        given()
                .param("login_challenge", TEST_LOGIN_CHALLENGE)
                .when()
                .get(LOGIN_INIT_REQUEST_MAPPING)
                .then()
                .assertThat()
                .statusCode(200)
                .header(HttpHeaders.CONTENT_TYPE, MediaType.TEXT_HTML_VALUE + ";charset=UTF-8")
                .body(containsString("Teenusesse <strong translate=\"no\">Teenusenimi A</strong> sisselogimine"))
                .body(containsString("Teenusesse <strong translate=\"no\">Teenusenimi A</strong> sisselogimine n??uab k??rgema tasemega autentimisvahendiga uuesti autentimist."))
                .body(not(containsString("data:image/svg+xml;base64,testlogo")));
    }

    @Test
    void loginInit_WhenContinueSessionAndConsentsAreMissing_ReAuthenticate() {
        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/oauth2/auth/requests/login?login_challenge=" + TEST_LOGIN_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_login_request_with_subject.json")));
        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/oauth2/auth/sessions/consent?subject=test1234"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_consents_missing.json")));
        HYDRA_MOCK_SERVER.stubFor(delete(urlEqualTo("/oauth2/auth/sessions/consent?subject=test1234&login_session_id=e56cbaf9-81e9-4473-a733-261e8dd38e95&all=true&trigger_backchannel_logout=true"))
                .willReturn(aResponse()
                        .withStatus(204)));
        HYDRA_MOCK_SERVER.stubFor(delete(urlEqualTo("/oauth2/auth/sessions/login/e56cbaf9-81e9-4473-a733-261e8dd38e95"))
                .willReturn(aResponse()
                        .withStatus(204)));
        Cookie hydraCookie = new Cookie.Builder("oauth2_authentication_session_insecure", "a77cbaf9-77e9-5573-a711-919e8dd38a11")
                .setMaxAge(1000)
                .build();

        Cookie invalidatedHydraCookie = given()
                .param("login_challenge", TEST_LOGIN_CHALLENGE)
                .cookie(hydraCookie)
                .when()
                .get(LOGIN_INIT_REQUEST_MAPPING)
                .then()
                .assertThat()
                .statusCode(302)
                .header("Location", equalTo("https://hydra.localhost:9000/oauth2/auth?scope=openid&prompt=consent&response_type=code&client_id=openIdDemo&redirect_uri=https://hydra.localhost:9000/oauth/response&state=049d71ea-30cd-4a74-8dcd-47156055d364&nonce=5210b42a-2362-420b-bb81-54796da8c814&ui_locales=et"))
                .extract().detailedCookie("oauth2_authentication_session_insecure");

        assertThat(invalidatedHydraCookie.getMaxAge(), equalTo(0L));
    }

    @Test
    void loginInit_WhenUpdateSessionAndConsentsAreMissing_ThrowsTechnicalGeneralError() {
        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/oauth2/auth/requests/login?login_challenge=" + TEST_LOGIN_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_login_request_with_id_token_hint.json")));
        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/oauth2/auth/sessions/consent?subject=test1234"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_consents_missing.json")));

        given()
                .param("login_challenge", TEST_LOGIN_CHALLENGE)
                .when()
                .get(LOGIN_INIT_REQUEST_MAPPING)
                .then()
                .assertThat()
                .statusCode(500)
                .cookies(emptyMap())
                .body("error", equalTo("TECHNICAL_GENERAL"));

        assertErrorIsLogged("SsoException: No valid consent requests found");
    }

    @Test
    void loginInit_WhenConsentsRequestRespondsWith500_ThrowsTechnicalGeneralError() {
        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/oauth2/auth/requests/login?login_challenge=" + TEST_LOGIN_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_login_request_with_subject.json")));

        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/oauth2/auth/sessions/consent?subject=test1234"))
                .willReturn(aResponse()
                        .withStatus(500)));

        given()
                .param("login_challenge", TEST_LOGIN_CHALLENGE)
                .when()
                .get(LOGIN_INIT_REQUEST_MAPPING)
                .then()
                .assertThat()
                .statusCode(500)
                .cookies(emptyMap())
                .body("error", equalTo("TECHNICAL_GENERAL"));

        assertErrorIsLogged("SsoException: Failed to fetch Hydra consents list --> 500 Internal Server Error from GET");
    }

    @ParameterizedTest
    @ValueSource(strings = {"", "......", "123456789012345678901234567890123456789012345678900"})
    void loginInit_WhenLoginChallengeInvalid_ThrowsUserInputError(String loginChallenge) {
        given()
                .param("login_challenge", loginChallenge)
                .when()
                .get(LOGIN_INIT_REQUEST_MAPPING)
                .then()
                .assertThat()
                .statusCode(400)
                .cookies(emptyMap())
                .body("error", equalTo("USER_INPUT"));

        assertErrorIsLogged("User input exception: loginInit.loginChallenge: Incorrect login_challenge format");
    }

    @Test
    void loginInit_WhenLoginChallengeParamIsDuplicate_ThrowsUserInputError() {
        given()
                .param("login_challenge", TEST_LOGIN_CHALLENGE)
                .param("login_challenge", "abcdeff098aadfccabcdeff098aadfca")
                .when()
                .get(LOGIN_INIT_REQUEST_MAPPING)
                .then()
                .assertThat()
                .statusCode(400)
                .cookies(emptyMap())
                .body("error", equalTo("USER_INPUT"));

        assertErrorIsLogged("Duplicate parameters not allowed in request. Found multiple parameters with name: login_challenge");
    }

    @Test
    void loginInit_WhenLoginChallengeMissing_ThrowsUserInputError() {
        given()
                .when()
                .get(LOGIN_INIT_REQUEST_MAPPING)
                .then()
                .assertThat()
                .statusCode(400)
                .cookies(emptyMap())
                .body("error", equalTo("USER_INPUT"));

        assertErrorIsLogged("User input exception: Required request parameter 'login_challenge' for method parameter type String is not present");
    }

    @Test
    void loginInit_WhenFetchLoginRequestInfoRespondsWith404_ThrowsUserInputError() {
        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/oauth2/auth/requests/login?login_challenge=" + TEST_LOGIN_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(404)));

        given()
                .param("login_challenge", TEST_LOGIN_CHALLENGE)
                .when()
                .get(LOGIN_INIT_REQUEST_MAPPING)
                .then()
                .assertThat()
                .statusCode(400)
                .cookies(emptyMap())
                .body("error", equalTo("USER_INPUT"));

        assertErrorIsLogged("SsoException: Failed to fetch Hydra login request info --> 404 Not Found from GET");
    }

    @Test
    void loginInit_WhenFetchLoginRequestInfoRespondsWith410_ThrowsUserInputError() {
        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/oauth2/auth/requests/login?login_challenge=" + TEST_LOGIN_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(410)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_login_request.json")));

        given()
                .param("login_challenge", TEST_LOGIN_CHALLENGE)
                .when()
                .get(LOGIN_INIT_REQUEST_MAPPING)
                .then()
                .assertThat()
                .statusCode(400)
                .cookies(emptyMap())
                .body("error", equalTo("USER_INPUT"));

        assertErrorIsLogged("SsoException: Failed to fetch Hydra login request info --> 410 Gone from GET");
    }

    @Test
    void loginInit_WhenFetchLoginRequestInfoRespondsWith500_ThrowsTechincalGeneralError() {
        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/oauth2/auth/requests/login?login_challenge=" + TEST_LOGIN_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(500)));

        given()
                .param("login_challenge", TEST_LOGIN_CHALLENGE)
                .when()
                .get(LOGIN_INIT_REQUEST_MAPPING)
                .then()
                .assertThat()
                .statusCode(500)
                .cookies(emptyMap())
                .body("error", equalTo("TECHNICAL_GENERAL"));

        assertErrorIsLogged("SsoException: Failed to fetch Hydra login request info --> 500 Internal Server Error from GET");
    }

    @Test
    void loginInit_WhenLoginResponseRequestUrlDoesntContainPromptConsent_ThrowsUserInputError() {

        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/oauth2/auth/requests/login?login_challenge=" + TEST_LOGIN_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_login_request_url_without_prompt_consent.json")));

        given()
                .param("login_challenge", TEST_LOGIN_CHALLENGE)
                .when()
                .get(LOGIN_INIT_REQUEST_MAPPING)
                .then()
                .assertThat()
                .statusCode(400)
                .cookies(emptyMap())
                .body("error", equalTo("USER_INPUT"));

        assertErrorIsLogged("SsoException: Request URL must contain prompt value");
    }

    @Test
    void loginInit_WhenLoginResponseRequestScopeContainsOnlyPhone_ThrowsUserInputError() {
        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/oauth2/auth/requests/login?login_challenge=" + TEST_LOGIN_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_login_request_scope_with_phone.json")));

        given()
                .param("login_challenge", TEST_LOGIN_CHALLENGE)
                .when()
                .get(LOGIN_INIT_REQUEST_MAPPING)
                .then()
                .assertThat()
                .statusCode(400)
                .cookies(emptyMap());

        assertErrorIsLogged("SsoException: Requested scope must contain openid and may contain phone, but nothing else");
    }

    @Test
    void loginInit_WhenLoginResponseRequestWithInvalidScope_ThrowsUserInputError() {

        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/oauth2/auth/requests/login?login_challenge=" + TEST_LOGIN_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_login_request_scope_with_idcard.json")));

        given()
                .param("login_challenge", TEST_LOGIN_CHALLENGE)
                .when()
                .get(LOGIN_INIT_REQUEST_MAPPING)
                .then()
                .assertThat()
                .statusCode(400)
                .cookies(emptyMap());

        assertErrorIsLogged("SsoException: Requested scope must contain openid and may contain phone, but nothing else");
    }

    @Test
    void loginInit_WhenLoginResponseRequestScopeWithOpenIdAndInvalidScope_ThrowsUserInputError() {

        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/oauth2/auth/requests/login?login_challenge=" + TEST_LOGIN_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_login_request_scope_with_openid_and_idcard.json")));

        given()
                .param("login_challenge", TEST_LOGIN_CHALLENGE)
                .when()
                .get(LOGIN_INIT_REQUEST_MAPPING)
                .then()
                .assertThat()
                .statusCode(400)
                .cookies(emptyMap());

        assertErrorIsLogged("SsoException: Requested scope must contain openid and may contain phone, but nothing else");
    }

    @Test
    void loginInit_WhenLoginResponseRequestIdTokenHintClaimIsNonEmpty_ThrowsUserInputError() {

        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/oauth2/auth/requests/login?login_challenge=" + TEST_LOGIN_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_login_request_id_token_hint_claim_non_empty_without_subject.json")));

        given()
                .param("login_challenge", TEST_LOGIN_CHALLENGE)
                .when()
                .get(LOGIN_INIT_REQUEST_MAPPING)
                .then()
                .assertThat()
                .statusCode(400)
                .cookies(emptyMap());

        assertErrorIsLogged("SsoException: id_token_hint_claims must be null");
    }

    @Test
    void loginInit_WhenLoginResponseRequestSubjectIsEmptyAndSkipIsTrue_ThrowsTechnicalGeneralError() {

        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/oauth2/auth/requests/login?login_challenge=" + TEST_LOGIN_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_login_request_skip_true.json")));

        given()
                .param("login_challenge", TEST_LOGIN_CHALLENGE)
                .when()
                .get(LOGIN_INIT_REQUEST_MAPPING)
                .then()
                .assertThat()
                .statusCode(500)
                .cookies(emptyMap());

        assertErrorIsLogged("SsoException: Subject is null, therefore login response skip value can not be true");
    }

    @Test
    void loginInit_WhenLoginResponseRequestSubjectIsNotEmptyAndSkipIsFalse_ThrowsTechnicalGeneralError() {

        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/oauth2/auth/requests/login?login_challenge=" + TEST_LOGIN_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_login_request_skip_false.json")));

        given()
                .param("login_challenge", TEST_LOGIN_CHALLENGE)
                .when()
                .get(LOGIN_INIT_REQUEST_MAPPING)
                .then()
                .assertThat()
                .statusCode(500)
                .cookies(emptyMap());

        assertErrorIsLogged("SsoException: Subject exists, therefore login response skip value can not be false");
    }

    @Test
    void loginInit_WhenLoginResponseRequestHasMoreThanOneAcrValue_ThrowsUserInputError() {

        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/oauth2/auth/requests/login?login_challenge=" + TEST_LOGIN_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_login_request_with_more_than_one_acr.json")));

        given()
                .param("login_challenge", TEST_LOGIN_CHALLENGE)
                .when()
                .get(LOGIN_INIT_REQUEST_MAPPING)
                .then()
                .assertThat()
                .statusCode(400)
                .cookies(emptyMap())
                .body("error", equalTo("USER_INPUT"));

        assertErrorIsLogged("SsoException: acrValues must contain only 1 value");
    }

    @Test
    void loginInit_WhenLoginResponseRequestHasOneIncorrectAcrValue_ThrowsUserInputError() {

        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/oauth2/auth/requests/login?login_challenge=" + TEST_LOGIN_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_login_request_with_one_incorrect_acr.json")));

        given()
                .param("login_challenge", TEST_LOGIN_CHALLENGE)
                .when()
                .get(LOGIN_INIT_REQUEST_MAPPING)
                .then()
                .assertThat()
                .statusCode(400)
                .cookies(emptyMap())
                .body("error", equalTo("USER_INPUT"));

        assertErrorIsLogged("SsoException: acrValues must be one of low/substantial/high");
    }

    @Test
    void loginInit_WhenLoginResponseRequestHasOneCapitalizedAcrValue_ThrowsUserInputError() {

        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/oauth2/auth/requests/login?login_challenge=" + TEST_LOGIN_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_login_request_with_capitalized_acr.json")));

        given()
                .param("login_challenge", TEST_LOGIN_CHALLENGE)
                .when()
                .get(LOGIN_INIT_REQUEST_MAPPING)
                .then()
                .assertThat()
                .statusCode(400)
                .cookies(emptyMap())
                .body("error", equalTo("USER_INPUT"));

        assertErrorIsLogged("SsoException: acrValues must be one of low/substantial/high");
    }

    @Test
    void loginInit_WhenNoCSRFCookieIsSet_SetsCSRFCookie() {
        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/oauth2/auth/requests/login?login_challenge=" + TEST_LOGIN_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_login_request.json")));

        DetailedCookieMatcher detailedCookieMatcher = RestAssuredMatchers.detailedCookie();

        given()
                .param("login_challenge", TEST_LOGIN_CHALLENGE)
                .when()
                .get("/login/init")
                .then()
                .assertThat()
                .statusCode(302)
                .header("Location", Matchers.matchesRegex("https:\\/\\/tara.localhost:10000\\/oidc\\/authorize\\?ui_locales=et&scope=openid\\+phone&acr_values=high&response_type=code&govsso_login_challenge=abcdeff098aadfccabcdeff098aadfcc&redirect_uri=https%3A%2F%2Fgateway.localhost%3A8000%2Flogin%2Ftaracallback&state=.*&nonce=.*&client_id=testclient123"))
                .cookie(COOKIE_NAME_XSRF_TOKEN, detailedCookieMatcher
                        .httpOnly(true)
                        .secured(true)
                        .path("/")
                        .maxAge(securityConfigurationProperties.getCookieMaxAgeSeconds()));
    }

    // TODO This test will stop working on 2038-xx-xx. Change it to be independent of current time.
    @Test
    void loginInit_WhenPromptNone_ExtendSession() {
        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/oauth2/auth/requests/login?login_challenge=" + TEST_LOGIN_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_login_request_with_prompt_none.json")));

        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/oauth2/auth/sessions/consent?subject=test1234"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_consents.json")));

        HYDRA_MOCK_SERVER.stubFor(put(urlEqualTo("/oauth2/auth/requests/login/accept?login_challenge=" + TEST_LOGIN_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_login_accept.json")));

        given()
                .param("login_challenge", TEST_LOGIN_CHALLENGE)
                .when()
                .get(LOGIN_INIT_REQUEST_MAPPING)
                .then()
                .assertThat()
                .statusCode(302)
                .cookies(emptyMap())
                .header("Location", Matchers.matchesRegex("https://clienta.localhost:11443/auth/login/test"));
    }

    @Test
    void loginInit_WhenPromptValueIsInvalid_ThrowsUserInputError() {
        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/oauth2/auth/requests/login?login_challenge=" + TEST_LOGIN_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_login_request_with_invalid_prompt_value.json")));

        given()
                .param("login_challenge", TEST_LOGIN_CHALLENGE)
                .when()
                .get(LOGIN_INIT_REQUEST_MAPPING)
                .then()
                .assertThat()
                .statusCode(400)
                .cookies(emptyMap())
                .body("error", equalTo("USER_INPUT"));

        assertErrorIsLogged("SsoException: Invalid prompt value");
    }

    @Test
    void loginInit_WhenMultiplePromptValues_ThrowsUserInputError() {
        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/oauth2/auth/requests/login?login_challenge=" + TEST_LOGIN_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_login_request_with_multiple_prompt_values.json")));

        given()
                .param("login_challenge", TEST_LOGIN_CHALLENGE)
                .when()
                .get(LOGIN_INIT_REQUEST_MAPPING)
                .then()
                .assertThat()
                .statusCode(400)
                .cookies(emptyMap())
                .body("error", equalTo("USER_INPUT"));

        assertErrorIsLogged("SsoException: Request URL contains more than 1 prompt values");
    }

    @Test
    void loginInit_WhenPromptNone_SubjectEmpty_ThrowsUserInputError() {
        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/oauth2/auth/requests/login?login_challenge=" + TEST_LOGIN_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_login_request_with_prompt_none_subject_empty.json")));

        given()
                .param("login_challenge", TEST_LOGIN_CHALLENGE)
                .when()
                .get(LOGIN_INIT_REQUEST_MAPPING)
                .then()
                .assertThat()
                .statusCode(400)
                .cookies(emptyMap())
                .body("error", equalTo("USER_INPUT"));

        assertErrorIsLogged("SsoException: Subject cannot be empty for session update");
    }

    @Test
    void loginInit_WhenPromptNone_OidcContextMissing_ThrowsUserInputError() {
        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/oauth2/auth/requests/login?login_challenge=" + TEST_LOGIN_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_login_request_with_prompt_none_oidc_context_missing.json")));

        given()
                .param("login_challenge", TEST_LOGIN_CHALLENGE)
                .when()
                .get(LOGIN_INIT_REQUEST_MAPPING)
                .then()
                .assertThat()
                .statusCode(400)
                .cookies(emptyMap())
                .body("error", equalTo("USER_INPUT"));

        assertErrorIsLogged("SsoException: Oidc context cannot be empty for session update");
    }

    @Test
    void loginInit_WhenPromptNone_TokenMissing_ThrowsUserInputError() {
        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/oauth2/auth/requests/login?login_challenge=" + TEST_LOGIN_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_login_request_with_prompt_none_token_missing.json")));

        given()
                .param("login_challenge", TEST_LOGIN_CHALLENGE)
                .when()
                .get(LOGIN_INIT_REQUEST_MAPPING)
                .then()
                .assertThat()
                .statusCode(400)
                .cookies(emptyMap())
                .body("error", equalTo("USER_INPUT"));

        assertErrorIsLogged("SsoException: Id token cannot be empty for session update");
    }

    @Test
    void loginInit_WhenPromptNone_AudienceDoesNotMatchRequestClientId_ThrowsUserInputError() {
        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/oauth2/auth/requests/login?login_challenge=" + TEST_LOGIN_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_login_request_with_prompt_none_mismatching_client_id.json")));

        given()
                .param("login_challenge", TEST_LOGIN_CHALLENGE)
                .when()
                .get(LOGIN_INIT_REQUEST_MAPPING)
                .then()
                .assertThat()
                .statusCode(400)
                .cookies(emptyMap())
                .body("error", equalTo("USER_INPUT"));

        assertErrorIsLogged("SsoException: Id token audiences must contain request client id");
    }

    @Test
    void loginInit_WhenPromptNone_TokenSessionIdDoesNotMatchWithRequestSessionId_ThrowsUserInputError() {
        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/oauth2/auth/requests/login?login_challenge=" + TEST_LOGIN_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_login_request_with_prompt_none_mismatching_token_session_id.json")));

        given()
                .param("login_challenge", TEST_LOGIN_CHALLENGE)
                .when()
                .get(LOGIN_INIT_REQUEST_MAPPING)
                .then()
                .assertThat()
                .statusCode(400)
                .cookies(emptyMap())
                .body("error", equalTo("USER_INPUT"));

        assertErrorIsLogged("SsoException: Id token session id must equal request session id");
    }

    @Test
    void loginInit_WhenPromptNone_TokenExpired_ThrowsUserInputError() {
        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/oauth2/auth/requests/login?login_challenge=" + TEST_LOGIN_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_login_request_with_prompt_none_token_expired.json")));

        given()
                .param("login_challenge", TEST_LOGIN_CHALLENGE)
                .when()
                .get(LOGIN_INIT_REQUEST_MAPPING)
                .then()
                .assertThat()
                .statusCode(400)
                .cookies(emptyMap())
                .body("error", equalTo("USER_INPUT"));

        assertErrorIsLogged("SsoException: Id token must not be expired");
    }

    @Test
    void loginInit_WhenPromptNone_WhenConsentsIdTokenAcrValueLowerThanLoginRequestInfoAcrValue_ThrowsTechnicalGeneralError() {
        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/oauth2/auth/requests/login?login_challenge=" + TEST_LOGIN_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_login_request_with_prompt_none.json")));

        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/oauth2/auth/sessions/consent?subject=test1234"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_consents_first_acr_value_low.json")));

        given()
                .param("login_challenge", TEST_LOGIN_CHALLENGE)
                .when()
                .get(LOGIN_INIT_REQUEST_MAPPING)
                .then()
                .assertThat()
                .statusCode(500)
                .cookies(emptyMap())
                .body("error", equalTo("TECHNICAL_GENERAL"));

        assertErrorIsLogged("SsoException: ID Token acr value must be equal to or higher than hydra login request acr");
    }

    @Test
    void loginInit_WhenFetchLoginRequestInfoDisplayUserConsentFalse_AcceptsConsent() {

        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/oauth2/auth/requests/login?login_challenge=" + TEST_LOGIN_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_login_request_display_user_consent_false.json")));

        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/oauth2/auth/sessions/consent?subject=test1234"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_consents.json")));

        HYDRA_MOCK_SERVER.stubFor(put(urlEqualTo("/oauth2/auth/requests/login/accept?login_challenge=" + TEST_LOGIN_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_login_accept.json")));


        given()
                .param("login_challenge", TEST_LOGIN_CHALLENGE)
                .when()
                .get(LOGIN_INIT_REQUEST_MAPPING)
                .then()
                .assertThat()
                .statusCode(302)
                .cookies(emptyMap())
                .header("Location", Matchers.matchesRegex("https://clienta.localhost:11443/auth/login/test"));
    }

    @Test
    void loginInit_WhenFetchLoginRequestInfoDisplayUserConsentTrueWithSkipUserConsentsClientIds_AcceptsConsent() {

        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/oauth2/auth/requests/login?login_challenge=" + TEST_LOGIN_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_login_request_with_skip_user_consent_client_ids.json")));

        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/oauth2/auth/sessions/consent?subject=test1234"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_consents.json")));

        HYDRA_MOCK_SERVER.stubFor(put(urlEqualTo("/oauth2/auth/requests/login/accept?login_challenge=" + TEST_LOGIN_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_login_accept.json")));


        given()
                .param("login_challenge", TEST_LOGIN_CHALLENGE)
                .when()
                .get(LOGIN_INIT_REQUEST_MAPPING)
                .then()
                .assertThat()
                .statusCode(302)
                .cookies(emptyMap())
                .header("Location", Matchers.matchesRegex("https://clienta.localhost:11443/auth/login/test"));
    }

    @Test
    void loginInit_WhenFetchLoginRequestInfoDisplayUserConsentTrueWithSkipUserConsentsClientIdsNotInExistingSession_AsksForConsent() {

        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/oauth2/auth/requests/login?login_challenge=" + TEST_LOGIN_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_login_request_with_skip_user_consent_client_ids_not_in_existing_session.json")));

        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/oauth2/auth/sessions/consent?subject=test1234"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_consents.json")));

        given()
                .param("login_challenge", TEST_LOGIN_CHALLENGE)
                .when()
                .get(LOGIN_INIT_REQUEST_MAPPING)
                .then()
                .assertThat()
                .statusCode(200)
                .header(HttpHeaders.CONTENT_TYPE, MediaType.TEXT_HTML_VALUE + ";charset=UTF-8")
                .body(containsString("Teenusesse <span translate=\"no\">Teenusenimi A&lt;1&gt;2&amp;3</span> sisselogimine"));
    }

    @Nested
    @NestedTestConfiguration(OVERRIDE)
    @TestPropertySource(properties = {"govsso.session-max-duration-hours=1"})
    class MaxSessionDurationOneHourTests extends BaseTest {

        @BeforeEach
        public void setupExpectedResponseSpec() {
            RestAssured.responseSpecification = new ResponseSpecBuilder()
                    .expectHeaders(EXPECTED_RESPONSE_HEADERS_WITH_CORS).build();
        }

        @Test
        @SneakyThrows
        void loginInit_WhenConsentIdTokenExpired10SecondsAgo_ThrowsTechnicalGeneralError() {

            SignedJWT jwt = createIdTokenWithAgeInSeconds(3610);
            String responseBody = createConsentsResponseBodyWithIdToken(jwt);

            HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/oauth2/auth/requests/login?login_challenge=" + TEST_LOGIN_CHALLENGE))
                    .willReturn(aResponse()
                            .withStatus(200)
                            .withHeader("Content-Type", "application/json; charset=UTF-8")
                            .withBodyFile("mock_responses/mock_sso_oidc_login_request_with_subject.json")));

            HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/oauth2/auth/sessions/consent?subject=test1234"))
                    .willReturn(aResponse()
                            .withStatus(200)
                            .withHeader("Content-Type", "application/json; charset=UTF-8")
                            .withBody(responseBody)));

            given()
                    .param("login_challenge", TEST_LOGIN_CHALLENGE)
                    .when()
                    .get(LOGIN_INIT_REQUEST_MAPPING)
                    .then()
                    .assertThat()
                    .statusCode(500)
                    .body("error", equalTo("TECHNICAL_GENERAL"));

            assertErrorIsLogged("SsoException: Hydra session has expired");
        }

        @Test
        @SneakyThrows
        void loginInit_WhenConsentIdTokenLasts10MoreSeconds_Returns200() {

            SignedJWT jwt = createIdTokenWithAgeInSeconds(3590);
            String responseBody = createConsentsResponseBodyWithIdToken(jwt);

            HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/oauth2/auth/requests/login?login_challenge=" + TEST_LOGIN_CHALLENGE))
                    .willReturn(aResponse()
                            .withStatus(200)
                            .withHeader("Content-Type", "application/json; charset=UTF-8")
                            .withBodyFile("mock_responses/mock_sso_oidc_login_request_with_subject.json")));

            HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/oauth2/auth/sessions/consent?subject=test1234"))
                    .willReturn(aResponse()
                            .withStatus(200)
                            .withHeader("Content-Type", "application/json; charset=UTF-8")
                            .withBody(responseBody)));

            given()
                    .param("login_challenge", TEST_LOGIN_CHALLENGE)
                    .when()
                    .get(LOGIN_INIT_REQUEST_MAPPING)
                    .then()
                    .assertThat()
                    .statusCode(200);
        }

        private String createConsentsResponseBodyWithIdToken(SignedJWT jwt) {
            String consentsResponseBody = """
                    [
                      {
                        "consent_request": {
                          "context": {
                            "tara_id_token": "%s"
                          },
                          "login_session_id": "e56cbaf9-81e9-4473-a733-261e8dd38e95"
                        }
                      }
                    ]
                    """;

            return String.format(consentsResponseBody, jwt.serialize());
        }

        private SignedJWT createIdTokenWithAgeInSeconds(int ageInSeconds) throws JOSEException {
            JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                    .notBeforeTime(Date.from(Instant.now().minusSeconds(ageInSeconds)))
                    .claim("profile_attributes", Map.of("given_name", "test1", "family_name", "test2"))
                    .claim("acr", "high")
                    .build();
            SignedJWT jwt = new SignedJWT(new JWSHeader.Builder(RS256).keyID(TARA_JWK.getKeyID()).build(), claimsSet);
            JWSSigner signer = new RSASSASigner(TARA_JWK);
            jwt.sign(signer);
            return jwt;
        }
    }
}
