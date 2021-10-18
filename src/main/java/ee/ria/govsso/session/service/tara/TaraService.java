package ee.ria.govsso.session.service.tara;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.proc.BadJOSEException;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.oauth2.sdk.AuthorizationCodeGrant;
import com.nimbusds.oauth2.sdk.AuthorizationGrant;
import com.nimbusds.oauth2.sdk.ErrorObject;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.TokenRequest;
import com.nimbusds.oauth2.sdk.TokenResponse;
import com.nimbusds.oauth2.sdk.auth.ClientAuthentication;
import com.nimbusds.oauth2.sdk.auth.ClientSecretBasic;
import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import com.nimbusds.openid.connect.sdk.Nonce;
import com.nimbusds.openid.connect.sdk.OIDCTokenResponse;
import com.nimbusds.openid.connect.sdk.OIDCTokenResponseParser;
import com.nimbusds.openid.connect.sdk.claims.IDTokenClaimsSet;
import com.nimbusds.openid.connect.sdk.op.OIDCProviderMetadata;
import com.nimbusds.openid.connect.sdk.validators.IDTokenValidator;
import ee.ria.govsso.session.configuration.properties.SsoConfigurationProperties;
import ee.ria.govsso.session.configuration.properties.TaraConfigurationProperties;
import ee.ria.govsso.session.error.exceptions.SsoException;
import ee.ria.govsso.session.error.exceptions.TaraException;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import javax.net.ssl.SSLContext;
import java.io.IOException;
import java.net.URI;

import static com.nimbusds.jose.jwk.source.RemoteJWKSet.DEFAULT_HTTP_CONNECT_TIMEOUT;
import static com.nimbusds.jose.jwk.source.RemoteJWKSet.DEFAULT_HTTP_READ_TIMEOUT;
import static com.nimbusds.oauth2.sdk.ResponseType.Value.CODE;
import static com.nimbusds.openid.connect.sdk.OIDCScopeValue.OPENID;

@Slf4j
@Service
@RequiredArgsConstructor
public class TaraService {

    private final TaraConfigurationProperties taraConfigurationProperties;
    private final SsoConfigurationProperties ssoConfigurationProperties;
    private final TaraMetadataService taraMetadataService;
    private final SSLContext trustContext;

    public AuthenticationRequest createAuthenticationRequest() {
        ClientID clientID = new ClientID(taraConfigurationProperties.getClientId());
        URI callback = ssoConfigurationProperties.getCallbackUri();
        State state = new State();
        Nonce nonce = new Nonce();
        ResponseType responseType = new ResponseType(CODE);
        Scope scope = new Scope(OPENID);
        return new AuthenticationRequest.Builder(responseType, scope, clientID, callback)
                .endpointURI(taraMetadataService.getMetadata().getAuthorizationEndpointURI())
                .state(state)
                .nonce(nonce)
                .build();
    }

    public SignedJWT requestIdToken(String code) {
        try {
            TokenRequest tokenRequest = createTokenRequest(code);
            HTTPRequest httpRequest = tokenRequest.toHTTPRequest();
            httpRequest.setConnectTimeout(DEFAULT_HTTP_CONNECT_TIMEOUT); // TODO: Configurable
            httpRequest.setReadTimeout(DEFAULT_HTTP_READ_TIMEOUT); // TODO: Configurable
            httpRequest.setSSLSocketFactory(trustContext.getSocketFactory());
            HTTPResponse response = httpRequest.send();

            TokenResponse tokenResponse = OIDCTokenResponseParser.parse(response);
            if (!tokenResponse.indicatesSuccess()) {
                ErrorObject errorObject = tokenResponse.toErrorResponse().getErrorObject();
                String errorMessage = "ErrorCode:" + errorObject.getCode() +
                        ", Error description:" + errorObject.getDescription() +
                        ", Status Code:" + errorObject.getHTTPStatusCode();
                throw new TaraException(errorMessage); // TODO: Needs more work
            }

            OIDCTokenResponse successResponse = (OIDCTokenResponse) tokenResponse.toSuccessResponse();

            JWT idToken = successResponse.getOIDCTokens().getIDToken();
            if (!(idToken instanceof SignedJWT)) {
                throw new SsoException("Unsigned ID Token");
            }
            return (SignedJWT) idToken;
        } catch (IOException | ParseException ex) {
            throw new SsoException("Unable to request ID Token", ex);
        }
    }

    public void verifyIdToken(@NonNull String nonce, @NonNull SignedJWT idToken) {
        try {
            IDTokenValidator verifier = taraMetadataService.getIDTokenValidator();
            IDTokenClaimsSet claimsSet = verifier.validate(idToken, Nonce.parse(nonce));
            // TODO: https://e-gov.github.io/TARA-Doku/TehnilineKirjeldus#51-identsust%C3%B5endi-kontrollimine

        } catch (BadJOSEException ex) {
            throw new TaraException("Unable to validate ID Token", ex);
        } catch (JOSEException ex) {
            throw new SsoException("Unable to parse ID Token", ex);
        }
    }

    private TokenRequest createTokenRequest(String code) {
        AuthorizationCode authorizationCode = new AuthorizationCode(code);
        URI callback = ssoConfigurationProperties.getCallbackUri();
        AuthorizationGrant codeGrant = new AuthorizationCodeGrant(authorizationCode, callback);
        ClientID clientID = new ClientID(taraConfigurationProperties.getClientId());
        Secret clientSecret = new Secret(taraConfigurationProperties.getClientSecret());
        ClientAuthentication clientAuth = new ClientSecretBasic(clientID, clientSecret);
        OIDCProviderMetadata metadata = taraMetadataService.getMetadata();
        URI tokenEndpoint = metadata.getTokenEndpointURI();
        return new TokenRequest(tokenEndpoint, clientAuth, codeGrant);
    }
}
