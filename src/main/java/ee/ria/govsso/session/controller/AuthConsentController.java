package ee.ria.govsso.session.controller;

import ee.ria.govsso.session.service.hydra.HydraService;
import ee.ria.govsso.session.session.SsoSession;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Controller;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.SessionAttribute;
import org.springframework.web.servlet.view.RedirectView;

import javax.validation.constraints.Pattern;

import static ee.ria.govsso.session.session.SsoSession.SSO_SESSION;

@Slf4j
@Validated
@Controller
@RequiredArgsConstructor
public class AuthConsentController {
    public static final String AUTH_CONSENT_REQUEST_MAPPING = "/auth/consent";

    private final HydraService hydraService;

    @GetMapping(value = AUTH_CONSENT_REQUEST_MAPPING, produces = MediaType.TEXT_HTML_VALUE)
    public RedirectView authConsent(
            @RequestParam(name = "consent_challenge")
            @Pattern(regexp = "^[a-f0-9]{32}$") String consentChallenge,
            @SessionAttribute(value = SSO_SESSION, required = false) SsoSession ssoSession) {

        String redirectUrl = hydraService.acceptConsent(consentChallenge, ssoSession);

        return new RedirectView(redirectUrl);
    }
}
