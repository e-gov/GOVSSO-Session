package ee.ria.govsso.session.util;

import lombok.experimental.UtilityClass;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.Optional;

import static ee.ria.govsso.session.session.SsoCookie.COOKIE_NAME_GOVSSO;
import static java.util.Arrays.stream;

@UtilityClass
public class CookieUtil {

    /**
     * For this to work, it is expected to run Hydra and GOVSSO-Session behind a reverse proxy that exposes them under
     * the same domain. Only then will cookies set by Hydra also reach GOVSSO-Session.
     *
     * @param request
     * @param response
     */
    public void deleteHydraSessionCookie(HttpServletRequest request, HttpServletResponse response) {
        String cookieName = request.isSecure() ? "oauth2_authentication_session" : "oauth2_authentication_session_insecure";
        Cookie[] cookies = request.getCookies();
        if (cookies != null) {
            for (Cookie cookie : cookies) {
                if (cookie.getName().equals(cookieName)) {
                    Cookie newCookie = createCookie(cookieName, cookie.getValue());
                    response.addCookie(newCookie);
                }
            }
        }
    }

    public Cookie getCookie(HttpServletRequest request, String cookieName) {
        Cookie[] cookies = request.getCookies();
        if (cookies != null) {
            Optional<Cookie> cookie = stream(cookies).filter(c -> c.getName().equals(COOKIE_NAME_GOVSSO)).findFirst();
            return cookie.orElse(null);
        } else {
            return null;
        }
    }

    private Cookie createCookie(String name, String value) {
        Cookie cookie = new Cookie(name, value);
        cookie.setPath("/");
        cookie.setMaxAge(0);
        return cookie;
    }
}
