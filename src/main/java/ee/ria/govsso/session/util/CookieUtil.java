package ee.ria.govsso.session.util;

import lombok.experimental.UtilityClass;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

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

    private Cookie createCookie(String name, String value) {
        Cookie cookie = new Cookie(name, value);
        cookie.setPath("/");
        cookie.setMaxAge(0);
        return cookie;
    }
}
