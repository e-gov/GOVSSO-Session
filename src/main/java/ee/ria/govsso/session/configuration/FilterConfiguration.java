package ee.ria.govsso.session.configuration;

import ee.ria.govsso.session.filter.DuplicateRequestParameterFilter;
import ee.ria.govsso.session.filter.RequestCorrelationFilter;
import ee.ria.govsso.session.session.SsoCookieSigner;
import org.springframework.boot.info.BuildProperties;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;

@Configuration
public class FilterConfiguration {

    @Bean
    public FilterRegistrationBean<RequestCorrelationFilter> requestCorrelationFilter(BuildProperties buildProperties, SsoCookieSigner ssoCookieSigner) {
        FilterRegistrationBean<RequestCorrelationFilter> registrationBean = new FilterRegistrationBean<>();
        registrationBean.setFilter(new RequestCorrelationFilter(buildProperties, ssoCookieSigner));
        registrationBean.setOrder(Ordered.LOWEST_PRECEDENCE - 1);
        return registrationBean;
    }

    @Bean
    public FilterRegistrationBean<DuplicateRequestParameterFilter> duplicateRequestParameterFilter() {
        FilterRegistrationBean<DuplicateRequestParameterFilter> registrationBean = new FilterRegistrationBean<>();
        registrationBean.setFilter(new DuplicateRequestParameterFilter());
        registrationBean.setOrder(Ordered.LOWEST_PRECEDENCE);
        return registrationBean;
    }
}
