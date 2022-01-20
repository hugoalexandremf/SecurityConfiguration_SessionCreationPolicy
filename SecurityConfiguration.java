package TestingSessionCreationPolicy.Config;

import TestingSessionCreationPolicy.Init;
import TestingSessionCreationPolicy.Service.X509CustomUserDetailsService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.actuate.autoconfigure.security.servlet.EndpointRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;

@Configuration
@EnableGlobalMethodSecurity(prePostEnabled = true)
@EnableWebSecurity
public class SecurityConfiguration {

   @Configuration
   @Order(1)
   public static class X509ClientSessionCreationPolicyAlways extends WebSecurityConfigurerAdapter {

        @Autowired
        private X509CUDService x509CustomUserDetailsService;

        @Override
        protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        }

        @Override
        protected void configure(HttpSecurity http) throws Exception {
             http
                  .antMatcher("/testMVCController/**")
                  .csrf().disable()
                  .authorizeRequests()
                  .anyRequest().authenticated()
                  .and()
                  .x509()
                  .authenticationUserDetailsService(x509CustomUserDetailsService)
                  .and()
                  .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.ALWAYS);
        }

   }

   @Configuration
   @Order(2)
   public static class X509ClientSessionCreationPolicyStateless extends WebSecurityConfigurerAdapter {

        @Autowired
        private X509CUDService X509CUDService ;

        @Override
        protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        }

        @Override
        protected void configure(HttpSecurity http) throws Exception {
             http
                  .antMatcher("/**")
                  .csrf().disable()
                  .authorizeRequests()
                  .anyRequest().authenticated()
                  .and()
                  .x509()
                  .authenticationUserDetailsService(x509CustomUserDetailsService);
                  .and()
                  .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);
        }

        @Override
        @Bean
        public AuthenticationManager authenticationManagerBean() throws Exception {
             return super.authenticationManagerBean();
        }

   }
}
