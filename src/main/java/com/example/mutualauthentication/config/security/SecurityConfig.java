package com.example.mutualauthentication.config.security;

import com.example.mutualauthentication.util.X509CertificateUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.access.AccessDeniedHandler;

import javax.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;

@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class SecurityConfig extends WebSecurityConfigurerAdapter {

	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http.csrf().disable()
			.authorizeRequests()
				.antMatchers("/css/**", "/js/**").permitAll()	
				.antMatchers("/").permitAll()	
				.anyRequest().authenticated()
				.and()
			.formLogin()
				.loginPage("/login")
					.defaultSuccessUrl("/home")
				.permitAll()
				.and()
	        .x509()
	        	.subjectPrincipalRegex("CN=(.*?)(?:,|$)")
	        	.userDetailsService(userDetailsService())
	        	.and()
	        .exceptionHandling()
	        	.accessDeniedHandler(accessDeniedHandler());
	}
	
	@Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
		PasswordEncoder encoder = PasswordEncoderFactories.createDelegatingPasswordEncoder();
        
		auth.inMemoryAuthentication()
        	.withUser("user").password(encoder.encode("user")).roles("USER")
        	.and()
        	.withUser("admin").password(encoder.encode("admin")).roles("USER", "ADMIN");
    }
	
	@Bean
    public UserDetailsService userDetailsService() {
        return new UserDetailsService() {
            
        	@Autowired
        	private HttpServletRequest request;

			@Override
            public UserDetails loadUserByUsername(String username) {
				X509Certificate[] certs = (X509Certificate[]) request.getAttribute("javax.servlet.request.X509Certificate");
				
				if (certs != null && certs.length > 0) {
					X509Certificate x509Certificate = certs[0];
					
					try {
						String cpf = X509CertificateUtils.getCpfFromSubjectAlternativeName(x509Certificate);
						System.out.println(cpf);
					} catch (CertificateParsingException | IOException e) {
						e.printStackTrace();
					}
				}	
				return new User(username, "", AuthorityUtils.commaSeparatedStringToAuthorityList("ROLE_USER"));
            }
        };
    }
	
	@Bean
	public AccessDeniedHandler accessDeniedHandler(){
	    return new com.example.mutualauthentication.config.security.CustomAccessDeniedHandler();
	}
	
}