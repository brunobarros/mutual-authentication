package com.example.mutualauthentication.controller;

import com.example.mutualauthentication.util.X509CertificateUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.RequestMapping;

import javax.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.security.Principal;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;

@Controller
@RequestMapping(value = "/home")
public class HomeController {
	
	private static Logger log = LoggerFactory.getLogger(HomeController.class);
	
	@PreAuthorize("hasAuthority('ROLE_USER')")
	@RequestMapping
    public String index(Model model, Principal principal, HttpServletRequest request) {
    	Authentication authentication = (Authentication) principal;
		UserDetails currentUser = (UserDetails) authentication.getPrincipal();
		
		model.addAttribute("username", currentUser.getUsername());
		
		if (authentication.getCredentials() instanceof X509Certificate) {
			model.addAttribute("credentials", authentication.getCredentials());

			X509Certificate[] certs = (X509Certificate[]) request.getAttribute("javax.servlet.request.X509Certificate");
			
			if (certs != null && certs.length > 0) {
				X509Certificate x509Certificate = certs[0];
				
				try {
					String cpf = X509CertificateUtils.getCpfFromSubjectAlternativeName(x509Certificate);
					model.addAttribute("cpf", cpf);

					String email = X509CertificateUtils.getEmailFromSanX509Certificate(x509Certificate);
					model.addAttribute("email", email);
				} catch (CertificateParsingException | IOException e) {
					e.printStackTrace();
					log.error(e.getMessage());
				} catch (Exception e) {
					e.printStackTrace();
					log.error(e.getMessage());
				}
			}	
		}
		
        return "home/index";
    }
	
}