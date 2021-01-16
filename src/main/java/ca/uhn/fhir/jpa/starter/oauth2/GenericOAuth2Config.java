/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package ca.uhn.fhir.jpa.starter.oauth2;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;

@Configuration
@EnableWebSecurity
public class GenericOAuth2Config extends WebSecurityConfigurerAdapter {

    @Value("${spring.security.oauth2.resourceserver.opaquetoken.introspection-uri:}")
    String opaqueIntrospectionUri;

    @Value("${spring.security.oauth2.resourceserver.opaquetoken.client-id:}")
    String opaqueClientId;

    @Value("${spring.security.oauth2.resourceserver.opaquetoken.client-secret:}")
    String opaqueClientSecret;

    @Value("${spring.security.oauth2.resourceserver.jwt.jwk-set-uri:}")
    String jwtJwkSetUri; 
    
    @Value("${spring.security.oauth2.resourceserver.jwt.issuer-uri:}")
    String jwtIssuerUri;     
    
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        /* Authenticate with the appropriate method if the values are set.
           We allow any authenticated user full access for now, but if specific
           tiers of access are required for different scopes that could be configured
           and added here.
        */
        if (!(opaqueIntrospectionUri.isEmpty())) {
            http.csrf()
                .disable()
                .authorizeRequests(authz -> authz.anyRequest().authenticated())
                .oauth2ResourceServer(oauth2 -> oauth2
                    .opaqueToken(token -> token.introspectionUri(this.opaqueIntrospectionUri)
                    .introspectionClientCredentials(this.opaqueClientId, this.opaqueClientSecret)));        
        } else if (!(this.jwtJwkSetUri.isEmpty()) || !(this.jwtIssuerUri.isEmpty())){
            http.csrf()
                .disable()
                .authorizeRequests(authz -> authz.anyRequest().authenticated())
                .oauth2ResourceServer(oauth2 -> oauth2.jwt());       
        } else {
            http.csrf()
                .disable()
                .authorizeRequests()
                .anyRequest()
                .permitAll();
        }
    }
}
