package ca.uhn.fhir.jpa.starter;

import ca.uhn.fhir.context.FhirContext;
import ca.uhn.fhir.rest.client.api.IGenericClient;
import ca.uhn.fhir.rest.client.api.ServerValidationModeEnum;
import ca.uhn.fhir.rest.client.interceptor.BearerTokenAuthInterceptor;
import ca.uhn.fhir.rest.client.interceptor.LoggingInterceptor;
import ca.uhn.fhir.rest.server.exceptions.AuthenticationException;
import org.hl7.fhir.r4.model.*;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.web.server.LocalServerPort;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.test.context.junit.jupiter.SpringExtension;

import io.restassured.RestAssured;
import io.restassured.response.Response;

import static org.junit.jupiter.api.Assertions.assertEquals;


@ExtendWith(SpringExtension.class)
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT, classes = Application.class, properties =
  {
    "spring.batch.job.enabled=false",
    "spring.datasource.url=jdbc:h2:mem:dbr4",
    "hapi.fhir.fhir_version=r4",
    "hapi.fhir.subscription.websocket_enabled=true",
    "hapi.fhir.empi_enabled=true",
    //Override is currently required when using Empi as the construction of the Empi beans are ambiguous as they are constructed multiple places. This is evident when running in a spring boot environment
    "spring.main.allow-bean-definition-overriding=true",
    // Use MockLab.io's OAuth server for JWK
    "spring.security.oauth2.resourceserver.jwt.jwk-set-uri=https://oauth.mocklab.io/.well-known/jwks.json"
    // 
  })
@EnableAutoConfiguration
public class ExampleServerOauth {

  private static final org.slf4j.Logger ourLog = org.slf4j.LoggerFactory.getLogger(ExampleServerDstu2IT.class);
  private IGenericClient ourClient;
  private FhirContext ourCtx;

  @LocalServerPort
  private int port;

  @Test
  void testConnectOauthUnauthorized() {

    try {
        ourClient.search().forResource(Person.class).execute();
        throw new AssertionError("Expected Unauthorized.");
    } catch (AuthenticationException err) {
        // Expected.
    }
  }
  
  @Test
  void testConnectOauthAuthorized() {
    String token = obtainAccessToken("unused_scope");
      
    ourClient.registerInterceptor(new BearerTokenAuthInterceptor(token));
    ourClient.search().forResource(Person.class).execute();

  }  

  private String obtainAccessToken(String scopes) {
        // obtain authentication url with custom codes from mocklab
        Response response = RestAssured.given()
            .redirects()
            .follow(false)
            .urlEncodingEnabled(true)
            .param("email", "foo@bar.com")
            .param("password", "hello")
            .param("clientId", "Client")
            .param("redirect_uri", "http://localhost:" + port)
            .post("https://oauth.mocklab.io/login");
        assertEquals(HttpStatus.FOUND.value(), response.getStatusCode());
        
        // extract authorization code
        String location = response.getHeader(HttpHeaders.LOCATION);
        String code = location.split("code=")[1].split("&")[0];

        // get access token from mocklab
        response = RestAssured.given()
            .urlEncodingEnabled(false)
            .param("grant_type", "authorization_code")
            .param("code", code)
            .param("client_id", "Client")
            .param("client_secret", "ClientSecret")
            .param("redirect_uri", "http://localhost:" + port)                
            .post("https://oauth.mocklab.io/oauth/token");

        return response.jsonPath()
            .getString("access_token");
    }
  
  @BeforeEach
  void beforeEach() {
    ourCtx = FhirContext.forR4();
    ourCtx.getRestfulClientFactory().setServerValidationMode(ServerValidationModeEnum.NEVER);
    ourCtx.getRestfulClientFactory().setSocketTimeout(1200 * 1000);
    String ourServerBase = "http://localhost:" + port + "/fhir/";
    ourClient = ourCtx.newRestfulGenericClient(ourServerBase);
    ourClient.registerInterceptor(new LoggingInterceptor(true));
  }
}
