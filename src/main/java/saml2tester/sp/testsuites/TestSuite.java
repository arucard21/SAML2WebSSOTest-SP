package saml2tester.sp.testsuites;

import java.io.BufferedReader;
import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.List;
import java.util.UUID;

import org.joda.time.DateTime;
import org.opensaml.Configuration;
import org.opensaml.DefaultBootstrap;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.AttributeStatement;
import org.opensaml.saml2.core.AttributeValue;
import org.opensaml.saml2.core.Audience;
import org.opensaml.saml2.core.AudienceRestriction;
import org.opensaml.saml2.core.AuthnContext;
import org.opensaml.saml2.core.AuthnContextClassRef;
import org.opensaml.saml2.core.AuthnStatement;
import org.opensaml.saml2.core.Conditions;
import org.opensaml.saml2.core.Issuer;
import org.opensaml.saml2.core.Response;
import org.opensaml.saml2.core.Status;
import org.opensaml.saml2.core.StatusCode;
import org.opensaml.saml2.core.Subject;
import org.opensaml.saml2.core.SubjectConfirmation;
import org.opensaml.saml2.core.SubjectConfirmationData;
import org.opensaml.saml2.core.impl.AttributeBuilder;
import org.opensaml.xml.ConfigurationException;
import org.opensaml.xml.XMLObjectBuilderFactory;
import org.opensaml.xml.schema.XSString;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Document;

import saml2tester.common.SAMLAttribute;
import saml2tester.common.TestStatus;
import saml2tester.common.standardNames.MD;
import saml2tester.common.standardNames.SAMLmisc;
import saml2tester.sp.LoginAttempt;
import saml2tester.sp.SPConfiguration;
import saml2tester.sp.SPTestRunner;

/**
 * This is the module containing the abstract base classes that are required in every test suite, as well as any methods that 
 * would be useful for any test suite. All test suites should inherit the classes in this module and import the necessary methods 
 * and variables.
 * 
 * Each test case should be defined in the testcases variable below. See the documentation there for more information.
 * 
 * SAML2test uses a mock IdP to test against. Each test suite can specify the configuration of the mock IdP separately.
 * 
 * - The metadata that the mock IdP should use can be generated in the get_idp_metadata() method. The metadata can be generated using 
 * the builders in saml2test.saml_builders.metadata_builders module.
 * 
 * - The SAML Responses that should be sent, have to be defined in each SAML_Response_Test class. It must be returned by the 
 * test_response() method. The SAML Responses can be generated using the builders in saml2test.saml_builders.response_builders module.
 * 
 * @author: Riaas Mokiem
 */
public abstract class TestSuite {
	/**
	 * Logger for this class
	 */
	private final Logger logger = LoggerFactory.getLogger(SPTestRunner.class);

	/**
	 * Retrieve the protocol on which the mock IdP should be available
	 * 
	 * @return the protocol on which the mock IdP should be available
	 */
	public abstract String getMockIdPProtocol();
		
	/**
	 * Retrieve the URL on which the mock IdP should be available
	 * 
	 * @return the URL on which the mock IdP should be available
	 */
	public abstract String getMockIdPHostname();

	/**
	 * Retrieve the port on which the mock IdP should be available
	 * 
	 * @return the port on which the mock IdP should be available
	 */
	public abstract int getMockIdPPort();

	/**
	 * Retrieve the relative path on which the mock IdP should listen to SSO connections
	 * 
	 * @return the the relative path on which the mock IdP listens to SSO connections
	 */
	public abstract String getMockIdPSsoPath();

	/**
	 * Retrieves the EntityID for the mock IdP
	 * 
	 * @return the EntityID for the mock IdP
	 */
	public abstract String getmockIdPEntityID();

	public String getMockIdPURL(){
		URL mockIdPURL = null;
		try {
			mockIdPURL = new URL(getMockIdPProtocol(), getMockIdPHostname(), getMockIdPPort(), getMockIdPSsoPath());
		} catch (MalformedURLException e) {
			logger.error("The URL of the mock IdP was malformed", e);
		}
		
		if(mockIdPURL != null){
			return mockIdPURL.toString();
		}
		else{
			return null;
		}
	}
	
	/**
	 * Get the IdP metadata that should be used in the mock IdP for this test suite.
	 * 
	 * This allows you to use specific IdP metadata for each test suite, which is defined in this method. 
	 * 
	 * @return: the metadata XML that should be used by the mock IdP when running tests from this test suite
	 */
	public abstract String getIdPMetadata();

	/**
	 * Retrieve the X.509 Certificate that should be used by the mock IdP.
	 * 
	 * @param certLocation contains the location of the certificate file that should be used (e.g. "keys/mycert.pem")
	 * 			Can be null or empty, in which case a default certificate is used
	 * @return: the X.509 Certificate in PEM format
	 */
	public String getIdPCertificate(String certLocation){
		String cert = "";
		
		// if a specific certificate location is provided, use the certificate from that location
		if ( certLocation != null &&  !certLocation.isEmpty() ){
			Path certPath = Paths.get(certLocation); 
			try {
				BufferedReader reader = Files.newBufferedReader(certPath, Charset.defaultCharset());
				String line;
				while ( (line = reader.readLine()) != null){
					cert += line + "\n";
				}
			} catch (IOException e) {
				logger.error("IOException occurred while accessing the user-provided file for the mock IdP's X.509 Certificate", e);
			}
		}
		else {
			// use the default certificate
			cert = 	"-----BEGIN CERTIFICATE-----\r\n" + 
					"MIIC8jCCAlugAwIBAgIJAJHg2V5J31I8MA0GCSqGSIb3DQEBBQUAMFoxCzAJBgNV\r\n" + 
					"BAYTAlNFMQ0wCwYDVQQHEwRVbWVhMRgwFgYDVQQKEw9VbWVhIFVuaXZlcnNpdHkx\r\n" + 
					"EDAOBgNVBAsTB0lUIFVuaXQxEDAOBgNVBAMTB1Rlc3QgU1AwHhcNMDkxMDI2MTMz\r\n" + 
					"MTE1WhcNMTAxMDI2MTMzMTE1WjBaMQswCQYDVQQGEwJTRTENMAsGA1UEBxMEVW1l\r\n" + 
					"YTEYMBYGA1UEChMPVW1lYSBVbml2ZXJzaXR5MRAwDgYDVQQLEwdJVCBVbml0MRAw\r\n" + 
					"DgYDVQQDEwdUZXN0IFNQMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDkJWP7\r\n" + 
					"bwOxtH+E15VTaulNzVQ/0cSbM5G7abqeqSNSs0l0veHr6/ROgW96ZeQ57fzVy2MC\r\n" + 
					"FiQRw2fzBs0n7leEmDJyVVtBTavYlhAVXDNa3stgvh43qCfLx+clUlOvtnsoMiiR\r\n" + 
					"mo7qf0BoPKTj7c0uLKpDpEbAHQT4OF1HRYVxMwIDAQABo4G/MIG8MB0GA1UdDgQW\r\n" + 
					"BBQ7RgbMJFDGRBu9o3tDQDuSoBy7JjCBjAYDVR0jBIGEMIGBgBQ7RgbMJFDGRBu9\r\n" + 
					"o3tDQDuSoBy7JqFepFwwWjELMAkGA1UEBhMCU0UxDTALBgNVBAcTBFVtZWExGDAW\r\n" + 
					"BgNVBAoTD1VtZWEgVW5pdmVyc2l0eTEQMA4GA1UECxMHSVQgVW5pdDEQMA4GA1UE\r\n" + 
					"AxMHVGVzdCBTUIIJAJHg2V5J31I8MAwGA1UdEwQFMAMBAf8wDQYJKoZIhvcNAQEF\r\n" + 
					"BQADgYEAMuRwwXRnsiyWzmRikpwinnhTmbooKm5TINPE7A7gSQ710RxioQePPhZO\r\n" + 
					"zkM27NnHTrCe2rBVg0EGz7QTd1JIwLPvgoj4VTi/fSha/tXrYUaqc9AqU1kWI4WN\r\n" + 
					"+vffBGQ09mo+6CffuFTZYeOhzP/2stAPwCTU4kxEoiy0KpZMANI=\r\n" + 
					"-----END CERTIFICATE-----";
		}
		return cert;
	}

    /**
     * Retrieve RSA private key that corresponds to the X.509 Certificate that is used by the mock IdP
     * 
     * @param keyLocation contains the location of the private key file that should be used (e.g. "keys/mykey.pem"). 
     * 			Can be null or empty, in which case a default private key is used 
     * @return: the RSA private key in PEM format
     */
	public String getIdPPrivateKey(String keyLocation){
		String key = "";
		
		// if a specific key location is provided, use the private key from that location
		if ( keyLocation != null &&  !keyLocation.isEmpty() ){
			Path keyPath = Paths.get(keyLocation); 
			try {
				BufferedReader reader = Files.newBufferedReader(keyPath, Charset.defaultCharset());
				String line;
				while ( (line = reader.readLine()) != null){
					key += line + "\n";
				}
			} catch (IOException e) {
				logger.error("IOException occurred while accessing the user-provided file for the mock IdP's private key", e);
			}
		}
		else {
			// use the default private key
			key = 	"-----BEGIN RSA PRIVATE KEY-----\r\n" + 
					"MIICXAIBAAKBgQDkJWP7bwOxtH+E15VTaulNzVQ/0cSbM5G7abqeqSNSs0l0veHr\r\n" + 
					"6/ROgW96ZeQ57fzVy2MCFiQRw2fzBs0n7leEmDJyVVtBTavYlhAVXDNa3stgvh43\r\n" + 
					"qCfLx+clUlOvtnsoMiiRmo7qf0BoPKTj7c0uLKpDpEbAHQT4OF1HRYVxMwIDAQAB\r\n" + 
					"AoGAbx9rKH91DCw/ZEPhHsVXJ6cYHxGcMoAWvnMMC9WUN+bNo4gNL205DLfsxXA1\r\n" + 
					"jqXFXZj3+38vSFumGPA6IvXrN+Wyp3+Lz3QGc4K5OdHeBtYlxa6EsrxPgvuxYDUB\r\n" + 
					"vx3xdWPMjy06G/ML+pR9XHnRaPNubXQX3UxGBuLjwNXVmyECQQD2/D84tYoCGWoq\r\n" + 
					"5FhUBxFUy2nnOLKYC/GGxBTX62iLfMQ3fbQcdg2pJsB5rrniyZf7UL+9FOsAO9k1\r\n" + 
					"8DO7G12DAkEA7Hkdg1KEw4ZfjnnjEa+KqpyLTLRQ91uTVW6kzR+4zY719iUJ/PXE\r\n" + 
					"PxJqm1ot7mJd1LW+bWtjLpxs7jYH19V+kQJBAIEpn2JnxdmdMuFlcy/WVmDy09pg\r\n" + 
					"0z0imdexeXkFmjHAONkQOv3bWv+HzYaVMo8AgCOksfEPHGqN4eUMTfFeuUMCQF+5\r\n" + 
					"E1JSd/2yCkJhYqKJHae8oMLXByNqRXTCyiFioutK4JPYIHfugJdLfC4QziD+Xp85\r\n" + 
					"RrGCU+7NUWcIJhqfiJECQAIgUAzfzhdj5AyICaFPaOQ+N8FVMLcTyqeTXP0sIlFk\r\n" + 
					"JStVibemTRCbxdXXM7OVipz1oW3PBVEO3t/VyjiaGGg=\r\n" + 
					"-----END RSA PRIVATE KEY-----";
		}
		return key;
	}
	
	/**
	 * Create a minimal SAML Response.
	 * 
	 * This creates the minimal SAML Response that is valid for the Web SSO profile.
	 * It will:
	 * - generate random UUID-based ID's for the Assertion and Response
	 * - use the AssertionConsumerService URL for the POST binding as Recipient
	 * - use a validity period of 15 minutes from now
	 * - use the bearer method for SubjectConfirmation
	 * - set the AudienceRestriction to the SP Entity ID
	 * - use the Password authentication context
	 * - set all IssueInstant attributes to the current date and time
	 * 
	 * You can edit the Response as you see fit to customize it to your needs
	 * 
	 * @return the minimal SAML Response
	 */
	public Response createMinimalWebSSOResponse(){
		SPConfiguration sp = SPTestRunner.getSPConfig();
		try {
			DefaultBootstrap.bootstrap();
		} catch (ConfigurationException e) {
			logger.error("Could not bootstrap OpenSAML", e);
		}
		XMLObjectBuilderFactory builderfac = Configuration.getBuilderFactory();
		Response response = (Response) builderfac.getBuilder(Response.DEFAULT_ELEMENT_NAME).buildObject(Response.DEFAULT_ELEMENT_NAME);
		Assertion assertion = (Assertion) builderfac.getBuilder(Assertion.DEFAULT_ELEMENT_NAME).buildObject(Assertion.DEFAULT_ELEMENT_NAME);
		Issuer issuer = (Issuer) builderfac.getBuilder(Issuer.DEFAULT_ELEMENT_NAME).buildObject(Issuer.DEFAULT_ELEMENT_NAME);
		Status status = (Status) builderfac.getBuilder(Status.DEFAULT_ELEMENT_NAME).buildObject(Status.DEFAULT_ELEMENT_NAME);
		StatusCode statuscode = (StatusCode) builderfac.getBuilder(StatusCode.DEFAULT_ELEMENT_NAME).buildObject(StatusCode.DEFAULT_ELEMENT_NAME);
		Subject subject = (Subject) builderfac.getBuilder(Subject.DEFAULT_ELEMENT_NAME).buildObject(Subject.DEFAULT_ELEMENT_NAME);
		SubjectConfirmation subjectconf = (SubjectConfirmation) builderfac.getBuilder(SubjectConfirmation.DEFAULT_ELEMENT_NAME).buildObject(SubjectConfirmation.DEFAULT_ELEMENT_NAME);
		SubjectConfirmationData subjectconfdata = (SubjectConfirmationData) builderfac.getBuilder(SubjectConfirmationData.DEFAULT_ELEMENT_NAME).buildObject(SubjectConfirmationData.DEFAULT_ELEMENT_NAME);
		Conditions conditions = (Conditions) builderfac.getBuilder(Conditions.DEFAULT_ELEMENT_NAME).buildObject(Conditions.DEFAULT_ELEMENT_NAME);
		AudienceRestriction audRes = (AudienceRestriction) builderfac.getBuilder(AudienceRestriction.DEFAULT_ELEMENT_NAME).buildObject(AudienceRestriction.DEFAULT_ELEMENT_NAME);
		Audience aud = (Audience) builderfac.getBuilder(Audience.DEFAULT_ELEMENT_NAME).buildObject(Audience.DEFAULT_ELEMENT_NAME);
		AuthnStatement authnstatement = (AuthnStatement) builderfac.getBuilder(AuthnStatement.DEFAULT_ELEMENT_NAME).buildObject(AuthnStatement.DEFAULT_ELEMENT_NAME);
		AuthnContext authncontext = (AuthnContext) builderfac.getBuilder(AuthnContext.DEFAULT_ELEMENT_NAME).buildObject(AuthnContext.DEFAULT_ELEMENT_NAME);
		AuthnContextClassRef authncontextclassref = (AuthnContextClassRef) builderfac.getBuilder(AuthnContextClassRef.DEFAULT_ELEMENT_NAME).buildObject(AuthnContextClassRef.DEFAULT_ELEMENT_NAME);

		// create status for Response
		statuscode.setValue(SAMLmisc.STATUS_SUCCESS);
		status.setStatusCode(statuscode);
		// create Issuer for Assertion 
		issuer.setValue(getmockIdPEntityID());
		// create Subject for Assertion
		subjectconfdata.setRecipient(sp.getMDACSLocation(SAMLmisc.BINDING_HTTP_POST));
		subjectconfdata.setNotOnOrAfter(DateTime.now().plusMinutes(15));
		subjectconf.setSubjectConfirmationData(subjectconfdata);
		subjectconf.setMethod(SAMLmisc.CONFIRMATION_METHOD_BEARER);
		subject.getSubjectConfirmations().add(subjectconf);
		// create Conditions for Assertion
		aud.setAudienceURI(sp.getMDAttribute(MD.ENTITYDESCRIPTOR, MD.ENTITYID));
		audRes.getAudiences().add(aud);
		conditions.getAudienceRestrictions().add(audRes);
		// create AuthnStatement for Assertion
		authncontextclassref.setAuthnContextClassRef(SAMLmisc.AUTHNCONTEXT_PASSWORD);
		authncontext.setAuthnContextClassRef(authncontextclassref);
		authnstatement.setAuthnContext(authncontext);
		authnstatement.setAuthnInstant(DateTime.now());
		// add created elements to Assertion
		assertion.setID("_"+UUID.randomUUID().toString());
		assertion.setIssueInstant(DateTime.now());
		assertion.setIssuer(issuer);
		assertion.setSubject(subject);
		assertion.setConditions(conditions);
		assertion.getAuthnStatements().add(authnstatement);
		
		// add created elements to Response
		response.setID("_"+UUID.randomUUID().toString());
		response.setIssueInstant(DateTime.now());
		response.getAssertions().add(assertion);
		response.setStatus(status);
		
		return response;
	}
	
	/**
	 * Add the attributes configured for the target SP to the Assertion in an AttributeStatement
	 */
	public void addTargetSPAttributes(Assertion assertion){
		SPConfiguration sp = SPTestRunner.getSPConfig();
		
		try {
			DefaultBootstrap.bootstrap();
		} catch (ConfigurationException e) {
			logger.error("Could not bootstrap OpenSAML", e);
		}
		XMLObjectBuilderFactory builderfac = Configuration.getBuilderFactory();
		// add attributes to the Response
		AttributeStatement attrStat = (AttributeStatement) builderfac.getBuilder(AttributeStatement.DEFAULT_ELEMENT_NAME).buildObject(AttributeStatement.DEFAULT_ELEMENT_NAME);
		AttributeBuilder attrbuilder = (AttributeBuilder) builderfac.getBuilder(org.opensaml.saml2.core.Attribute.DEFAULT_ELEMENT_NAME);
		List<SAMLAttribute> attributes = sp.getAttributes();
		// add all attributes that were configured for the target SP to the attribute statement
		for (SAMLAttribute attr : attributes){
			// build the attribute
			org.opensaml.saml2.core.Attribute attribute = attrbuilder.buildObject();
			// set the name to the attribute name that was configured for the target SP
			attribute.setName(attr.getAttributeName());
			// same for the nameformat
			attribute.setNameFormat(attr.getNameFormat());
			// create the AttributeValue node, which is the same as xs:any but with the AttributeValue tag name
			XSString attrval = (XSString) builderfac.getBuilder(XSString.TYPE_NAME).buildObject(AttributeValue.DEFAULT_ELEMENT_NAME, XSString.TYPE_NAME);
			// set the value of the AttributeValue
			attrval.setValue(attr.getAttributeValue());
			// add the AttributeValue to the Attribute
			attribute.getAttributeValues().add(attrval);
			// add the Attribute to the AttributeStatement
			attrStat.getAttributes().add(attribute);
		}
		assertion.getAttributeStatements().add(attrStat);
	}
	
	/**
	 * The interface for all test cases. Defines the methods that are required for the test runner to correctly run
	 * the test case.
	 * 
	 * In the test case you can define what should be checked in the SAML SP Metadata or in the SAML Request. You can also
	 * provide LoginAttempt objects that specify the logins attempts that should be tested on the SP.  
	 * 
	 * @author RiaasM
	 *
	 */
	public interface TestCase{

		/**
		 * Retrieve a description of the test case
		 * 
		 * @return a description of this test case
		 */
		String getDescription();
		
		/**
		 * Retrieve the message that should be reported when the test passes.
		 * 
		 * @return the message for when the test passes
		 */
		String getSuccessMessage();
		
		/**
		 * Retrieve the message that should be reported when the test fails.
		 * 
		 * @return the message for when the test fails
		 */
		String getFailedMessage();
	}
	
	public interface ConfigTestCase extends TestCase {
		
		/**
		 * Check the provided configuration.  
		 * 
		 * @return the status of the test
		 */
		TestStatus checkConfig(SPConfiguration config);
	}

	public interface MetadataTestCase extends TestCase {
		
		/**
		 * Check the provided metadata.  
		 * 
		 * @return the status of the test
		 */
		TestStatus checkMetadata(Document metadata);
	}
	
	public interface RequestTestCase extends TestCase {

		/**
		 * Check the provided request for the provided binding
		 * 
		 * @return the status of the test
		 */
		TestStatus checkRequest(String request, String binding);
	}

	public interface LoginTestCase extends TestCase {

		/**
		 * Retrieve the list of login attempts that should be tested on the SP.
		 * 
		 * You should create a class that implements the LoginAttempt interface
		 * for each login attempt you wish to test. In that class, you should specify
		 * the SAML Response in the getResponse() method body. This method is provided
		 * with the SAML Request, which you can use to build your Response. You should
		 * then add a new instance of this class to a list and return that list. 
		 * 
		 * @param request is the SAML Request
		 * @return the list of login attempts that should be tested on the SP.
		 */
		List<LoginAttempt> getLoginAttempts();
		
		/**
		 * Check the results from your login attempts and return the appropriate status
		 * 
		 * @param loginResults is the list of results for each login attempt (true if successful, false otherwise)
		 * @return the status of the test
		 */
		TestStatus checkLoginResults(List<Boolean> loginResults);
	}
}