package saml2webssotest.sp.testsuites;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.StringReader;
import java.net.MalformedURLException;
import java.net.URL;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyPair;
import java.security.Security;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

import javax.xml.namespace.QName;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMReader;
import org.joda.time.DateTime;
import org.opensaml.Configuration;
import org.opensaml.DefaultBootstrap;
import org.opensaml.common.xml.SAMLConstants;
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
import org.opensaml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml2.metadata.IDPSSODescriptor;
import org.opensaml.saml2.metadata.KeyDescriptor;
import org.opensaml.saml2.metadata.SingleSignOnService;
import org.opensaml.xml.ConfigurationException;
import org.opensaml.xml.Namespace;
import org.opensaml.xml.XMLObjectBuilderFactory;
import org.opensaml.xml.schema.XSString;
import org.opensaml.xml.security.credential.UsageType;
import org.opensaml.xml.security.keyinfo.KeyInfoGenerator;
import org.opensaml.xml.security.x509.BasicX509Credential;
import org.opensaml.xml.security.x509.X509Credential;
import org.opensaml.xml.security.x509.X509KeyInfoGeneratorFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import saml2webssotest.common.SAMLAttribute;
import saml2webssotest.common.SAMLUtil;
import saml2webssotest.common.StringPair;
import saml2webssotest.common.TestSuite;
import saml2webssotest.sp.SPConfiguration;
import saml2webssotest.sp.SPTestRunner;

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
public abstract class SPTestSuite implements TestSuite {
	/**
	 * Placeholders for indicating certain values in SAML Responses that are not yet available
	 * These should match the regex matching strings in SamlWebSSOHandler.
	 */
	public static final String PLACEHOLDER_REQUESTID = "[[requestID]]";
	public static final String PLACEHOLDER_ACSURL = "[[acsURL]]";
	/**
	 *  regex matching strings for replacing the placeholders in a SAML Response
	 *  These should match the placeholder variables in SPTestSuite
	 */
	public static final String REGEX_REQUESTID = "\\[\\[requestID\\]\\]";
	public static final String REGEX_ACSURL = "\\[\\[acsURL\\]\\]";
	
	/**
	 * Logger for this class
	 */
	private final Logger logger = LoggerFactory.getLogger(SPTestRunner.class);

	/**
	 * Retrieves the EntityID for the mock IdP
	 * 
	 * @return the EntityID for the mock IdP
	 */
	public String getmockIdPEntityID(){
		return "http://localhost:8080/sso";
	}
	
	@Override
	public URL getMockServerURL(){
		try {
			return new URL("http", "localhost", 8080, "/sso");
		} catch (MalformedURLException e) {
			logger.error("The URL of the mock IdP was malformed", e);
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
	public String getMockedMetadata() {
		try {
			DefaultBootstrap.bootstrap();
		} catch (ConfigurationException e) {
			logger.error("Could not bootstrap OpenSAML", e);
		}
		XMLObjectBuilderFactory xmlbuilderfac = Configuration.getBuilderFactory();		
		EntityDescriptor ed = (EntityDescriptor) xmlbuilderfac.getBuilder(EntityDescriptor.DEFAULT_ELEMENT_NAME).buildObject(EntityDescriptor.DEFAULT_ELEMENT_NAME);
		IDPSSODescriptor idpssod = (IDPSSODescriptor) xmlbuilderfac.getBuilder(IDPSSODescriptor.DEFAULT_ELEMENT_NAME).buildObject(IDPSSODescriptor.DEFAULT_ELEMENT_NAME);
		SingleSignOnService ssos = (SingleSignOnService) xmlbuilderfac.getBuilder(SingleSignOnService.DEFAULT_ELEMENT_NAME).buildObject(SingleSignOnService.DEFAULT_ELEMENT_NAME);
		KeyDescriptor keydescriptor = (KeyDescriptor) xmlbuilderfac.getBuilder(KeyDescriptor.DEFAULT_ELEMENT_NAME).buildObject(KeyDescriptor.DEFAULT_ELEMENT_NAME);
		
		ssos.setBinding(SAMLConstants.SAML2_REDIRECT_BINDING_URI);
		if (getMockServerURL() == null)
			return null;

		ssos.setLocation(getMockServerURL().toString());

		X509KeyInfoGeneratorFactory keyInfoGeneratorFactory = new X509KeyInfoGeneratorFactory();
		keyInfoGeneratorFactory.setEmitEntityCertificate(true);
		KeyInfoGenerator keyInfoGenerator = keyInfoGeneratorFactory.newInstance();
		try {
			// TODO add a command-line parameter that lets you configure a path to the X509 credentials
			keydescriptor.setKeyInfo(keyInfoGenerator.generate(getX509Credentials(null)));
		} catch (org.opensaml.xml.security.SecurityException e) {
			e.printStackTrace();
		}
		keydescriptor.setUse(UsageType.SIGNING);
		 
		idpssod.addSupportedProtocol(SAMLConstants.SAML20P_NS);
		idpssod.getSingleSignOnServices().add(ssos);
		idpssod.getKeyDescriptors().add(keydescriptor);
		
		ed.setEntityID(getmockIdPEntityID());
		ed.getRoleDescriptors().add(idpssod);
		
		// return the metadata as a string
		return SAMLUtil.toXML(ed);
	}

	@Override
	public X509Credential getX509Credentials(String certLocation){
		BasicX509Credential credentials = new BasicX509Credential();
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
		// retrieve the certificate
		X509Certificate idpCert = null;
		try {
			idpCert = (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(new ByteArrayInputStream(cert.getBytes()));
		} catch (CertificateException e) {
			e.printStackTrace();
		}
		if (idpCert == null){
			return null;
		}
		else{
			credentials.setEntityCertificate(idpCert);
			credentials.setPublicKey(idpCert.getPublicKey());
			credentials.setPrivateKey(getMockServerPrivateKey(certLocation));
			
			return credentials;
		}
	}

    /**
     * Retrieve RSA private key that corresponds to the X.509 Certificate that is used by the mock IdP
     * 
     * @param keyLocation contains the location of the private key file that should be used (e.g. "keys/mykey.pem"). 
     * 			Can be null or empty, in which case a default private key is used 
     * @return: the RSA private key in PEM format
     */
	private RSAPrivateKey getMockServerPrivateKey(String keyLocation){
		RSAPrivateKey privateKey = null;
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
		
		try {
			BufferedReader br = new BufferedReader(new StringReader(key));
			Security.addProvider(new BouncyCastleProvider());
			PEMReader pr = new PEMReader(br);
			KeyPair kp = (KeyPair) pr.readObject();
			pr.close();
			br.close();
			privateKey = (RSAPrivateKey) kp.getPrivate();
		} catch (IOException e) {
			e.printStackTrace();
		}
		
		return privateKey;
	}
	
	/**
	 * Create a minimal SAML Response.
	 * 
	 * This creates the minimal SAML Response that is valid for the Web SSO profile.
	 * It will:
	 * - contain a single Assertion
	 * - contain a valid AuthnStatement
	 * - generate random UUID-based ID's for the Assertion and Response
	 * - use the AssertionConsumerService URL for the POST binding as Recipient
	 * - use a validity period of 5 minutes from now (NotOnOrAfter)
	 * - use the bearer method for SubjectConfirmation
	 * - set the AudienceRestriction to the SP Entity ID
	 * - use the Password authentication context
	 * - set all IssueInstant attributes to the current date and time
	 * - set the Recipient to the provided ACS URL or, if IdP-initiated, the default ACS URL from the target SP metadata 
	 * - if requestID is provided, the InResponseTo attribute is set on SubjectConfirmationData and Response
	 * 
	 * You can edit the Response as you see fit to customize it to your needs
	 * 
	 * THe request ID and acsURL can be set to placeholder values so they can be 
	 * replaced with their correct values from the AuthnRequest when the Response
	 * is sent. This is available in PLACEHOLDER_REQUESTID or PLACEHOLDER_ACSURL.
	 * 
	 * @param requestID is the ID of the AuthnRequest that the response is intended 
	 * to answer, it should be null if the response is IdP-initiated.
	 * @param acsURL is the URL of the AssertionConsumerService which is intended 
	 * to be the Recipient of the Assertion in the Response, or null if 
	 * IdP-initiated in which case the default ACS URL will be selected from the
	 * target SP's metadata
	 * @return the minimal SAML Response required for the Web Browser SSO profile
	 */
	public Response createMinimalWebSSOResponse(String requestID, String acsURL){
		try {
			DefaultBootstrap.bootstrap();
		} catch (ConfigurationException e) {
			logger.error("Could not bootstrap OpenSAML", e);
		}
		XMLObjectBuilderFactory builderfac = Configuration.getBuilderFactory();
		Response response = (Response) builderfac.getBuilder(Response.DEFAULT_ELEMENT_NAME).buildObject(Response.DEFAULT_ELEMENT_NAME);
		Status status = (Status) builderfac.getBuilder(Status.DEFAULT_ELEMENT_NAME).buildObject(Status.DEFAULT_ELEMENT_NAME);
		StatusCode statuscode = (StatusCode) builderfac.getBuilder(StatusCode.DEFAULT_ELEMENT_NAME).buildObject(StatusCode.DEFAULT_ELEMENT_NAME);

		// create status for Response
		statuscode.setValue(StatusCode.SUCCESS_URI);
		status.setStatusCode(statuscode);
		// create the assertion
		Assertion assertion = createMinimalAssertion(requestID, acsURL);
		// add created elements to Response
		response.setID("_"+UUID.randomUUID().toString());
		response.setIssueInstant(DateTime.now());
		response.getAssertions().add(assertion);
		response.setStatus(status);
		if(requestID != null){
			response.setInResponseTo(requestID);
		}
		return response;
	}
	
	public Assertion createMinimalAssertion(String requestID, String acsURL){
		SPConfiguration sp = SPTestRunner.getInstance().getSPConfig();
		try {
			DefaultBootstrap.bootstrap();
		} catch (ConfigurationException e) {
			logger.error("Could not bootstrap OpenSAML", e);
		}
		XMLObjectBuilderFactory builderfac = Configuration.getBuilderFactory();
		Assertion assertion = (Assertion) builderfac.getBuilder(Assertion.DEFAULT_ELEMENT_NAME).buildObject(Assertion.DEFAULT_ELEMENT_NAME);
		Issuer issuer = (Issuer) builderfac.getBuilder(Issuer.DEFAULT_ELEMENT_NAME).buildObject(Issuer.DEFAULT_ELEMENT_NAME);
		Subject subject = (Subject) builderfac.getBuilder(Subject.DEFAULT_ELEMENT_NAME).buildObject(Subject.DEFAULT_ELEMENT_NAME);
		SubjectConfirmation subjectconf = (SubjectConfirmation) builderfac.getBuilder(SubjectConfirmation.DEFAULT_ELEMENT_NAME).buildObject(SubjectConfirmation.DEFAULT_ELEMENT_NAME);
		SubjectConfirmationData subjectconfdata = (SubjectConfirmationData) builderfac.getBuilder(SubjectConfirmationData.DEFAULT_ELEMENT_NAME).buildObject(SubjectConfirmationData.DEFAULT_ELEMENT_NAME);
		Conditions conditions = (Conditions) builderfac.getBuilder(Conditions.DEFAULT_ELEMENT_NAME).buildObject(Conditions.DEFAULT_ELEMENT_NAME);
		AudienceRestriction audRes = (AudienceRestriction) builderfac.getBuilder(AudienceRestriction.DEFAULT_ELEMENT_NAME).buildObject(AudienceRestriction.DEFAULT_ELEMENT_NAME);
		Audience aud = (Audience) builderfac.getBuilder(Audience.DEFAULT_ELEMENT_NAME).buildObject(Audience.DEFAULT_ELEMENT_NAME);
		AuthnStatement authnstatement = (AuthnStatement) builderfac.getBuilder(AuthnStatement.DEFAULT_ELEMENT_NAME).buildObject(AuthnStatement.DEFAULT_ELEMENT_NAME);
		AuthnContext authncontext = (AuthnContext) builderfac.getBuilder(AuthnContext.DEFAULT_ELEMENT_NAME).buildObject(AuthnContext.DEFAULT_ELEMENT_NAME);
		AuthnContextClassRef authncontextclassref = (AuthnContextClassRef) builderfac.getBuilder(AuthnContextClassRef.DEFAULT_ELEMENT_NAME).buildObject(AuthnContextClassRef.DEFAULT_ELEMENT_NAME);

		// create Issuer for Assertion 
		issuer.setValue(getmockIdPEntityID());
		// create Subject for Assertion
		if (acsURL == null){
			// use default ACS URL for IdP-initiated Responses
			subjectconfdata.setRecipient(sp.getApplicableACS(null).getValue());
		}
		else{
			subjectconfdata.setRecipient(acsURL);
		}
		subjectconfdata.setNotOnOrAfter(DateTime.now().plusMinutes(5));
		if (requestID != null){
			subjectconfdata.setInResponseTo(requestID);
		}
		subjectconf.setSubjectConfirmationData(subjectconfdata);
		subjectconf.setMethod(SubjectConfirmation.METHOD_BEARER);
		subject.getSubjectConfirmations().add(subjectconf);
		// create Conditions for Assertion
		aud.setAudienceURI(sp.getMDAttribute(EntityDescriptor.DEFAULT_ELEMENT_LOCAL_NAME, EntityDescriptor.ENTITY_ID_ATTRIB_NAME));
		audRes.getAudiences().add(aud);
		conditions.getAudienceRestrictions().add(audRes);
		// create AuthnStatement for Assertion
		authncontextclassref.setAuthnContextClassRef(AuthnContext.PASSWORD_AUTHN_CTX);
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
		// return the assertion
		return assertion;
	}
	
	/**
	 * Add the attributes configured for the target SP to the Assertion in an AttributeStatement
	 */
	public void addTargetSPAttributes(Assertion assertion){
		SPConfiguration sp = SPTestRunner.getInstance().getSPConfig();
		
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
			// add the namespace for the attribute (remains unchanged if namespace already in use)
			attribute.getNamespaceManager().getNamespaces().add(new Namespace(attr.getNamespace(), attr.getPrefix()));
			// set the name to the attribute name that was configured for the target SP
			attribute.setName(attr.getAttributeName());
			// set the nameformat that was configured for the target SP
			attribute.setNameFormat(attr.getNameFormat());
			// set the friendly name that was configured for the target SP
			attribute.setFriendlyName(attr.getFriendlyName());
			// add any additional custom attributes
			ArrayList<StringPair> customattrs = attr.getCustomAttributes();
			for(StringPair customattr : customattrs){
				if (!attr.getNamespace().isEmpty() && !attr.getPrefix().isEmpty()){
					attribute.getUnknownAttributes().put(new QName(attr.getNamespace(), customattr.getName(), attr.getPrefix()), customattr.getValue());
				}
				else{
					logger.error("Custom attributes are configured for the SAML Attributes, but no custom namespace and prefix were given");
				}
			}
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
	
	public interface ConfigTestCase extends TestCase {
		
		/**
		 * Check the provided configuration.  
		 * 
		 * @return the status of the test
		 */
		boolean checkConfig(SPConfiguration config);
	}

	public interface RequestTestCase extends TestCase {

		/**
		 * Check the provided request for the provided binding
		 * 
		 * @return the status of the test
		 */
		boolean checkRequest(String request, String binding);
	}

	public interface LoginTestCase extends TestCase {
		
		/**
		 * Check the result a login attempt. 
		 * 
		 * The procedure for this is as follows:
		 * - Initiate the login attempt with SPTestRunner.initiateLoginAttempt()
		 * - Specify the Response you wish the mock IdP to send to the target SP
		 * - Complete the login attempt with SPTestRunner.completeLoginAttempt()
		 * - Check if the result of the completed login attempt matches your expectations
		 * 
		 * You can attempt multiple logins, but it is advisable to use 
		 * SPTestRunner.resetBrowser() between logins so your previous login attempt is 
		 * not still in an active session.
		 * 
		 * @return the status of the test
		 */
		boolean checkLogin();
		
		/*
		 * The following example implementation tests if the target SP allows SP-initiated login attempts with a signed Response message. 
		 * It can be used as a reference and/or template for implementing the checkLogin() method: 
		 * 
		 @Override
		 public TestStatus checkLogin() {
		 	// get a browser to test in
			WebClient browser = SPTestRunner.getNewBrowser();
			// initiate the login attempt at the target SP
			SPTestRunner.initiateLoginAttempt(browser, true);
			// retrieve the ID of the AuthnRequest
			String requestID = SAMLUtil.getSamlMessageID(SPTestRunner.getAuthnRequest());
			// create the minimally required (by the SAML Web SSO profile) Response 
			Response response = createMinimalWebSSOResponse();
			// get all Assertion elements from the Response
			List<Assertion> assertions = response.getAssertions();
			// if more than 1 assertion was created in the minimal Response, we should log it since it means something 
			// has changed in the test framework's  code
			if (assertions.size() > 1) {
				logger.debug("The minimal Web SSO Response was created with more than 1 Assertion");
			}
			// retrieve the first Assertion element, which should also be the only one
			Assertion assertion = assertions.get(0);
			// set the InReplyTo attribute on the SubjectConfirmationData element of every SubjectConfirmations element
			// this is required for SP-initiated login attempts
			List<SubjectConfirmation> subConfs = assertion.getSubject().getSubjectConfirmations();
			for (SubjectConfirmation subConf : subConfs) {
				subConf.getSubjectConfirmationData().setInResponseTo(requestID);
			}
			// add the Attribute elements specified in targetSP.json to the Assertion
			addTargetSPAttributes(assertion);
			// sign the assertion
			SAMLUtil.sign(assertion, getX509Credentials(null));
			// set the Destination attribute that is required on signed Response messages
			response.setDestination(
					SPTestRunner
					.getSPConfig()
					.getApplicableACS(SAMLUtil.fromXML(SPTestRunner.getAuthnRequest()))
					.getAttributes()
					.getNamedItem(MD.LOCATION)
					.getNodeValue());
			// set the InResponseTo attribute on the Response element as required on SP-initated login attempts
			response.setInResponseTo(requestID);
			// sign the Response element
			SAMLUtil.sign(response, getX509Credentials(null));
			// complete the login attempt 
			Boolean loginValidSigResponse = SPTestRunner.completeLoginAttempt(browser, SAMLUtil.toXML(response));
			// make sure a valid login attempt will succeed before continuing the test case
			if (loginValidSigResponse) {
				resultMessage = "The Service Provider allows login with a signed Response message";
				return TestStatus.OK;
			}
			else{
				resultMessage = "The Service Provider does not allow login with a signed Response message";
				return TestStatus.ERROR;
			}
		}
		*
		*/
	}
}