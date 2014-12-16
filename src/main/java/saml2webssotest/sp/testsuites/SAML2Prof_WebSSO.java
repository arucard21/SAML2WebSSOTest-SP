package saml2webssotest.sp.testsuites;

import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

import javax.net.ssl.HttpsURLConnection;

import org.opensaml.Configuration;
import org.opensaml.DefaultBootstrap;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.NameID;
import org.opensaml.saml2.core.Response;
import org.opensaml.saml2.core.SubjectConfirmation;
import org.opensaml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml2.metadata.IDPSSODescriptor;
import org.opensaml.saml2.metadata.KeyDescriptor;
import org.opensaml.saml2.metadata.SingleSignOnService;
import org.opensaml.xml.ConfigurationException;
import org.opensaml.xml.XMLObjectBuilderFactory;
import org.opensaml.xml.security.credential.UsageType;
import org.opensaml.xml.security.keyinfo.KeyInfoGenerator;
import org.opensaml.xml.security.x509.X509KeyInfoGeneratorFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import saml2webssotest.common.SAMLUtil;
import saml2webssotest.common.TestStatus;
import saml2webssotest.common.standardNames.CipherSuiteNames;
import saml2webssotest.common.standardNames.MD;
import saml2webssotest.common.standardNames.SAML;
import saml2webssotest.common.standardNames.SAMLP;
import saml2webssotest.common.standardNames.SAMLmisc;
import saml2webssotest.sp.LoginAttempt;
import saml2webssotest.sp.SPConfiguration;
import saml2webssotest.sp.SPTestRunner;


public class SAML2Prof_WebSSO extends SPTestSuite {
	/**
	 * Logger for this class
	 */
	private final Logger logger = LoggerFactory.getLogger(SAML2Prof_WebSSO.class);

	@Override
	public String getmockIdPEntityID() {
		return "http://localhost:8080/sso";
	}

	public URL getMockServerURL(){
		try {
			return new URL("http", "localhost", 8080, "/sso");
		} catch (MalformedURLException e) {
			logger.error("The URL of the mock IdP was malformed", e);
			return null;
		}
	}

	@Override
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
		
		ssos.setBinding(SAMLmisc.BINDING_HTTP_REDIRECT);
		if (getMockServerURL() == null)
			return null;

		ssos.setLocation(getMockServerURL().toString());

		X509KeyInfoGeneratorFactory keyInfoGeneratorFactory = new X509KeyInfoGeneratorFactory();
		keyInfoGeneratorFactory.setEmitEntityCertificate(true);
		KeyInfoGenerator keyInfoGenerator = keyInfoGeneratorFactory.newInstance();
		try {
			keydescriptor.setKeyInfo(keyInfoGenerator.generate(getX509Credentials(null)));
		} catch (org.opensaml.xml.security.SecurityException e) {
			e.printStackTrace();
		}
		keydescriptor.setUse(UsageType.SIGNING);
		 
		idpssod.addSupportedProtocol(SAMLmisc.SAML20_PROTOCOL);
		idpssod.getSingleSignOnServices().add(ssos);
		idpssod.getKeyDescriptors().add(keydescriptor);
		
		ed.setEntityID(getmockIdPEntityID());
		ed.getRoleDescriptors().add(idpssod);
		
		// return the metadata as a string
		return SAMLUtil.toXML(ed);
	}

	/**
	 * Tests the following part of the SAML 2.0 Web Browser SSO Profile: 
	 * 		It is RECOMMENDED that the HTTP exchanges in this step [SAMLProf 4.1.3.5] be made over either SSL 3.0 [SSL3] or 
	 * 		TLS 1.0 [RFC2246] to maintain confidentiality and message integrity
	 * 
	 * Note that this test case accepts any TLS protocol as valid.
	 * 
	 * @author RiaasM
	 *
	 */
	public class ConfigSecureACS implements ConfigTestCase {
		private String resultMessage;
		
		@Override
		public String getDescription() {
			return "Test if the Service Provider receives its SAML Response on an endpoint that uses either SSL 3.0 or TLS 1.0 (RECOMMENDATION)";
		}
	
		@Override
		public String getResultMessage() {
			return resultMessage;
		}
	
		@Override
		public TestStatus checkConfig(SPConfiguration config) {
			// retrieve the default ACS location
			String acsLoc = config.getDefaultMDACSLocation();
			// access the default ACS location and check if it uses SSL 3.0 or TLS 1.0
			try {
				URL acsURL = new URL(acsLoc);
				// check if the URL uses the HTTPS protocol
				if (!acsURL.getProtocol().equalsIgnoreCase("https")){
					resultMessage = "The Service Provider's AssertionConsumerService is not made available over HTTPS";
					return TestStatus.ERROR;
				}
				// connect to the URL to retrieve which cipher is actually used
				HttpsURLConnection acsConn = (HttpsURLConnection) acsURL.openConnection();
				acsConn.connect();
				String cipher = acsConn.getCipherSuite();
				acsConn.disconnect();
				// check if cipher belongs to TLS or SSL v3.0 protocol
				if (cipher.startsWith("TLS_")){
					// accept all TLS ciphers
					resultMessage = "The Service Provider's AssertionConsumerService uses TLS 1.x";
					return TestStatus.OK;
				}
				else if (CipherSuiteNames.sslv3.contains(cipher)){
					// cipher is part of SSLv3 protocol
					resultMessage = "The Service Provider's AssertionConsumerService uses SSL 3.0";
					return TestStatus.OK;
				}
				else{
					resultMessage = "The Service Provider's AssertionConsumerService uses neither SSL 3.0 nor TLS 1.x";
					return TestStatus.ERROR;
				}
			} catch (MalformedURLException e) {
				logger.error("The AssertionConsumerService location from the target SP's metadata is malformed");
				logger.debug("", e);
				return TestStatus.CRITICAL;
			} catch (IOException e) {
				logger.error("Could not access the AssertionConsumerService location");
				logger.debug("", e);
				return TestStatus.CRITICAL;
			}
			
		}
		
	}

	/**
	 * Tests the following part of the SAML 2.0 Web Browser SSO Profile: 
	 * 		The <AuthnRequest> message MAY be signed, if authentication of the request issuer is required.
	 * 
	 * @author RiaasM
	 *
	 */
	public class RequestSigned implements RequestTestCase{
		private String resultMessage; 

		@Override
		public String getDescription() {
			return "Test if the Service Provider signs its Authentication Requests (MAY requirement)";
		}

		@Override
		public String getResultMessage() {
			return resultMessage;
		}

		@Override
		public TestStatus checkRequest(String request, String binding) {
			NodeList signatures = SAMLUtil.fromXML(request).getElementsByTagNameNS(SAMLmisc.NAMESPACE_XML_DSIG, SAMLmisc.XML_DSIG_SIGNATURE);
			// check if there's a signature that's a direct child of the AuthnRequest
			for (int i = 0; i < signatures.getLength(); i++){
				Node signature = signatures.item(i);
				if (signature.getParentNode().getNodeName().equals(SAMLP.AUTHNREQUEST)){
					resultMessage = "The Service Provider signs its Authentication Requests";
					return TestStatus.OK;
				}
			}
			// Request was not signed, notify user
			resultMessage = "The Service Provider did not sign its Authentication Request. If authentication of the request's issuer is required, the request may be signed.";
			return TestStatus.INFORMATION;
		}
	}
	
	/**
	 * Tests the following part of the SAML 2.0 Web Browser SSO Profile: 
	 * 		The <Issuer> element MUST be present
	 * 
	 * @author RiaasM
	 *
	 */
	public class RequestIssuer implements RequestTestCase{
		private String resultMessage; 
	
		@Override
		public String getDescription() {
			return "Test if the Service Provider's Authentication Requests contain an Issuer (MUST requirement)";
		}

		@Override
		public String getResultMessage() {
			return resultMessage;
		}
	
		@Override
		public TestStatus checkRequest(String request, String binding) {
			NodeList issuers = SAMLUtil.fromXML(request).getElementsByTagNameNS(SAML.NAMESPACE, SAML.ISSUER);
			// check if an issuer was found
			if (issuers.getLength() > 0){
				resultMessage = "The Service Provider's Authentication Requests contains an Issuer";
				return TestStatus.OK;
			}
			else{
				resultMessage = "The Service Provider's Authentication Requests did not contain an Issuer";
				return TestStatus.ERROR;
			}
		}
	}

	/**
	 * Tests the following part of the SAML 2.0 Web Browser SSO Profile: 
	 * 		The <Issuer> element ... MUST contain the unique identifier of the requesting service provider
	 * 
	 * @author RiaasM
	 *
	 */
	public class RequestIssuerUniqueIdentifier implements RequestTestCase{
		private String resultMessage; 
	
		@Override
		public String getDescription() {
			return "Test if the Service Provider's Authentication Requests contain an Issuer containing the SP's unique identifier (MUST requirement)";
		}
	
		@Override
		public String getResultMessage() {
			return resultMessage;
		}
	
		@Override
		public TestStatus checkRequest(String request, String binding) {
			NodeList issuers = SAMLUtil.fromXML(request).getElementsByTagNameNS(SAML.NAMESPACE, SAML.ISSUER);
			// check if an issuer was found
			if (issuers.getLength() == 0 ){
				resultMessage = "The Service Provider's Authentication Requests did not contain an Issuer";
				return TestStatus.CRITICAL;				
			}
			// check if all issuers (should only be 1) have the SP's Entity ID as its value
			for(int i = 0; i < issuers.getLength(); i++){
				Node issue = issuers.item(i);
				if (!issue.getTextContent().equalsIgnoreCase(SPTestRunner.getSPConfig().getMDAttribute(MD.ENTITYDESCRIPTOR, MD.ENTITYID))){
					resultMessage = "The Service Provider's Authentication Requests contained an Issuer that did not contain the SP's Entity ID";
					return TestStatus.ERROR;
				}
			}
			resultMessage = "The Service Provider's Authentication Requests contains only Issuer elements containing the SP's unique identifier (Entity ID)";
			return TestStatus.OK;
		}
	}

	/**
	 * Tests the following part of the SAML 2.0 Web Browser SSO Profile: 
	 * 		The <Issuer> element ... , the Format attribute MUST be omitted or have a value of urn:oasis:names:tc:SAML:2.0:nameid-format:entity.
	 * 
	 * @author RiaasM
	 *
	 */
	public class RequestIssuerFormat implements RequestTestCase{
		private String resultMessage;
		
		@Override
		public String getDescription() {
			return "Test if the Service Provider's Authentication Requests contain an Issuer with a Format attribute that is either omitted or has a value of "+SAMLmisc.NAMEID_FORMAT_ENTITY+"(MUST requirement)";
		}
	
		@Override
		public String getResultMessage() {
			return resultMessage;
		}
	
		@Override
		public TestStatus checkRequest(String request, String binding) {
			NodeList issuers = SAMLUtil.fromXML(request).getElementsByTagNameNS(SAML.NAMESPACE, SAML.ISSUER);
			// check if the issuer was found
			if (issuers.getLength() == 0 ){
				resultMessage = "The Service Provider's Authentication Requests did not contain an Issuer";
				return TestStatus.CRITICAL;
			}
			// check if the issuer(s) has the SP's Entity ID as its value
			for(int i = 0; i < issuers.getLength(); i++){
				Node issue = issuers.item(i);
				Node format = issue.getAttributes().getNamedItem(SAMLmisc.FORMAT);
				if (format != null && !format.getNodeValue().equalsIgnoreCase(SAMLmisc.NAMEID_FORMAT_ENTITY)){
					resultMessage = "The Service Provider's Authentication Request contains an Issuer with an invalid Format attribute";
					return TestStatus.ERROR;
				}
			}
			resultMessage = "The Service Provider's Authentication Requests contains only Issuer elements with a valid or omitted Format attribute";
			return TestStatus.OK;
		}
	}

	/**
	 * Tests the following part of the SAML 2.0 Web Browser SSO Profile: 
	 * 		Note that the service provider MAY include a <Subject> element in the request 
	 * 		that names the actual identity about which it wishes to receive an assertion. 
	 * 		This element MUST NOT contain any <SubjectConfirmation> elements.
	 * 
	 * @author RiaasM
	 *
	 */
	public class RequestSubject implements RequestTestCase{
		private String resultMessage;
		
		@Override
		public String getDescription() {
			return "Test if the Service Provider's Authentication Requests contain only Subject element without any SubjectConfirmation elements (MUST requirement)";
		}
	
		@Override
		public String getResultMessage() {
			return resultMessage;
		}
	
		@Override
		public TestStatus checkRequest(String request, String binding) {
			// check if the request contains any Subject element
			NodeList subjects = SAMLUtil.fromXML(request).getElementsByTagNameNS(SAML.NAMESPACE, SAML.SUBJECT);
			if (subjects.getLength() == 0 ){
				resultMessage = "The Service Provider's Authentication Requests did not contain any Subject elements";
				return TestStatus.OK;
			}
			// check if the request contains any Subject element
			NodeList subjectconfs = SAMLUtil.fromXML(request).getElementsByTagNameNS(SAML.NAMESPACE, SAML.SUBJECTCONFIRMATION);
			if (subjectconfs.getLength() == 0 ){
				resultMessage = "The Service Provider's Authentication Requests contained only Subject elements without any SubjectConfirmation elements";
				return TestStatus.OK;
			}
			else{
				resultMessage = "The Service Provider's Authentication Requests contained Subject elements as well as SubjectConfirmation elements";
				return TestStatus.ERROR;
			}
		}
	}

	/**
	 * Tests the following part of the SAML 2.0 Web Browser SSO Profile: 
	 * 		Verify any signatures present on the assertion(s) or the response
	 * 
	 * We can test this by trying to authenticate with responses that have invalid signatures and 
	 * ensuring it fails to log in. 
	 * 
	 * @author RiaasM
	 */
	public class LoginSignatureVerification implements LoginTestCase{
		private String resultMessage;

		@Override
		public String getDescription() {
			return "Test if the Service Provider allows logging in with either the persistent or transient name identifier format (MUST requirement)";
		}

		@Override
		public String getResultMessage() {
			return resultMessage;
		}

		@Override
		public List<LoginAttempt> getLoginAttempts() {
			ArrayList<LoginAttempt> attempts = new ArrayList<LoginAttempt>();
		
			// create a login attempt with an invalid signature on the assertion
			class LoginAttemptInvalidSignatureAssertion implements LoginAttempt{

				@Override
				public boolean isSPInitiated() {
					return true;
				}
				
				@Override
				public String getResponse(String request) {
					// retrieve the request ID from the request
					String requestID = SAMLUtil.getSamlMessageID(request);
					
					// create the minimally required Response
					Response response = createMinimalWebSSOResponse();
					// add attributes and sign the assertions in the response
					List<Assertion> assertions = response.getAssertions();
					for (Assertion assertion : assertions){
						// sign the assertion before editing it, so the signature becomes invalid
						SAMLUtil.sign(assertion, getX509Credentials(null));
						
						// create nameid with transient format
						NameID nameid = (NameID) Configuration.getBuilderFactory().getBuilder(NameID.DEFAULT_ELEMENT_NAME).buildObject(NameID.DEFAULT_ELEMENT_NAME);
						nameid.setValue("_"+UUID.randomUUID().toString());
						nameid.setFormat(SAMLmisc.NAMEID_FORMAT_TRANSIENT);
						assertion.getSubject().setNameID(nameid);

						// set the InReplyTo attribute on the subjectconfirmationdata of all subjectconfirmations
						List<SubjectConfirmation> subconfs = assertion.getSubject().getSubjectConfirmations();
						for (SubjectConfirmation subconf : subconfs){
							subconf.getSubjectConfirmationData().setInResponseTo(requestID);
						}
						// add the attributes
						addTargetSPAttributes(assertion);
					}
					// add the InReplyTo attribute to the Response as well
					response.setInResponseTo(requestID);
					return SAMLUtil.toXML(response);
				}
			}
			
			// create a login attempt with an invalid signature on the response
			class LoginAttemptInvalidSignatureResponse implements LoginAttempt{

				@Override
				public boolean isSPInitiated() {
					return true;
				}
				
				@Override
				public String getResponse(String request) {
					// retrieve the request ID from the request
					String requestID = SAMLUtil.getSamlMessageID(request);
					
					// create the minimally required Response
					Response response = createMinimalWebSSOResponse();
					// add attributes and sign the assertions in the response
					List<Assertion> assertions = response.getAssertions();
					for (Assertion assertion : assertions){
						// create nameid with transient format
						NameID nameid = (NameID) Configuration.getBuilderFactory().getBuilder(NameID.DEFAULT_ELEMENT_NAME).buildObject(NameID.DEFAULT_ELEMENT_NAME);
						nameid.setValue("_"+UUID.randomUUID().toString());
						nameid.setFormat(SAMLmisc.NAMEID_FORMAT_TRANSIENT);
						assertion.getSubject().setNameID(nameid);

						// set the InReplyTo attribute on the subjectconfirmationdata of all subjectconfirmations
						List<SubjectConfirmation> subconfs = assertion.getSubject().getSubjectConfirmations();
						for (SubjectConfirmation subconf : subconfs){
							subconf.getSubjectConfirmationData().setInResponseTo(requestID);
						}
						// add the attributes
						addTargetSPAttributes(assertion);
						SAMLUtil.sign(assertion, getX509Credentials(null));
					}
					SAMLUtil.sign(response, getX509Credentials(null));
					// add the InReplyTo attribute to the Response after signing so the signature will become invalid
					response.setInResponseTo(requestID);
					return SAMLUtil.toXML(response);
				}
			}
			attempts.add(new LoginAttemptInvalidSignatureAssertion());
			attempts.add(new LoginAttemptInvalidSignatureResponse());
			return attempts;
		}

		@Override
		public TestStatus checkLoginResults(List<Boolean> loginResults) {
			// the results should come back in the same order as they were provided, so we can check which login attempts succeeded
			if (loginResults.get(0).booleanValue()){	
				// the invalid signature on the assertion was ignored and login succeeded anyway
				if (loginResults.get(1).booleanValue()){
					// the invalid signature on the response was also ignored and login succeeded anyway
					resultMessage = "The Service Provider did not check any signatures";
					return TestStatus.ERROR;
				}
				else{
					// the invalid signature on the response was not ignored and its login failed as it should
					resultMessage = "The Service Provider did not check the Assertion signature";
					return TestStatus.ERROR;
				}
			}
			else{
				// the invalid signature on the assertion was not ignored and login failed as it should
				if (loginResults.get(1).booleanValue()){
					// the invalid signature on the response was ignored and login succeeded anyway
					resultMessage = "The Service Provider did not check the Response signature";
					return TestStatus.ERROR;
				}
				else{
					// the invalid signature on both the assertion and the response weren't ignored and both logins failed as they should
					resultMessage = "The Service Provider checked all signatures";
					return TestStatus.OK;
				}
			}
		}
	}
}
