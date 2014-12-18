package saml2webssotest.sp.testsuites;

import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.List;
import java.util.UUID;

import javax.net.ssl.HttpsURLConnection;

import org.opensaml.Configuration;
import org.opensaml.saml2.core.SubjectConfirmationData;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.NameID;
import org.opensaml.saml2.core.Response;
import org.opensaml.saml2.core.SubjectConfirmation;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Document;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import saml2webssotest.common.SAMLUtil;
import saml2webssotest.common.TestStatus;
import saml2webssotest.common.standardNames.CipherSuiteNames;
import saml2webssotest.common.standardNames.MD;
import saml2webssotest.common.standardNames.SAML;
import saml2webssotest.common.standardNames.SAMLmisc;
import saml2webssotest.sp.SPConfiguration;
import saml2webssotest.sp.SPTestRunner;


public class SAML2Prof_WebSSO extends SPTestSuite {
	/**
	 * Logger for this class
	 */
	private final Logger logger = LoggerFactory.getLogger(SAML2Prof_WebSSO.class);

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
			String acsLoc = config.getApplicableACS(null).getAttributes().getNamedItem(MD.LOCATION).getNodeValue();
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
	 * 		Regardless of the SAML binding used, the service provider MUST do the following:
	 * 			- Verify any signatures present on the assertion(s) or the response
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
			return "Test if the Service Provider correctly verifies the signatures on the assertion and response (MUST requirement)";
		}

		@Override
		public String getResultMessage() {
			return resultMessage;
		}

		@Override
		public TestStatus checkLogin() {
			SPTestRunner.initiateLoginAttempt(true);
			// retrieve the request ID from the request
			String requestID = SAMLUtil.getSamlMessageID(SPTestRunner.getSamlRequest());
			
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

				// sign the assertion before editing it, so the signature becomes invalid
				SAMLUtil.sign(assertion, getX509Credentials(null));
			}
			// add the InReplyTo attribute to the Response as well
			response.setInResponseTo(requestID);
			// convert the Response to an XML string and replace the signature with an invalid one 
			String responseInvalSigAssertion = SAMLUtil.toXML(response).replaceAll(
					"SignatureValue>[^<]*</", 
					"SignatureValue>VGhpcyBpcyB0aGUgaW52YWxpZCBzaWduYXR1cmUgdGhhdCB3aWxsIGJlIGVuY29kZWQgaW4gQmFzZTY0IGFuZCB3aWxsIHJlcGxhY2UgdGhlIHZhbGlkIHNpZ25hdHVyZQ==</");
			// Note that the invalid signature is the Base64-encoded string "This is the invalid signature that will be encoded in Base64 and will replace the valid signature"
			
			Boolean loginInvalSigAssertion = SPTestRunner.completeLoginAttempt(responseInvalSigAssertion);
			
			logger.debug("Finished the assertion signature login, starting the response signature login");
			
			SPTestRunner.resetBrowser();
			
			SPTestRunner.initiateLoginAttempt(true);
			// retrieve the new request ID
			requestID = SAMLUtil.getSamlMessageID(SPTestRunner.getSamlRequest());
			
			// reset the Response to the minimally required Response
			response = createMinimalWebSSOResponse();
			// add attributes and sign the assertions in the reset Response
			assertions = response.getAssertions();
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
			}
			Document request = SAMLUtil.fromXML(SPTestRunner.getSamlRequest());
			response.setDestination(SPTestRunner.getSPConfig().getApplicableACS(request).getAttributes().getNamedItem(MD.LOCATION).getNodeValue());
			// add the InReplyTo attribute to the Response after signing so the signature will become invalid
			response.setInResponseTo(requestID);
			SAMLUtil.sign(response, getX509Credentials(null));
			String responseInvalSigResponse = SAMLUtil.toXML(response).replaceAll(
					"SignatureValue>[^<]*</", 
					"SignatureValue>VGhpcyBpcyB0aGUgaW52YWxpZCBzaWduYXR1cmUgdGhhdCB3aWxsIGJlIGVuY29kZWQgaW4gQmFzZTY0IGFuZCB3aWxsIHJlcGxhY2UgdGhlIHZhbGlkIHNpZ25hdHVyZQ==</");
			// Note that the invalid signature is the Base64-encoded string "This is the invalid signature that will be encoded in Base64 and will replace the valid signature"
			
			Boolean loginInvalSigResponse = SPTestRunner.completeLoginAttempt(responseInvalSigResponse);
			
			
			if (loginInvalSigAssertion == null || loginInvalSigResponse == null){
				logger.debug("The login attempt could not be completed");
				return TestStatus.CRITICAL;
			}
			else if (loginInvalSigAssertion){	
				// the invalid signature on the assertion was ignored and login succeeded anyway
				if (loginInvalSigResponse){
					// the invalid signature on the response was also ignored and login succeeded anyway
					resultMessage = "The Service Provider did not check the signatures on either the Assertions or the Response";
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
				if (loginInvalSigResponse){
					// the invalid signature on the response was ignored and login succeeded anyway
					resultMessage = "The Service Provider did not check the Response signature";
					return TestStatus.ERROR;
				}
				else{
					// the invalid signature on both the assertion and the response weren't ignored and both logins failed as they should
					resultMessage = "The Service Provider checked the signatures on both the Assertions and the Response";
					return TestStatus.OK;
				}
			}
		}
	}

	/**
	 * Tests the following part of the SAML 2.0 Web Browser SSO Profile: 
	 * 		Regardless of the SAML binding used, the service provider MUST do the following:
	 * 			[...]
	 * 			- Verify that the Recipient attribute in any bearer <SubjectConfirmationData> matches the assertion consumer service URL 
	 * 			  to which the <Response> or artifact was delivered
	 *  
	 * @author RiaasM
	 */
	public class LoginRecipientVerification implements LoginTestCase{
		private String resultMessage;
	
		@Override
		public String getDescription() {
			return "Test if the Service Provider correctly verifies that the Recipient matches the URL on which the Response was received (MUST requirement)";
		}
	
		@Override
		public String getResultMessage() {
			return resultMessage;
		}
	
		@Override
		public TestStatus checkLogin() {
			/**
			 * Check if the target SP rejects a login attempt when the Recipient does not match the ACS URL on which it was delivered
			 */
			
			SPTestRunner.initiateLoginAttempt(true);
			
			// retrieve the request ID from the request
			String requestID = SAMLUtil.getSamlMessageID(SPTestRunner.getSamlRequest());
			
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
					SubjectConfirmationData subconfdata = (SubjectConfirmationData) subconf.getSubjectConfirmationData();
					subconfdata.setInResponseTo(requestID);
					// set all recipients to an invalid location (but still a valid URL)
					subconfdata.setRecipient("http://www.topdesk.com/");
				}
				// add the attributes
				addTargetSPAttributes(assertion);
				
				// sign the assertion
				SAMLUtil.sign(assertion, getX509Credentials(null));
			}
			// add the InReplyTo attribute to the Response as well
			response.setInResponseTo(requestID);
			String responseInvalRecipient = SAMLUtil.toXML(response);
			
			Boolean loginInvalRecipient = SPTestRunner.completeLoginAttempt(responseInvalRecipient);

			if (loginInvalRecipient == null){
				logger.debug("The login attempt could not be completed");
				return TestStatus.CRITICAL;
			}
			if (loginInvalRecipient){
				// the invalid recipient should cause the login attempt to fail but login succeeded
				resultMessage = "The Service Provider did not verify if the Recipient matches the URL on which the Response was received";
				return TestStatus.ERROR;
			}
			
			/**
			 * Check if the target SP also allows a login attempt if the Recipient does match the ACS URL on which it was delivered
			 */
			
			SPTestRunner.resetBrowser();
			
			SPTestRunner.initiateLoginAttempt(true);
			// retrieve the new request ID
			requestID = SAMLUtil.getSamlMessageID(SPTestRunner.getSamlRequest());
			
			// reset the Response to the minimally required Response
			response = createMinimalWebSSOResponse();
			// add attributes and sign the assertions in the response (this time leaving the recipient to its original, correct value)
			assertions = response.getAssertions();
			for (Assertion assertion : assertions){						
				// create nameid with transient format
				NameID nameid = (NameID) Configuration.getBuilderFactory().getBuilder(NameID.DEFAULT_ELEMENT_NAME).buildObject(NameID.DEFAULT_ELEMENT_NAME);
				nameid.setValue("_"+UUID.randomUUID().toString());
				nameid.setFormat(SAMLmisc.NAMEID_FORMAT_TRANSIENT);
				assertion.getSubject().setNameID(nameid);

				// set the InReplyTo attribute on the subjectconfirmationdata of all subjectconfirmations
				List<SubjectConfirmation> subconfs = assertion.getSubject().getSubjectConfirmations();
				for (SubjectConfirmation subconf : subconfs){
					SubjectConfirmationData subconfdata = (SubjectConfirmationData) subconf.getSubjectConfirmationData();
					subconfdata.setInResponseTo(requestID);
				}
				// add the attributes
				addTargetSPAttributes(assertion);
				
				// sign the assertion
				SAMLUtil.sign(assertion, getX509Credentials(null));
			}
			// add the InReplyTo attribute to the Response as well
			response.setInResponseTo(requestID);
			String responseValidRecipient = SAMLUtil.toXML(response);
			
			Boolean loginValidRecipient = SPTestRunner.completeLoginAttempt(responseValidRecipient);

			if (loginValidRecipient == null){
				logger.debug("The login attempt could not be completed");
				return TestStatus.CRITICAL;
			}
			if (loginValidRecipient){
				// the valid recipient should cause the login attempt to succeed and it did
				resultMessage = "The Service Provider verified if the Recipient did matches the URL on which the Response was received";
				return TestStatus.OK;
			}
			else{
				// the valid recipient should cause the login attempt to succeed, but it failed
				resultMessage = "The Service Provider did not verify if the Recipient matches the URL on which the Response was received";
				return TestStatus.ERROR;
			}
		}
	}
}
