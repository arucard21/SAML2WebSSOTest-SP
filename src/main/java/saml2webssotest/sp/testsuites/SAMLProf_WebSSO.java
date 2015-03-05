package saml2webssotest.sp.testsuites;

import java.io.IOException;
import java.net.MalformedURLException;
import java.net.Socket;
import java.net.URL;
import java.net.UnknownHostException;
import java.security.GeneralSecurityException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

import org.joda.time.DateTime;
import org.opensaml.common.xml.SAMLConstants;
import org.opensaml.saml2.core.AuthnStatement;
import org.opensaml.saml2.core.Issuer;
import org.opensaml.saml2.core.NameID;
import org.opensaml.saml2.core.Subject;
import org.opensaml.saml2.core.SubjectConfirmationData;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.Response;
import org.opensaml.saml2.core.SubjectConfirmation;
import org.opensaml.saml2.metadata.EntityDescriptor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import com.gargoylesoftware.htmlunit.FailingHttpStatusCodeException;
import com.gargoylesoftware.htmlunit.WebClient;
import com.gargoylesoftware.htmlunit.html.HtmlPage;

import saml2webssotest.common.SAMLUtil;
import saml2webssotest.common.StandardNames;
import saml2webssotest.common.TestSuite;
import saml2webssotest.sp.SPConfiguration;
import saml2webssotest.sp.SPTestRunner;

public class SAMLProf_WebSSO extends SPTestSuite {
	/**
	 * Logger for this class
	 */
	private final Logger logger = LoggerFactory.getLogger(SAMLProf_WebSSO.class);

	@Override
	public List<TestSuite> getDependencies() {
		ArrayList<TestSuite> dependencies = new ArrayList<TestSuite>();
		return dependencies;
	}

	/**
	 * Tests the following part of the SAML 2.0 Web Browser SSO Profile:
	 * 
	 * It is RECOMMENDED that the HTTP exchanges in this step [SAMLProf 4.1.3.5] be made over either SSL 3.0 [SSL3] or TLS 1.0 [RFC2246] to
	 * maintain confidentiality and message integrity
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
			return "Test if the Service Provider receives its SAML Response on an endpoint that uses either SSL 3.0 or TLS 1.0";
		}
		
		@Override
		public String getResultMessage() {
			return resultMessage;
		}

		@Override
		public boolean isMandatory() {
			return false;
		}

		@Override
		public boolean checkConfig(SPConfiguration config) {
			// retrieve the default ACS location
			String acsLoc = config.getApplicableACS(null).getName();
			// access the default ACS location and check if it uses SSL 3.0 or TLS 1.0
			try {
				URL acsURL = new URL(acsLoc);
				// check if the URL uses the HTTPS protocol
				if (!acsURL.getProtocol().equalsIgnoreCase("https")) {
					resultMessage = "The Service Provider's AssertionConsumerService is not made available over HTTPS";
					return false;
				}
				
				// Create a trust manager that does not validate certificate chains since we don't care 
				// about certificate validy but about the used protocol
				TrustManager[] trustAllCerts = new TrustManager[] { 
				    new X509TrustManager() {
						
						@Override
						public X509Certificate[] getAcceptedIssuers() {
							return new X509Certificate[0];
						}
						
						@Override
						public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {				
						}
						
						@Override
						public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {
						}
					}};

				// Install the all-trusting trust manager
				try {
				    SSLContext sc = SSLContext.getInstance("SSL"); 
				    sc.init(null, trustAllCerts, new java.security.SecureRandom()); 
				    HttpsURLConnection.setDefaultSSLSocketFactory(sc.getSocketFactory());
				} catch (GeneralSecurityException e) {
				} 
				// connect to the URL
				HttpsURLConnection acsConn = (HttpsURLConnection) acsURL.openConnection();
				acsConn.connect();
				// retrieve the cipersuite used on the connection
				String cipher = acsConn.getCipherSuite();
				acsConn.disconnect();
				// check if cipher belongs to TLS or SSL v3.0 protocol
				if (cipher.startsWith("TLS_")) {
					// accept all TLS ciphers
					resultMessage = "The Service Provider's AssertionConsumerService uses TLS 1.x";
					return true;
				} else if (StandardNames.sslv3.contains(cipher)) {
					// cipher is part of SSLv3 protocol
					resultMessage = "The Service Provider's AssertionConsumerService uses SSL 3.0";
					return true;
				} else {
					resultMessage = "The Service Provider's AssertionConsumerService uses neither SSL 3.0 nor TLS 1.x";
					return false;
				}
			} catch (MalformedURLException e) {
				logger.error("The AssertionConsumerService location from the target SP's metadata is malformed");
				logger.debug("", e);
				return false;
			} catch (IOException e) {
				logger.error("Could not access the AssertionConsumerService location");
				logger.debug("", e);
				return false;
			}

		}

	}

	/**
	 * Tests the following part of the SAML 2.0 Web Browser SSO Profile: The <Issuer> element MUST be present
	 * 
	 * Tested by checking if the AuthnRequest contains an Issuer
	 * 
	 * @author RiaasM
	 * 
	 */
	public class RequestIssuer implements RequestTestCase {
		private String resultMessage;

		@Override
		public String getDescription() {
			return "Test if the Service Provider's Authentication Requests contain an Issuer";
		}

		@Override
		public String getResultMessage() {
			return resultMessage;
		}

		@Override
		public boolean isMandatory() {
			return true;
		}

		@Override
		public boolean checkRequest(String request, String binding) {
			NodeList issuers = SAMLUtil.fromXML(request).getElementsByTagNameNS(SAMLConstants.SAML20_NS, Issuer.DEFAULT_ELEMENT_LOCAL_NAME);
			// check if an issuer was found
			if (issuers.getLength() > 0) {
				resultMessage = "The Service Provider's Authentication Requests contains an Issuer";
				return true;
			} else {
				resultMessage = "The Service Provider's Authentication Requests did not contain an Issuer";
				return false;
			}
		}
	}

	/**
	 * Tests the following part of the SAML 2.0 Web Browser SSO Profile:
	 * 
	 * The <Issuer> element ... MUST contain the unique identifier of the requesting service provider
	 * 
	 * Tested by checking if the Issuer in the AuthnRequest contains the target SP's Entity ID
	 * 
	 * @author RiaasM
	 * 
	 */
	public class RequestIssuerUniqueIdentifier implements RequestTestCase {
		private String resultMessage;

		@Override
		public String getDescription() {
			return "Test if the Service Provider's Authentication Requests contain an Issuer containing the SP's unique identifier";
		}

		@Override
		public String getResultMessage() {
			return resultMessage;
		}

		@Override
		public boolean isMandatory() {
			return true;
		}

		@Override
		public boolean checkRequest(String request, String binding) {
			NodeList issuers = SAMLUtil.fromXML(request).getElementsByTagNameNS(SAMLConstants.SAML20_NS, Issuer.DEFAULT_ELEMENT_LOCAL_NAME);
			// check if an issuer was found
			if (issuers.getLength() == 0) {
				resultMessage = "The Service Provider's Authentication Requests did not contain an Issuer";
				return false;
			}
			// check if all issuers (should only be 1) have the SP's Entity ID
			// as its value
			for (int i = 0; i < issuers.getLength(); i++) {
				Node issue = issuers.item(i);
				if (!issue.getTextContent().equalsIgnoreCase(SPTestRunner.getInstance().getSPConfig().getMDAttribute(EntityDescriptor.DEFAULT_ELEMENT_LOCAL_NAME, EntityDescriptor.ENTITY_ID_ATTRIB_NAME))) {
					resultMessage = "The Service Provider's Authentication Requests contained an Issuer that did not contain the SP's Entity ID";
					return false;
				}
			}
			resultMessage = "The Service Provider's Authentication Requests contains only Issuer elements containing the SP's unique identifier (Entity ID)";
			return true;
		}
	}

	/**
	 * Tests the following part of the SAML 2.0 Web Browser SSO Profile:
	 * 
	 * The <Issuer> element ... , the Format attribute MUST be omitted or have a value of urn:oasis:names:tc:SAML:2.0:nameid-format:entity.
	 * 
	 * Tested by checking if Issuer in the AuthnRequest either contains no Format attribute or the Format attribute has the correct value
	 * 
	 * @author RiaasM
	 * 
	 */
	public class RequestIssuerFormat implements RequestTestCase {
		private String resultMessage;

		@Override
		public String getDescription() {
			return "Test if the Service Provider's Authentication Requests contain an Issuer with a Format attribute that is either omitted or has a value of "
					+ NameID.ENTITY + "(MUST requirement)";
		}

		@Override
		public String getResultMessage() {
			return resultMessage;
		}

		@Override
		public boolean isMandatory() {
			return true;
		}

		@Override
		public boolean checkRequest(String request, String binding) {
			NodeList issuers = SAMLUtil.fromXML(request).getElementsByTagNameNS(SAMLConstants.SAML20_NS, Issuer.DEFAULT_ELEMENT_LOCAL_NAME);
			// check if the issuer was found
			if (issuers.getLength() == 0) {
				resultMessage = "The Service Provider's Authentication Requests did not contain an Issuer";
				return false;
			}
			// check if the issuer(s) has the SP's Entity ID as its value
			for (int i = 0; i < issuers.getLength(); i++) {
				Node issuer = issuers.item(i);
				Node format = issuer.getAttributes().getNamedItem(Issuer.FORMAT_ATTRIB_NAME);
				if (format != null && !format.getNodeValue().equalsIgnoreCase(NameID.ENTITY)) {
					resultMessage = "The Service Provider's Authentication Request contains an Issuer with an invalid Format attribute";
					return false;
				}
			}
			resultMessage = "The Service Provider's Authentication Requests contains only Issuer elements with a valid or omitted Format attribute";
			return true;
		}
	}

	/**
	 * Tests the following part of the SAML 2.0 Web Browser SSO Profile:
	 * 
	 * Note that the service provider MAY include a <Subject> element in the request that names the actual identity about which it wishes to
	 * receive an assertion. This element MUST NOT contain any <SubjectConfirmation> elements.
	 * 
	 * Tested by checking if the AuthnRequest contains any Subject elements and if so, it verifies that the AuthnRequest does not contain
	 * any SubjectConfirmation elements as well
	 * 
	 * @author RiaasM
	 * 
	 */
	public class RequestSubject implements RequestTestCase {
		private String resultMessage;

		@Override
		public String getDescription() {
			return "Test if the Service Provider's Authentication Requests contain only Subject element without any SubjectConfirmation elements";
		}

		@Override
		public String getResultMessage() {
			return resultMessage;
		}

		@Override
		public boolean isMandatory() {
			return true;
		}

		@Override
		public boolean checkRequest(String request, String binding) {
			// check if the request contains any Subject element
			NodeList subjects = SAMLUtil.fromXML(request).getElementsByTagNameNS(SAMLConstants.SAML20_NS, Subject.DEFAULT_ELEMENT_LOCAL_NAME);
			if (subjects.getLength() == 0) {
				resultMessage = "The Service Provider's Authentication Requests did not contain any Subject elements";
				return true;
			}
			// check if the request contains any Subject element
			NodeList subjectconfs = SAMLUtil.fromXML(request).getElementsByTagNameNS(SAMLConstants.SAML20_NS, SubjectConfirmation.DEFAULT_ELEMENT_LOCAL_NAME);
			if (subjectconfs.getLength() == 0) {
				resultMessage = "The Service Provider's Authentication Requests contained only Subject elements without any SubjectConfirmation elements";
				return true;
			} else {
				resultMessage = "The Service Provider's Authentication Requests contained Subject elements as well as SubjectConfirmation elements";
				return false;
			}
		}
	}

	/**
	 * Tests the following part of the SAML 2.0 Web Browser SSO Profile:
	 * 
	 * Regardless of the SAML binding used, the service provider MUST do the following: 
	 * 	- Verify any signatures present on the assertion(s) or the response
	 * 
	 * Tested by trying to log in to the target SP with:
	 * 	- A Response that has a valid signature in both the Assertion and the Response elements
	 * 		- This should log in correctly
	 * 	- a Response that has an invalid signature in the Assertion
	 * 		- This should fail to log in
	 * 	- a Response that has an invalid signature in the Response (with the required Destination attribute set correctly)
	 * 		- This should fail to log in
	 * 
	 * @author RiaasM
	 */
	public class LoginSignatureVerification implements LoginTestCase {
		private String resultMessage;

		@Override
		public String getDescription() {
			return "Test if the Service Provider correctly verifies the signatures on the assertion and response";
		}

		@Override
		public String getResultMessage() {
			return resultMessage;
		}

		@Override
		public boolean isMandatory() {
			return true;
		}

		@Override
		public boolean checkLogin() {
			// get a browser to test in
			WebClient browser = SPTestRunner.getInstance().getNewBrowser();
			// define the variables that can be used to store the components of the Response messages
			Response response;
			List<Assertion> assertions;
			Assertion assertion;
			
			// create the minimally required (by the SAML Web SSO profile) Response 
			response = createMinimalWebSSOResponse(PLACEHOLDER_REQUESTID, PLACEHOLDER_ACSURL);
			// get all Assertion elements from the Response
			assertions = response.getAssertions();
			// if more than 1 assertion was created in the minimal Response, we should log it since it means something 
			// has changed in the test framework's  code (do this only once in the test suite as it's just a notification
			// that something might have changed)
			if (assertions.size() > 1) {
				logger.debug("The minimal Web SSO Response was created with more than 1 Assertion");
			}
			// retrieve the first Assertion element, which should also be the only one
			assertion = assertions.get(0);
			// add the Attribute elements specified in targetSP.json to the Assertion
			addTargetSPAttributes(assertion);
			// sign the assertion
			SAMLUtil.sign(assertion, getX509Credentials(null));
			// set the Destination attribute that is required on signed Response messages
			response.setDestination(PLACEHOLDER_ACSURL);
			// sign the Response element
			SAMLUtil.sign(response, getX509Credentials(null));
			SPTestRunner.getInstance().setSamlResponse(SAMLUtil.toXML(response));
			// complete the login attempt 
			Boolean loginValidSigResponse = SPTestRunner.getInstance().attemptLogin(browser, true);
			// make sure a valid login attempt will succeed before continuing the test case
			if (loginValidSigResponse == null) {
				resultMessage = "The login attempt could not be completed";
				return false;
			} else if (!loginValidSigResponse) {
				resultMessage = "The Service Provider does not allow login with a correctly signed Response message";
				return false;
			}
			logger.debug("The Service Provider allows logins with a correctly signed Response message");
			// reset the browser so you don't remember any login information 
			browser = SPTestRunner.getInstance().getNewBrowser();
			// reset the Response variables so you don't accidentally re-use old data
			response = null;
			assertions = null;
			assertion = null;
			
			response = createMinimalWebSSOResponse(PLACEHOLDER_REQUESTID, PLACEHOLDER_ACSURL);
			assertions = response.getAssertions();
			assertion = assertions.get(0);
			addTargetSPAttributes(assertion);
			SAMLUtil.sign(assertion, getX509Credentials(null));
			/*
			 * Note that the invalid signature is the following Base64-encoded string:
			 * "This is the invalid signature that will be encoded in Base64 and will replace the valid signature"
			 */
			String responseInvalidSigAssertion = SAMLUtil
					.toXML(response)
					.replaceAll(
							"SignatureValue>[^<]*</",
							"SignatureValue>VGhpcyBpcyB0aGUgaW52YWxpZCBzaWduYXR1cmUgdGhhdCB3aWxsIGJlIGVuY29kZWQgaW4gQmFzZTY0IGFuZCB3aWxsIHJlcGxhY2UgdGhlIHZhbGlkIHNpZ25hdHVyZQ==</");
			SPTestRunner.getInstance().setSamlResponse(responseInvalidSigAssertion);
			// make sure the signature on the assertion is not updated (becoming valid again)
			SPTestRunner.getInstance().setSigUpdateAssertionAllowed(false);
			Boolean loginInvalidSigAssertion = SPTestRunner.getInstance().attemptLogin(browser, true);
			// reset the sig update boolean
			SPTestRunner.getInstance().setSigUpdateAssertionAllowed(true);
			logger.debug("Finished testing with a Response that has an invalid signature in the Assertion");

			browser = SPTestRunner.getInstance().getNewBrowser();
			response = null;
			assertions = null;
			assertion = null;
			
			response = createMinimalWebSSOResponse(PLACEHOLDER_REQUESTID, PLACEHOLDER_ACSURL);
			assertions = response.getAssertions();
			if (assertions.size() > 1) {
				logger.debug("The minimal Web SSO Response was created with more than 1 Assertion");
			}
			assertion = assertions.get(0);
			addTargetSPAttributes(assertion);
			response.setDestination(PLACEHOLDER_ACSURL);
			SAMLUtil.sign(response, getX509Credentials(null));
			/*
			 * Note that the invalid signature is the following Base64-encoded string:
			 * "This is the invalid signature that will be encoded in Base64 and will replace the valid signature"
			 */
			String responseInvalidSigResponse = SAMLUtil
					.toXML(response)
					.replaceAll(
							"SignatureValue>[^<]*</",
							"SignatureValue>VGhpcyBpcyB0aGUgaW52YWxpZCBzaWduYXR1cmUgdGhhdCB3aWxsIGJlIGVuY29kZWQgaW4gQmFzZTY0IGFuZCB3aWxsIHJlcGxhY2UgdGhlIHZhbGlkIHNpZ25hdHVyZQ==</");
			SPTestRunner.getInstance().setSamlResponse(responseInvalidSigResponse);
			SPTestRunner.getInstance().setSigUpdateResponseAllowed(false);
			Boolean loginInvalidSigResponse = SPTestRunner.getInstance().attemptLogin(browser, true);
			// reset the sig update boolean
			SPTestRunner.getInstance().setSigUpdateResponseAllowed(true);
			logger.debug("Finished testing with a Response that has an invalid signature in the Response");

			// check the result of the login attempts with invalid signatures
			if (loginInvalidSigAssertion == null || loginInvalidSigResponse == null) {
				resultMessage = "The login attempt could not be completed";
				return false;
			} else if (loginInvalidSigAssertion) {
				if (loginInvalidSigResponse) {
					resultMessage = "The Service Provider did not check the signatures on either the Assertions or the Response";
					return false;
				} else {
					resultMessage = "The Service Provider did not check the Assertion signature";
					return false;
				}
			} else {
				if (loginInvalidSigResponse) {
					resultMessage = "The Service Provider did not check the Response signature";
					return false;
				} else {
					resultMessage = "The Service Provider checked the signatures on both the Assertions and the Response";
					return true;
				}
			}
		}
	}

	/**
	 * Tests the following part of the SAML 2.0 Web Browser SSO Profile:
	 * 
	 * Regardless of the SAML binding used, the service provider MUST do the following: [...] 
	 * 	- Verify that the Recipient attribute in any bearer <SubjectConfirmationData> matches
	 * 	the assertion consumer service URL to which the <Response> or artifact was delivered
	 * 
	 * Tested by trying to log in to the target SP with:
	 * 	- A Response that has a valid Recipient value
	 * 		- This should log in correctly
	 * 	- a Response that has an invalid Recipient value
	 * 		- This should fail to log in
	 * 
	 * @author RiaasM
	 */
	public class LoginRecipientVerification implements LoginTestCase {
		private String resultMessage;

		@Override
		public String getDescription() {
			return "Test if the Service Provider correctly verifies that the Recipient matches the URL on which the Response was received";
		}

		@Override
		public String getResultMessage() {
			return resultMessage;
		}

		@Override
		public boolean isMandatory() {
			return true;
		}

		@Override
		public boolean checkLogin() {
			// get a browser to test in
			WebClient browser = SPTestRunner.getInstance().getNewBrowser();
			// define the variables that can be used to store the components of the Response messages
			Response response;
			List<Assertion> assertions;
			Assertion assertion;
			List<SubjectConfirmation> subConfs;
			
			/**
			 * Check if the target SP also allows a login attempt if the Recipient does match the ACS URL on which it was delivered
			 */
			response = createMinimalWebSSOResponse(PLACEHOLDER_REQUESTID, PLACEHOLDER_ACSURL);
			assertions = response.getAssertions();
			assertion = assertions.get(0);
			addTargetSPAttributes(assertion);
			SAMLUtil.sign(assertion, getX509Credentials(null));
			SPTestRunner.getInstance().setSamlResponse(SAMLUtil.toXML(response));
			Boolean loginValidRecipient = SPTestRunner.getInstance().attemptLogin(browser, true);

			if (loginValidRecipient == null) {
				logger.debug("The login attempt could not be completed");
				return false;
			}
			else if (!loginValidRecipient) {
				resultMessage = "The Service Provider did not allow login with a valid Recipient in the Response message";
				return false;
			}
			logger.debug("The Service Provider allowed login with a valid Recipient in the Response message");
			
			/**
			 * Check if the target SP rejects a login attempt when the Recipient does not match the ACS URL on which it was delivered
			 */
			browser = SPTestRunner.getInstance().getNewBrowser();
			response = null;
			assertions = null;
			assertion = null;
			subConfs = null;
			
			response = createMinimalWebSSOResponse(PLACEHOLDER_REQUESTID, PLACEHOLDER_ACSURL);
			assertions = response.getAssertions();
			assertion = assertions.get(0);
			subConfs = assertion.getSubject().getSubjectConfirmations();
			for (SubjectConfirmation subConf : subConfs) {
				SubjectConfirmationData subConfData = (SubjectConfirmationData) subConf.getSubjectConfirmationData();
				// set the recipient to an invalid location (that is still a valid URL)
				subConfData.setRecipient("http://www.topdesk.com/");
			}
			addTargetSPAttributes(assertion);
			SAMLUtil.sign(assertion, getX509Credentials(null));
			SPTestRunner.getInstance().setSamlResponse(SAMLUtil.toXML(response));
			Boolean loginInvalidRecipient = SPTestRunner.getInstance().attemptLogin(browser, true);

			if (loginInvalidRecipient == null) {
				resultMessage = "The login attempt could not be completed";
				return false;
			}
			else if (loginInvalidRecipient) {
				resultMessage = "The Service Provider did not verify if the Recipient matches the URL on which the Response was received";
				return false;
			}
			else{
				resultMessage = "The Service Provider correctly verifies if the Recipient matches the URL on which the Response was received";
				return true;
			}
		}
	}

	/**
	 * Tests the following part of the SAML 2.0 Web Browser SSO Profile:
	 * 
	 * Regardless of the SAML binding used, the service provider MUST do the following: [...] 
	 * 	- Verify that the NotOnOrAfter attribute in any bearer <SubjectConfirmationData> has not passed, subject to
	 * 	allowable clock skew between the providers
	 * 
	 * Tested by trying to log in to the target SP with:
	 * 	- A Response that has a valid NotOnOrAfter time (5 minutes)
	 * 		- This should log in correctly
	 * 	- a Response that has a NotOnOrAfter time set to now. We also wait for the allowable clock skew to no longer 
	 * 	be able to affect the validity of the Response
	 * 		- This should fail to log in
	 * 
	 * @author RiaasM
	 */
	public class LoginNotOnOrAfterVerification implements LoginTestCase {
		private String resultMessage;

		@Override
		public String getDescription() {
			return "Test if the Service Provider correctly verifies that the NotOnOrAfter time has not passed";
		}

		@Override
		public String getResultMessage() {
			return resultMessage;
		}

		@Override
		public boolean isMandatory() {
			return true;
		}

		@Override
		public boolean checkLogin() {
			// get a browser to test in
			WebClient browser = SPTestRunner.getInstance().getNewBrowser();
			// define the variables that can be used to store the components of the Response messages
			Response response;
			List<Assertion> assertions;
			Assertion assertion;
			List<SubjectConfirmation> subConfs;
			
			/**
			 * Check if the target SP allows a login attempt if the NotOnOrAfter time is valid
			 */

			response = createMinimalWebSSOResponse(PLACEHOLDER_REQUESTID, PLACEHOLDER_ACSURL);
			assertions = response.getAssertions();
			assertion = assertions.get(0);
			addTargetSPAttributes(assertion);
			SAMLUtil.sign(assertion, getX509Credentials(null));
			SPTestRunner.getInstance().setSamlResponse(SAMLUtil.toXML(response));
			Boolean loginValidNOOA = SPTestRunner.getInstance().attemptLogin(browser, true);
			
			if (loginValidNOOA == null) {
				resultMessage = "The login attempt could not be completed";
				return false;
			}
			else if (!loginValidNOOA) {
				resultMessage = "The Service Provider did not allow login with a valid NotOnOrAfter time in the Response message";
				return false;
			}
			logger.debug("The Service Provider allowed login with a valid NotOnOrAfter time in the Response message");

			/**
			 * Check if the target SP rejects a login attempt when the Recipient does not match the ACS URL on which it was delivered
			 */

			browser = SPTestRunner.getInstance().getNewBrowser();
			response = null;
			assertions = null;
			assertion = null;
			subConfs = null;
			
			response = createMinimalWebSSOResponse(PLACEHOLDER_REQUESTID, PLACEHOLDER_ACSURL);
			assertions = response.getAssertions();
			assertion = assertions.get(0);
			subConfs = assertion.getSubject().getSubjectConfirmations();
			for (SubjectConfirmation subConf : subConfs) {
				SubjectConfirmationData subConfData = subConf.getSubjectConfirmationData();
				// set the NotOnOrAfter attribute to now so it will be invalid when it arrives at the target SP
				subConfData.setNotOnOrAfter(DateTime.now());
			}
			addTargetSPAttributes(assertion);
			SAMLUtil.sign(assertion, getX509Credentials(null));
			// wait for the same amount of time as the clock skew on the target SP to make sure
			// the Response can't be made valid due to that clock skew (and a second longer, just to make sure)
			try {
				Thread.sleep(SPTestRunner.getInstance().getSPConfig().getClockSkew()+1000);
			} catch (InterruptedException e) {
				resultMessage = "The wait time intended to keep the clock skew from incorrectly causing the Response to be valid, was interrupted";
				return false;
			}
			SPTestRunner.getInstance().setSamlResponse(SAMLUtil.toXML(response));
			Boolean loginInvalidNOOA = SPTestRunner.getInstance().attemptLogin(browser, true);

			if (loginInvalidNOOA == null) {
				resultMessage = "The login attempt could not be completed";
				return false;
			}
			if (loginInvalidNOOA) {
				resultMessage = "The Service Provider did not verify that the NotOnOrAfter time has not passed";
				return false;
			} else {
				resultMessage = "The Service Provider correctly verified that the NotOnOrAfter time has not passed";
				return true;
			}
		}
	}

	/**
	 * Tests the following part of the SAML 2.0 Web Browser SSO Profile:
	 * 
	 * Regardless of the SAML binding used, the service provider MUST do the following: [...] 
	 * 	- Verify that the InResponseTo attribute in the bearer <SubjectConfirmationData> equals the ID of its original <AuthnRequest> message
	 * 
	 * Tested by trying to log in to the target SP with:
	 * 	- A Response that has a valid InResponseTo attribute
	 * 		- This should log in correctly
	 * 	- a Response that has an invalid InResponseTo attribute in the SubjectConfirmationData
	 * 		- This should fail to log in
	 * - a Response that has an invalid InResponseTo attribute in the Response
	 * 		- This should fail to log in
	 * 
	 * @author RiaasM
	 */
	public class LoginInResponseToVerification implements LoginTestCase {
		private String resultMessage;

		@Override
		public String getDescription() {
			return "Test if the Service Provider verifies that the InResponseTo ID matches the ID of the AuthnRequest";
		}

		@Override
		public String getResultMessage() {
			return resultMessage;
		}

		@Override
		public boolean isMandatory() {
			return true;
		}

		@Override
		public boolean checkLogin() {
			// get a browser to test in
			WebClient browser = SPTestRunner.getInstance().getNewBrowser();
			// define the variables that can be used to store the components of the Response messages
			Response response;
			List<Assertion> assertions;
			Assertion assertion;
			List<SubjectConfirmation> subConfs;
			
			/**
			 * Check if the target SP allows a login attempt if the InResponseTo attribute is valid
			 */

			response = createMinimalWebSSOResponse(PLACEHOLDER_REQUESTID, PLACEHOLDER_ACSURL);
			assertion = response.getAssertions().get(0);
			addTargetSPAttributes(assertion);
			SAMLUtil.sign(assertion, getX509Credentials(null));
			SPTestRunner.getInstance().setSamlResponse(SAMLUtil.toXML(response));
			Boolean loginValidIRT = SPTestRunner.getInstance().attemptLogin(browser, true);

			if (loginValidIRT == null) {
				resultMessage = "The login attempt could not be completed";
				return false;
			}
			else if (!loginValidIRT) {
				resultMessage = "The Service Provider did not allow login with a valid InResponseTo attribute in the Response message";
				return false;
			}
			logger.debug("The Service Provider allowed login with a valid InResponseTo attribute in the Response message");

			/**
			 * Check if the target SP rejects a login attempt when the InResponseTo attribute is invalid in SubjectConfirmationData
			 */

			browser = SPTestRunner.getInstance().getNewBrowser();
			response = null;
			assertions = null;
			assertion = null;
			subConfs = null;
			
			response = createMinimalWebSSOResponse(PLACEHOLDER_REQUESTID, PLACEHOLDER_ACSURL);
			assertions = response.getAssertions();
			assertion = assertions.get(0);
			subConfs = assertion.getSubject().getSubjectConfirmations();
			for (SubjectConfirmation subConf : subConfs) {
				SubjectConfirmationData subConfData = subConf.getSubjectConfirmationData();
				// set IRT to valid NCName but a new one that won't match the correct one
				subConfData.setInResponseTo("_"+UUID.randomUUID().toString()+"_"+UUID.randomUUID().toString());
			}
			addTargetSPAttributes(assertion);
			SAMLUtil.sign(assertion, getX509Credentials(null));
			SPTestRunner.getInstance().setSamlResponse(SAMLUtil.toXML(response));
			Boolean loginInvalidIRTSubConfData = SPTestRunner.getInstance().attemptLogin(browser, true);
			
			/**
			 * Check if the target SP rejects a login attempt when the InResponseTo attribute is invalid in Response
			 */

			browser = SPTestRunner.getInstance().getNewBrowser();
			response = null;
			assertions = null;
			assertion = null;
			subConfs = null;
			
			response = createMinimalWebSSOResponse(PLACEHOLDER_REQUESTID, PLACEHOLDER_ACSURL);
			assertions = response.getAssertions();
			assertion = assertions.get(0);
			addTargetSPAttributes(assertion);
			// set IRT to valid NCName but a new one that won't match the correct one
			response.setInResponseTo("_"+UUID.randomUUID().toString()+"_"+UUID.randomUUID().toString());
			SAMLUtil.sign(assertion, getX509Credentials(null));
			SPTestRunner.getInstance().setSamlResponse(SAMLUtil.toXML(response));
			Boolean loginInvalidIRTResponse = SPTestRunner.getInstance().attemptLogin(browser, true);

			if (loginInvalidIRTSubConfData == null || loginInvalidIRTResponse == null) {
				resultMessage = "The login attempt could not be completed";
				return false;
			} else if (loginInvalidIRTSubConfData) {
				if (loginInvalidIRTResponse) {
					resultMessage = "The Service Provider did not verify that the InResponseTo ID on either the SubjectConfirmationData or the Response matches the ID from the AuthnRequest";
					return false;
				} else {
					resultMessage = "The Service Provider did not verify that the InResponseTo ID on the SubjectConfirmationData matches the ID from the AuthnRequest";
					return false;
				}
			} else {
				if (loginInvalidIRTResponse) {
					resultMessage = "The Service Provider did not verify that the InResponseTo ID on the Response matches the ID from the AuthnRequest";
					return false;
				} else {
					resultMessage = "The Service Provider verifed that the InResponseTo ID on both the SubjectConfirmationData and the Response matches the ID from the AuthnRequest";
					return true;
				}
			}
		}
	}

	/**
	 * Tests the following part of the SAML 2.0 Web Browser SSO Profile:
	 * 
	 * Regardless of the SAML binding used, the service provider MUST do the following: [...]
	 * 	- Verify that the InResponseTo attribute [...], unless the response is unsolicited (see Section 4.1.5 ), 
	 * 	in which case the attribute MUST NOT be present
	 * 
	 * Tested by trying to log in to the target SP with:
	 * 	- An unsolicited Response without the InResponseTo attribute present
	 * 		- This should log in correctly
	 * 	- an unsolicited Response with an empty InResponseTo attribute present
	 * 		- This should fail to log in
	 * 
	 * @author RiaasM
	 */
	public class LoginInResponseToIdPInitiatedVerification implements LoginTestCase {
		private String resultMessage;

		@Override
		public String getDescription() {
			return "Test if the Service Provider verifies that the InResponseTo attribute is not present on IdP-initiated logins";
		}

		@Override
		public String getResultMessage() {
			return resultMessage;
		}

		@Override
		public boolean isMandatory() {
			return true;
		}

		@Override
		public boolean checkLogin() {
			// get a browser to test in
			WebClient browser = SPTestRunner.getInstance().getNewBrowser();
			// define the variables that can be used to store the components of the Response messages
			Response response;
			List<Assertion> assertions;
			Assertion assertion;
			List<SubjectConfirmation> subConfs;
			
			/**
			 * Try to log in with an unsolicited Response without the InResponseTo attribute present
			 */
			response = createMinimalWebSSOResponse(null, null);
			assertions = response.getAssertions();
			assertion = assertions.get(0);
			addTargetSPAttributes(assertion);
			SAMLUtil.sign(assertion, getX509Credentials(null));
			SPTestRunner.getInstance().setSamlResponse(SAMLUtil.toXML(response));
			Boolean loginValidIRTIdP = SPTestRunner.getInstance().attemptLogin(browser, false);

			if (loginValidIRTIdP == null) {
				resultMessage = "The IdP-initiated login attempt could not be completed";
				return false;
			}
			else if (!loginValidIRTIdP) {
				resultMessage = "The Service Provider did not allow login with an unsolicited Response message without an InResponseTo attribute";
				return false;
			}
			
			/**
			 * Try to log in with an unsolicited Response with an empty InResponseTo attribute present
			 */

			browser = SPTestRunner.getInstance().getNewBrowser();
			response = null;
			assertions = null;
			assertion = null;
			subConfs = null;
			
			response = createMinimalWebSSOResponse(null, null);
			assertions = response.getAssertions();
			assertion = assertions.get(0);
			subConfs = assertion.getSubject().getSubjectConfirmations();
			for (SubjectConfirmation subConf : subConfs) {
				subConf.getSubjectConfirmationData().setInResponseTo("");
			}
			addTargetSPAttributes(assertion);
			response.setInResponseTo("");
			SAMLUtil.sign(assertion, getX509Credentials(null));
			SPTestRunner.getInstance().setSamlResponse(SAMLUtil.toXML(response));
			Boolean loginInvalidIRTIdP = SPTestRunner.getInstance().attemptLogin(browser, false);

			if (loginInvalidIRTIdP == null) {
				logger.debug("The login attempt could not be completed");
				return false;
			}
			else if (!loginInvalidIRTIdP) {
				resultMessage = "The Service Provider correctly verified that the InResponseTo attribute is not present on IdP-initiated logins";
				return true;
			}
			else {
				resultMessage = "The Service Provider did not verify that the InResponseTo attribute is omitted for IdP-initiated logins";
				return false;
			}
		}
	}

	/**
	 * Tests the following part of the SAML 2.0 Web Browser SSO Profile:
	 * 
	 * If an <AuthnStatement> used to establish a security context for the principal contains a SessionNotOnOrAfter attribute, the security
	 * context SHOULD be discarded once this time is reached, unless the service provider reestablishes the principal's identity by
	 * repeating the use of this profile.
	 * 
	 * Tested by trying to log in to the target SP with a Response that has a valid, but short, SessionNotOnOrAfter attribute, then checking that
	 * you are still logged in after a page refresh. Then we disable the mock IdP so the SP can't re-authenticate and we wait for the session to
	 * become invalid and check that we are no longer logged in after a page refresh.
	 * 
	 * @author RiaasM
	 */
	public class LoginSessionValidity implements LoginTestCase {
		private String resultMessage;
	
		@Override
		public String getDescription() {
			return "Test if the Service Provider discards the security context when a SessionNotOnOrAfter is provided";
		}
	
		@Override
		public String getResultMessage() {
			return resultMessage;
		}
	
		@Override
		public boolean isMandatory() {
			return true;
		}

		@Override
		public boolean checkLogin() {
			// get a browser to test in
			WebClient browser = SPTestRunner.getInstance().getNewBrowser();
			// define the variables that can be used to store the components of the Response messages
			Response response;
			List<Assertion> assertions;
			Assertion assertion;
			
			response = createMinimalWebSSOResponse(PLACEHOLDER_REQUESTID, PLACEHOLDER_ACSURL);
			assertions = response.getAssertions();
			assertion = assertions.get(0);
			List<AuthnStatement> authnstatements = assertion.getAuthnStatements();
			for (AuthnStatement authnstatement : authnstatements) {
				// make the session valid for 5 seconds
				authnstatement.setSessionNotOnOrAfter(DateTime.now().plusMillis(5000));
			}
			addTargetSPAttributes(assertion);
			SAMLUtil.sign(assertion, getX509Credentials(null));
			SPTestRunner.getInstance().setSamlResponse(SAMLUtil.toXML(response));
			Boolean loginSessionValidity = SPTestRunner.getInstance().attemptLogin(browser, true);
	
			if (loginSessionValidity == null){
				resultMessage = "The login attempt could not be completed";
				return false;
			}
			else if (!loginSessionValidity) {
				resultMessage = "The Service Provider's session's validity could not be verified because the login failed";
				return false;
			}
	
			/**
			 * Check the session's validity
			 */
			try {
				// retrieve the current page from the browser
				HtmlPage curPage = (HtmlPage) browser.getCurrentWindow().getEnclosedPage();
				// refresh the page
				curPage.refresh();
				// check if you're still logged in and wait until the session is invalid
				if (!SPTestRunner.getInstance().checkLoginContent(curPage) || !SPTestRunner.getInstance().checkLoginCookies(browser.getCookies(curPage.getUrl()))
						|| !SPTestRunner.getInstance().checkLoginHTTPStatusCode(curPage) || !SPTestRunner.getInstance().checkLoginURL(curPage)) {
					resultMessage = "The Service Provider loses its login status after a refresh while the session is still valid";
					return false;
				}
				// disable the mock IdP so the SP can't re-authenticate the session
				SPTestRunner.getInstance().killMockServer();
				
				// wait till the session is no longer valid 
				// (which is the amount of time that is acceptable as clockskew + the session validity period of 1 second + an additional second to make sure we are indeed outside of the validity period)
				Thread.sleep(SPTestRunner.getInstance().getSPConfig().getClockSkew() + 5000 + 1000);
				// refresh the page and check if you're still logged in
				curPage.refresh();
				// check if you're still logged in
				if (SPTestRunner.getInstance().checkLoginContent(curPage) && SPTestRunner.getInstance().checkLoginCookies(browser.getCookies(curPage.getUrl()))
						&& SPTestRunner.getInstance().checkLoginHTTPStatusCode(curPage) && SPTestRunner.getInstance().checkLoginURL(curPage)) {
					resultMessage = "The Service Provider does not correctly discard the security context when a SessionNotOnOrAfter is provided ";
					return false;
				} else {
					resultMessage = "The Service Provider correctly discards the security context when a SessionNotOnOrAfter is provided ";
					return true;
				}
			} catch (FailingHttpStatusCodeException e) {
				resultMessage = "Could not retrieve browser page for the LoginTestCase";
				return false;
			} catch (MalformedURLException e) {
				resultMessage = "The URL for the start page was malformed";
				return false;
			} catch (IOException e) {
				resultMessage = "An I/O exception occurred while trying to access the start page";
				return false;
			} catch (InterruptedException e) {
				resultMessage = "The wait time intended to make the session invalid, was interrupted";
				return false;
			}
		}
	}

	/**
	 * Tests the following part of the SAML 2.0 Web Browser SSO Profile [4.1.4.5 POST-Specific Processing Rules]:
	 * 
	 * The service provider MUST ensure that bearer assertions are not replayed, by maintaining the set of used ID values for the length of
	 * time for which the assertion would be considered valid based on the NotOnOrAfter attribute in the <SubjectConfirmationData>.
	 * 
	 * Tested by trying to log in to the target SP with a Response that uses the "bearer" SAML Confirmation Method sent over the POST 
	 * binding twice, concurrently. We then try to sent the same two Responses to the target SP, which should reject both. 
	 * 
	 * @author RiaasM
	 */
	public class LoginBearerReplay implements LoginTestCase {
		private String resultMessage;

		@Override
		public String getDescription() {
			return "Test if the Service Provider ensures that bearer assertions are not replayed";
		}

		@Override
		public String getResultMessage() {
			return resultMessage;
		}

		@Override
		public boolean isMandatory() {
			return true;
		}

		@Override
		public boolean checkLogin() {
			// get a browser to test in
			WebClient browser = SPTestRunner.getInstance().getNewBrowser();
			// define the variables that can be used to store the components of the Response messages
			Response response;
			List<Assertion> assertions;
			Assertion assertion;
			
			response = createMinimalWebSSOResponse(PLACEHOLDER_REQUESTID, PLACEHOLDER_ACSURL);
			assertions = response.getAssertions();
			assertion = assertions.get(0);
			addTargetSPAttributes(assertion);
			SAMLUtil.sign(assertion, getX509Credentials(null));
			String responseBearer1 = SAMLUtil.toXML(response);
			SPTestRunner.getInstance().setSamlResponse(responseBearer1);
			Boolean loginBearer1 = SPTestRunner.getInstance().attemptLogin(browser, true);
			
			if (loginBearer1 == null){
				resultMessage = "The login attempt could not be completed";
				return false;
			}
			else if (!loginBearer1) {
				resultMessage = "The test could not be run because we could not login in with a valid Response";
				return false;
			}
			// create a second browser with the same options as the current browser
			WebClient secondBrowser = SPTestRunner.getInstance().getNewBrowser();
			
			// start another login attempt in the second browser
			response = null;
			assertions = null;
			assertion = null;
			
			SPTestRunner.getInstance().attemptLogin(secondBrowser, true);
			response = createMinimalWebSSOResponse(PLACEHOLDER_REQUESTID, PLACEHOLDER_ACSURL);
			assertions = response.getAssertions();
			assertion = assertions.get(0);
			addTargetSPAttributes(assertion);
			SAMLUtil.sign(assertion, getX509Credentials(null));
			String responseBearer2 = SAMLUtil.toXML(response);
			SPTestRunner.getInstance().setSamlResponse(responseBearer2);
			Boolean loginBearer2 = SPTestRunner.getInstance().attemptLogin(secondBrowser, true);

			if (loginBearer2 == null){
				resultMessage = "The login attempt could not be completed";
				return false;
			}
			else if (!loginBearer2) {
				resultMessage = "The test could not be run because we could not login in with a valid Response";
				return false;
			}
			
			/**
			 * Check that logging in with the same responses is not allowed
			 */
			
			browser = SPTestRunner.getInstance().getNewBrowser();
			secondBrowser = SPTestRunner.getInstance().getNewBrowser();
			
			SPTestRunner.getInstance().setSamlResponse(responseBearer1);
			SPTestRunner.getInstance().attemptLogin(browser, true);
			Boolean loginBearer1Replay = SPTestRunner.getInstance().attemptLogin(browser, true);
			SPTestRunner.getInstance().setSamlResponse(responseBearer2);
			SPTestRunner.getInstance().attemptLogin(secondBrowser, true);
			Boolean loginBearer2Replay = SPTestRunner.getInstance().attemptLogin(secondBrowser, true);
			
			if(loginBearer1Replay || loginBearer2Replay){
				resultMessage = "The Service Provider does not ensure that bearer assertions are not replayed";
				return false;
			}
			else{
				resultMessage = "The Service Provider ensures that bearer assertions are not replayed";
				return true;
			}
		}
	}

	/**
	 * Tests the following part of the SAML 2.0 Web Browser SSO Profile:
	 * 
	 * Verify that any assertions relied upon are valid in other respects. Any assertion which is not valid, or whose subject confirmation
	 * requirements cannot be met SHOULD be discarded and SHOULD NOT be used to establish a security context for the principal.
	 * 
	 * Tested by trying to log in to the target SP with: 
	 * 	- a Response that has one valid Assertion with AuthnStatement in it 
	 * 		- This should log in correctly 
	 * 	- a Response that has one Assertion that has a subjectconfirmation with an invalid Address (all other attributes are already tested separately anyway)  
	 * 		- This should fail to log in
	 * 	- a Response that has one Assertion that has an invalid NotBefore date (1 hour after now) on the Conditions element 
	 * 		- This should fail to log in
	 * 	- a Response that has one Assertion that has an invalid NotOnOrAfter date (1 hour before now) on the Conditions element 
	 * 		- This should fail to log in
	 * - a Response that has one Assertion that has an invalid AudienceRestriction element
	 * 		- This should fail to log in
	 * - A Response that has two Assertions, one invalid and one valid, both containing sufficient data for authentication (i.e. SubjectConfirmation and AuthnStatement elements)
	 * 		- This should log in correctly (disabled for now, might be too extensive for testing purposes)
	 * 
	 * @author RiaasM
	 */
	public class LoginAssertionValidation implements LoginTestCase {
		private String resultMessage;
	
		@Override
		public String getDescription() {
			return "Test if the Service Provider correctly verifies the validity of any assertions that are relied upon";
		}
	
		@Override
		public String getResultMessage() {
			return resultMessage;
		}
	
		@Override
		public boolean isMandatory() {
			return false;
		}
		
		@Override
		public boolean checkLogin() {
			// get a browser to test in
			WebClient browser = SPTestRunner.getInstance().getNewBrowser();
			// define the variables that can be used to store the components of the Response messages
			Response response;
			List<Assertion> assertions;
			Assertion assertion;
			List<SubjectConfirmation> subConfs;
			
			/**
			 * Try to log in with a valid Assertion
			 */
			response = createMinimalWebSSOResponse(PLACEHOLDER_REQUESTID, PLACEHOLDER_ACSURL);
			assertions = response.getAssertions();
			assertion = assertions.get(0);
			// include an address attribute so we can ensure that a valid address attribute also allows correct login
			subConfs = assertion.getSubject().getSubjectConfirmations();
			for (SubjectConfirmation subConf : subConfs) {
				SubjectConfirmationData subConfData = (SubjectConfirmationData) subConf.getSubjectConfirmationData();
				// get the IP address which is visible when connecting to the mock server
				String address = null;
				try {
					Socket mockIdPConnection = new Socket(getMockServerURL().getHost(), getMockServerURL().getPort());
					address = mockIdPConnection.getLocalAddress().getHostAddress();
					mockIdPConnection.close();
				} catch (UnknownHostException e) {
					logger.error("Can not create socket connected to mock IdP server: "+ getMockServerURL().toString(), e);
				} catch (IOException e) {
					logger.error("IOException occurred on socket connected to mock IdP server: "+ getMockServerURL().toString(), e);
				}
				if (address == null){
					logger.error("Could not retrieve the IP address that is visible when connecting to the mock IdP server");
				}
				else{
					logger.debug("The Address attribute on SubjectConfirmationData for the valid Response is "+address);
					// set the attribute to a valid address, this should be the address from where the assertion is sent (i.e. the IdP's address)
					subConfData.setAddress(address);
				}
			}
			addTargetSPAttributes(assertion);
			SAMLUtil.sign(assertion, getX509Credentials(null));
			SPTestRunner.getInstance().setSamlResponse(SAMLUtil.toXML(response));
			Boolean loginValidAssertion = SPTestRunner.getInstance().attemptLogin(browser, true);

			if (loginValidAssertion == null) {
				resultMessage = "The login attempt with a valid Assertion could not be completed";
				return false;
			}
			else if (!loginValidAssertion) {
				resultMessage = "The Service Provider did not allow login with a valid Assertion in the Response message";
				return false;
			}

			/**
			 * Try to log in with an Assertion that has a subjectconfirmationdata element with an invalid Address attribute
			 */

			browser = SPTestRunner.getInstance().getNewBrowser();
			response = null;
			assertions = null;
			assertion = null;
			subConfs = null;
			
			response = createMinimalWebSSOResponse(PLACEHOLDER_REQUESTID, PLACEHOLDER_ACSURL);
			assertions = response.getAssertions();
			assertion = assertions.get(0);
			subConfs = assertion.getSubject().getSubjectConfirmations();
			for (SubjectConfirmation subConf : subConfs) {
				SubjectConfirmationData subConfData = (SubjectConfirmationData) subConf.getSubjectConfirmationData();
				// set the attribute to a non-existing IP address (but still in a valid IP address format)
				// this should normally be the IP address of the client that is logging in (i.e. the browser's IP address)
				subConfData.setAddress("255.255.255.255");
			}
			addTargetSPAttributes(assertion);
			SAMLUtil.sign(assertion, getX509Credentials(null));
			SPTestRunner.getInstance().setSamlResponse(SAMLUtil.toXML(response));
			Boolean loginInvalidAddress = SPTestRunner.getInstance().attemptLogin(browser, true);

			if (loginInvalidAddress == null) {
				logger.debug("The login attempt could not be completed");
				return false;
			}
			else if (loginInvalidAddress) {
				resultMessage = "The Service Provider did not verify if the Address attribute on the SubjectConfirmationData is valid";
				return false;
			}
			
			/**
			 * Try to log in with an Assertion that has an invalid NotBefore date on the Conditions element
			 */

			browser = SPTestRunner.getInstance().getNewBrowser();
			response = null;
			assertions = null;
			assertion = null;
			subConfs = null;
			
			response = createMinimalWebSSOResponse(PLACEHOLDER_REQUESTID, PLACEHOLDER_ACSURL);
			assertions = response.getAssertions();
			assertion = assertions.get(0);
			// create Conditions element with invalid NotBefore attribute
			assertion.getConditions().setNotBefore(DateTime.now().plusHours(1));
			addTargetSPAttributes(assertion);
			SAMLUtil.sign(assertion, getX509Credentials(null));
			SPTestRunner.getInstance().setSamlResponse(SAMLUtil.toXML(response));
			Boolean loginInvalidNotBefore = SPTestRunner.getInstance().attemptLogin(browser, true);

			if (loginInvalidNotBefore == null) {
				logger.debug("The login attempt could not be completed");
				return false;
			}
			else if (loginInvalidNotBefore) {
				resultMessage = "The Service Provider did not verify the NotBefore time on the Conditions element";
				return false;
			}
			
			/**
			 * Try to log in with an Assertion that has an invalid NotOnOrAfter date on the Conditions element
			 */

			browser = SPTestRunner.getInstance().getNewBrowser();
			response = null;
			assertions = null;
			assertion = null;
			subConfs = null;
			
			response = createMinimalWebSSOResponse(PLACEHOLDER_REQUESTID, PLACEHOLDER_ACSURL);
			assertions = response.getAssertions();
			assertion = assertions.get(0);
			subConfs = assertion.getSubject().getSubjectConfirmations();
			// create Conditions element with invalid NotOnOrAfter attribute
			assertion.getConditions().setNotOnOrAfter(DateTime.now().minusHours(1));
			
			addTargetSPAttributes(assertion);
			SAMLUtil.sign(assertion, getX509Credentials(null));
			SPTestRunner.getInstance().setSamlResponse(SAMLUtil.toXML(response));
			Boolean loginInvalidNotOnOrAfter = SPTestRunner.getInstance().attemptLogin(browser, true);

			if (loginInvalidNotOnOrAfter == null) {
				logger.debug("The login attempt could not be completed");
				return false;
			}
			else if (loginInvalidNotOnOrAfter) {
				resultMessage = "The Service Provider did not verify the NotOnOrAfter time on the Conditions element";
				return false;
			}
			
			/**
			 * Try to log in with an Assertion that has an invalid AudienceRestriction element
			 */

			browser = SPTestRunner.getInstance().getNewBrowser();
			response = null;
			assertions = null;
			assertion = null;
			subConfs = null;
			
			response = createMinimalWebSSOResponse(PLACEHOLDER_REQUESTID, PLACEHOLDER_ACSURL);
			assertions = response.getAssertions();
			assertion = assertions.get(0);
			// set the invalid audience value (but make sure it is still a valid URI)
			// (note that the minimal response created by SAMLUtil has only 1 audiencerestriction with only 1 audience)
			assertion.getConditions().getAudienceRestrictions().get(0).getAudiences().get(0).setAudienceURI("http://www.topdesk.com/");
			addTargetSPAttributes(assertion);
			SAMLUtil.sign(assertion, getX509Credentials(null));
			SPTestRunner.getInstance().setSamlResponse(SAMLUtil.toXML(response));
			Boolean loginInvalidAudienceRestriction = SPTestRunner.getInstance().attemptLogin(browser, true);

			if (loginInvalidAudienceRestriction == null) {
				logger.debug("The login attempt could not be completed");
				return false;
			}
			else if (loginInvalidAudienceRestriction) {
				resultMessage = "The Service Provider did not verify the AudienceRestriction element";
				return false;
			}
			
			/**
			 * Try to log in with two Assertions, one invalid and one valid, both containing sufficient data for authentication (i.e. SubjectConfirmation and AuthnStatement elements)
			 * (this may be a bit overkill for the purpose of testing the validity of assertions)
			 */

			/*browser = SPTestRunner.getInstance().getNewBrowser();
			response = null;
			assertions = null;
			assertion = null;
			subConfs = null;
			
			response = createMinimalWebSSOResponse(PLACEHOLDER_REQUESTID, PLACEHOLDER_ACSURL);
			assertions = response.getAssertions();
			assertion = assertions.get(0);
			subConfs = assertion.getSubject().getSubjectConfirmations();
			for (SubjectConfirmation subConf : subConfs) {
				SubjectConfirmationData subConfData = (SubjectConfirmationData) subConf.getSubjectConfirmationData();
				// set the attribute to a invalid address (but still a valid URL), this should normally be the address from where the assertion is sent (i.e. the IdP's address)
				subConfData.setAddress("http://www.topdesk.com/");
			}
			// create Conditions element with invalid NotOnOrAfter attribute
			assertion.getConditions().setNotOnOrAfter(DateTime.now().minusHours(1));
			// create Conditions element with invalid NotBefore attribute
			assertion.getConditions().setNotBefore(DateTime.now().plusHours(1));
			
			addTargetSPAttributes(assertion);
			// create a second, valid assertion 
			Assertion validAssertion = createMinimalAssertion(requestID);
			// sign the assertion
			SAMLUtil.sign(validAssertion, getX509Credentials(null));
			// add the attributes required by the target SP
			addTargetSPAttributes(validAssertion);
			// add the assertion to the response
			response.getAssertions().add(validAssertion);
			
			SPTestRunner.getInstance().setSamlResponse(SAMLUtil.toXML(response));
			Boolean loginInvalidAndValidAssertions = SPTestRunner.getInstance().attemptLogin(browser, true);

			if (loginInvalidAndValidAssertions == null) {
				logger.debug("The login attempt could not be completed");
				return false;
			}
			else if (!loginInvalidAndValidAssertions) {
				resultMessage = "The Service Provider did not use the available, valid assertion to authenticate when an invalid assertion was also provided";
				return false;
			}*/
			// none of the tests failed, so this target SP works correctly
			resultMessage = "The Service Provider correctly verified the validity of any assertions that are relied upon";
			return true;
		}
	}
}
