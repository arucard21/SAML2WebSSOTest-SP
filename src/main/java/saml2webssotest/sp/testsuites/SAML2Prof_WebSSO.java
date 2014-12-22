package saml2webssotest.sp.testsuites;

import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;
import java.security.GeneralSecurityException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.List;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

import org.joda.time.DateTime;
import org.opensaml.saml2.core.AuthnStatement;
import org.opensaml.saml2.core.SubjectConfirmationData;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.Response;
import org.opensaml.saml2.core.SubjectConfirmation;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import com.gargoylesoftware.htmlunit.FailingHttpStatusCodeException;
import com.gargoylesoftware.htmlunit.WebClient;
import com.gargoylesoftware.htmlunit.html.HtmlPage;

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
				if (!acsURL.getProtocol().equalsIgnoreCase("https")) {
					resultMessage = "The Service Provider's AssertionConsumerService is not made available over HTTPS";
					return TestStatus.ERROR;
				}
				
				// Create a trust manager that does not validate certificate chains
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
					return TestStatus.OK;
				} else if (CipherSuiteNames.sslv3.contains(cipher)) {
					// cipher is part of SSLv3 protocol
					resultMessage = "The Service Provider's AssertionConsumerService uses SSL 3.0";
					return TestStatus.OK;
				} else {
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
			if (issuers.getLength() > 0) {
				resultMessage = "The Service Provider's Authentication Requests contains an Issuer";
				return TestStatus.OK;
			} else {
				resultMessage = "The Service Provider's Authentication Requests did not contain an Issuer";
				return TestStatus.ERROR;
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
			if (issuers.getLength() == 0) {
				resultMessage = "The Service Provider's Authentication Requests did not contain an Issuer";
				return TestStatus.CRITICAL;
			}
			// check if all issuers (should only be 1) have the SP's Entity ID
			// as its value
			for (int i = 0; i < issuers.getLength(); i++) {
				Node issue = issuers.item(i);
				if (!issue.getTextContent().equalsIgnoreCase(SPTestRunner.getSPConfig().getMDAttribute(MD.ENTITYDESCRIPTOR, MD.ENTITYID))) {
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
					+ SAMLmisc.NAMEID_FORMAT_ENTITY + "(MUST requirement)";
		}

		@Override
		public String getResultMessage() {
			return resultMessage;
		}

		@Override
		public TestStatus checkRequest(String request, String binding) {
			NodeList issuers = SAMLUtil.fromXML(request).getElementsByTagNameNS(SAML.NAMESPACE, SAML.ISSUER);
			// check if the issuer was found
			if (issuers.getLength() == 0) {
				resultMessage = "The Service Provider's Authentication Requests did not contain an Issuer";
				return TestStatus.CRITICAL;
			}
			// check if the issuer(s) has the SP's Entity ID as its value
			for (int i = 0; i < issuers.getLength(); i++) {
				Node issue = issuers.item(i);
				Node format = issue.getAttributes().getNamedItem(SAMLmisc.FORMAT);
				if (format != null && !format.getNodeValue().equalsIgnoreCase(SAMLmisc.NAMEID_FORMAT_ENTITY)) {
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
			if (subjects.getLength() == 0) {
				resultMessage = "The Service Provider's Authentication Requests did not contain any Subject elements";
				return TestStatus.OK;
			}
			// check if the request contains any Subject element
			NodeList subjectconfs = SAMLUtil.fromXML(request).getElementsByTagNameNS(SAML.NAMESPACE, SAML.SUBJECTCONFIRMATION);
			if (subjectconfs.getLength() == 0) {
				resultMessage = "The Service Provider's Authentication Requests contained only Subject elements without any SubjectConfirmation elements";
				return TestStatus.OK;
			} else {
				resultMessage = "The Service Provider's Authentication Requests contained Subject elements as well as SubjectConfirmation elements";
				return TestStatus.ERROR;
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
			return "Test if the Service Provider correctly verifies the signatures on the assertion and response (MUST requirement)";
		}

		@Override
		public String getResultMessage() {
			return resultMessage;
		}

		@Override
		public TestStatus checkLogin() {
			// get a browser to test in
			WebClient browser = SPTestRunner.getNewBrowser();
			// define the variables that can be used to store the components of the Response messages
			String requestID;
			Response response;
			List<Assertion> assertions;
			Assertion assertion;
			List<SubjectConfirmation> subConfs;
			Node acs;
			
			// initiate the login attempt at the target SP
			acs = SPTestRunner.initiateLoginAttempt(browser, true);
			// retrieve the ID of the AuthnRequest
			requestID = SAMLUtil.getSamlMessageID(SPTestRunner.getAuthnRequest());
			// create the minimally required (by the SAML Web SSO profile) Response 
			response = createMinimalWebSSOResponse();
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
			// set the InReplyTo attribute on the SubjectConfirmationData element of every SubjectConfirmations element
			subConfs = assertion.getSubject().getSubjectConfirmations();
			for (SubjectConfirmation subconf : subConfs) {
				subconf.getSubjectConfirmationData().setInResponseTo(requestID);
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
			// set the InResponseTo attribute on the Response element
			response.setInResponseTo(requestID);
			// sign the Response element
			SAMLUtil.sign(response, getX509Credentials(null));
			// complete the login attempt 
			Boolean loginValidSigResponse = SPTestRunner.completeLoginAttempt(browser, acs, SAMLUtil.toXML(response));
			// make sure a valid login attempt will succeed before continuing the test case
			if (loginValidSigResponse == null) {
				resultMessage = "The login attempt could not be completed";
				return TestStatus.CRITICAL;
			} else if (!loginValidSigResponse) {
				resultMessage = "The Service Provider does not allow login with a correctly signed Response message";
				return TestStatus.ERROR;
			}
			logger.debug("The Service Provider allows logins with a correctly signed Response message");
			// reset the browser so you don't remember any login information 
			browser = SPTestRunner.getNewBrowser();
			// reset the Response variables so you don't accidentally re-use old data
			requestID = null;
			response = null;
			assertions = null;
			assertion = null;
			subConfs = null;
			acs = null;

			acs = SPTestRunner.initiateLoginAttempt(browser, true);
			requestID = SAMLUtil.getSamlMessageID(SPTestRunner.getAuthnRequest());
			response = createMinimalWebSSOResponse();
			assertions = response.getAssertions();
			assertion = assertions.get(0);
			subConfs = assertion.getSubject().getSubjectConfirmations();
			for (SubjectConfirmation subconf : subConfs) {
				subconf.getSubjectConfirmationData().setInResponseTo(requestID);
			}
			addTargetSPAttributes(assertion);
			SAMLUtil.sign(assertion, getX509Credentials(null));
			response.setInResponseTo(requestID);
			/*
			 * Note that the invalid signature is the following Base64-encoded string:
			 * "This is the invalid signature that will be encoded in Base64 and will replace the valid signature"
			 */
			Boolean loginInvalidSigAssertion = SPTestRunner.completeLoginAttempt(browser, acs,
					SAMLUtil
					.toXML(response)
					.replaceAll(
							"SignatureValue>[^<]*</",
							"SignatureValue>VGhpcyBpcyB0aGUgaW52YWxpZCBzaWduYXR1cmUgdGhhdCB3aWxsIGJlIGVuY29kZWQgaW4gQmFzZTY0IGFuZCB3aWxsIHJlcGxhY2UgdGhlIHZhbGlkIHNpZ25hdHVyZQ==</"));			
			logger.debug("Finished testing with a Response that has an invalid signature in the Assertion");

			browser = SPTestRunner.getNewBrowser();
			requestID = null;
			response = null;
			assertions = null;
			assertion = null;
			subConfs = null;
			
			acs = SPTestRunner.initiateLoginAttempt(browser, true);
			requestID = SAMLUtil.getSamlMessageID(SPTestRunner.getAuthnRequest());
			response = createMinimalWebSSOResponse();
			assertions = response.getAssertions();
			if (assertions.size() > 1) {
				logger.debug("The minimal Web SSO Response was created with more than 1 Assertion");
			}
			assertion = assertions.get(0);
			subConfs = assertion.getSubject().getSubjectConfirmations();
			for (SubjectConfirmation subconf : subConfs) {
				subconf.getSubjectConfirmationData().setInResponseTo(requestID);
			}
			addTargetSPAttributes(assertion);
			response.setDestination(
					SPTestRunner
					.getSPConfig()
					.getApplicableACS(SAMLUtil.fromXML(SPTestRunner.getAuthnRequest()))
					.getAttributes()
					.getNamedItem(MD.LOCATION)
					.getNodeValue());
			response.setInResponseTo(requestID);
			SAMLUtil.sign(response, getX509Credentials(null));
			/*
			 * Note that the invalid signature is the following Base64-encoded string:
			 * "This is the invalid signature that will be encoded in Base64 and will replace the valid signature"
			 */
			Boolean loginInvalidSigResponse = SPTestRunner.completeLoginAttempt(browser, acs,
					SAMLUtil
					.toXML(response)
					.replaceAll(
							"SignatureValue>[^<]*</",
							"SignatureValue>VGhpcyBpcyB0aGUgaW52YWxpZCBzaWduYXR1cmUgdGhhdCB3aWxsIGJlIGVuY29kZWQgaW4gQmFzZTY0IGFuZCB3aWxsIHJlcGxhY2UgdGhlIHZhbGlkIHNpZ25hdHVyZQ==</"));
			logger.debug("Finished testing with a Response that has an invalid signature in the Response");

			// check the result of the login attempts with invalid signatures
			if (loginInvalidSigAssertion == null || loginInvalidSigResponse == null) {
				resultMessage = "The login attempt could not be completed";
				return TestStatus.CRITICAL;
			} else if (loginInvalidSigAssertion) {
				if (loginInvalidSigResponse) {
					resultMessage = "The Service Provider did not check the signatures on either the Assertions or the Response";
					return TestStatus.ERROR;
				} else {
					resultMessage = "The Service Provider did not check the Assertion signature";
					return TestStatus.ERROR;
				}
			} else {
				if (loginInvalidSigResponse) {
					resultMessage = "The Service Provider did not check the Response signature";
					return TestStatus.ERROR;
				} else {
					resultMessage = "The Service Provider checked the signatures on both the Assertions and the Response";
					return TestStatus.OK;
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
			return "Test if the Service Provider correctly verifies that the Recipient matches the URL on which the Response was received (MUST requirement)";
		}

		@Override
		public String getResultMessage() {
			return resultMessage;
		}

		@Override
		public TestStatus checkLogin() {
			// get a browser to test in
			WebClient browser = SPTestRunner.getNewBrowser();
			// define the variables that can be used to store the components of the Response messages
			String requestID;
			Response response;
			List<Assertion> assertions;
			Assertion assertion;
			List<SubjectConfirmation> subConfs;
			Node acs;
			/**
			 * Check if the target SP also allows a login attempt if the Recipient does match the ACS URL on which it was delivered
			 */
			acs = SPTestRunner.initiateLoginAttempt(browser, true);
			requestID = SAMLUtil.getSamlMessageID(SPTestRunner.getAuthnRequest());
			response = createMinimalWebSSOResponse();
			assertions = response.getAssertions();
			assertion = assertions.get(0);
			subConfs = assertion.getSubject().getSubjectConfirmations();
			for (SubjectConfirmation subconf : subConfs) {
				subconf.getSubjectConfirmationData().setInResponseTo(requestID);
			}
			addTargetSPAttributes(assertion);
			SAMLUtil.sign(assertion, getX509Credentials(null));
			response.setInResponseTo(requestID);
			Boolean loginValidRecipient = SPTestRunner.completeLoginAttempt(browser, acs, SAMLUtil.toXML(response));

			if (loginValidRecipient == null) {
				logger.debug("The login attempt could not be completed");
				return TestStatus.CRITICAL;
			}
			else if (!loginValidRecipient) {
				resultMessage = "The Service Provider did not allow login with a valid Recipient in the Response message";
				return TestStatus.ERROR;
			}
			logger.debug("The Service Provider allowed login with a valid Recipient in the Response message");
			
			/**
			 * Check if the target SP rejects a login attempt when the Recipient does not match the ACS URL on which it was delivered
			 */
			browser = SPTestRunner.getNewBrowser();
			requestID = null;
			response = null;
			assertions = null;
			assertion = null;
			subConfs = null;
			acs = null;
			
			acs = SPTestRunner.initiateLoginAttempt(browser, true);
			requestID = SAMLUtil.getSamlMessageID(SPTestRunner.getAuthnRequest());
			response = createMinimalWebSSOResponse();
			assertions = response.getAssertions();
			assertion = assertions.get(0);
			subConfs = assertion.getSubject().getSubjectConfirmations();
			for (SubjectConfirmation subConf : subConfs) {
				SubjectConfirmationData subConfData = (SubjectConfirmationData) subConf.getSubjectConfirmationData();
				subConfData.setInResponseTo(requestID);
				// set the recipient to an invalid location (that is still a valid URL)
				subConfData.setRecipient("http://www.topdesk.com/");
			}
			addTargetSPAttributes(assertion);
			SAMLUtil.sign(assertion, getX509Credentials(null));
			response.setInResponseTo(requestID);
			Boolean loginInvalidRecipient = SPTestRunner.completeLoginAttempt(browser, acs, SAMLUtil.toXML(response));

			if (loginInvalidRecipient == null) {
				resultMessage = "The login attempt could not be completed";
				return TestStatus.CRITICAL;
			}
			else if (loginInvalidRecipient) {
				resultMessage = "The Service Provider did not verify if the Recipient matches the URL on which the Response was received";
				return TestStatus.ERROR;
			}
			else{
				resultMessage = "The Service Provider correctly verifies if the Recipient matches the URL on which the Response was received";
				return TestStatus.OK;
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
			return "Test if the Service Provider correctly verifies that the NotOnOrAfter time has not passed (MUST requirement)";
		}

		@Override
		public String getResultMessage() {
			return resultMessage;
		}

		@Override
		public TestStatus checkLogin() {
			// get a browser to test in
			WebClient browser = SPTestRunner.getNewBrowser();
			// define the variables that can be used to store the components of the Response messages
			String requestID;
			Response response;
			List<Assertion> assertions;
			Assertion assertion;
			List<SubjectConfirmation> subConfs;
			Node acs;

			/**
			 * Check if the target SP allows a login attempt if the NotOnOrAfter time is valid
			 */

			acs = SPTestRunner.initiateLoginAttempt(browser, true);
			requestID = SAMLUtil.getSamlMessageID(SPTestRunner.getAuthnRequest());
			response = createMinimalWebSSOResponse();
			assertions = response.getAssertions();
			assertion = assertions.get(0);
			subConfs = assertion.getSubject().getSubjectConfirmations();
			for (SubjectConfirmation subconf : subConfs) {
				subconf.getSubjectConfirmationData().setInResponseTo(requestID);
			}
			addTargetSPAttributes(assertion);
			SAMLUtil.sign(assertion, getX509Credentials(null));
			response.setInResponseTo(requestID);
			Boolean loginValidNOOA = SPTestRunner.completeLoginAttempt(browser, acs, SAMLUtil.toXML(response));
			
			if (loginValidNOOA == null) {
				resultMessage = "The login attempt could not be completed";
				return TestStatus.CRITICAL;
			}
			else if (!loginValidNOOA) {
				resultMessage = "The Service Provider did not allow login with a valid NotOnOrAfter time in the Response message";
				return TestStatus.ERROR;
			}
			logger.debug("The Service Provider allowed login with a valid NotOnOrAfter time in the Response message");


			/**
			 * Check if the target SP rejects a login attempt when the Recipient does not match the ACS URL on which it was delivered
			 */

			browser = SPTestRunner.getNewBrowser();
			requestID = null;
			response = null;
			assertions = null;
			assertion = null;
			subConfs = null;
			acs = null;

			acs = SPTestRunner.initiateLoginAttempt(browser, true);
			requestID = SAMLUtil.getSamlMessageID(SPTestRunner.getAuthnRequest());
			response = createMinimalWebSSOResponse();
			assertions = response.getAssertions();
			assertion = assertions.get(0);
			subConfs = assertion.getSubject().getSubjectConfirmations();
			for (SubjectConfirmation subConf : subConfs) {
				SubjectConfirmationData subConfData = subConf.getSubjectConfirmationData();
				subConfData.setInResponseTo(requestID);
				// set the NotOnOrAfter attribute to now so it will be invalid when it arrives at the target SP
				subConfData.setNotOnOrAfter(DateTime.now());
			}
			addTargetSPAttributes(assertion);
			SAMLUtil.sign(assertion, getX509Credentials(null));
			response.setInResponseTo(requestID);
			// wait for the same amount of time as the clock skew on the target SP to make sure
			// the Response can't be made valid due to that clock skew
			try {
				Thread.sleep(SPTestRunner.getSPConfig().getClockSkew());
			} catch (InterruptedException e) {
				resultMessage = "The wait time intended to keep the clock skew from incorrectly causing the Response to be valid, was interrupted";
				return TestStatus.CRITICAL;
			}
			Boolean loginInvalidNOOA = SPTestRunner.completeLoginAttempt(browser, acs, SAMLUtil.toXML(response));

			if (loginInvalidNOOA == null) {
				resultMessage = "The login attempt could not be completed";
				return TestStatus.CRITICAL;
			}
			if (loginInvalidNOOA) {
				resultMessage = "The Service Provider did not verify that the NotOnOrAfter time has not passed";
				return TestStatus.ERROR;
			} else {
				resultMessage = "The Service Provider correctly verified that the NotOnOrAfter time has not passed";
				return TestStatus.OK;
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
			return "Test if the Service Provider verifies that the InResponseTo ID matches the ID of the AuthnRequest (MUST requirement)";
		}

		@Override
		public String getResultMessage() {
			return resultMessage;
		}

		@Override
		public TestStatus checkLogin() {
			// get a browser to test in
			WebClient browser = SPTestRunner.getNewBrowser();
			// define the variables that can be used to store the components of the Response messages
			String requestID;
			Response response;
			List<Assertion> assertions;
			Assertion assertion;
			List<SubjectConfirmation> subConfs;
			Node acs;

			/**
			 * Check if the target SP allows a login attempt if the InResponseTo attribute is valid
			 */

			acs = SPTestRunner.initiateLoginAttempt(browser, true);
			requestID = SAMLUtil.getSamlMessageID(SPTestRunner.getAuthnRequest());
			response = createMinimalWebSSOResponse();
			assertions = response.getAssertions();
			assertion = assertions.get(0);
			subConfs = assertion.getSubject().getSubjectConfirmations();
			for (SubjectConfirmation subconf : subConfs) {
				subconf.getSubjectConfirmationData().setInResponseTo(requestID);
			}
			addTargetSPAttributes(assertion);
			SAMLUtil.sign(assertion, getX509Credentials(null));
			response.setInResponseTo(requestID);
			Boolean loginValidIRT = SPTestRunner.completeLoginAttempt(browser, acs, SAMLUtil.toXML(response));

			if (loginValidIRT == null) {
				resultMessage = "The login attempt could not be completed";
				return TestStatus.CRITICAL;
			}
			else if (!loginValidIRT) {
				resultMessage = "The Service Provider did not allow login with a valid InResponseTo attribute in the Response message";
				return TestStatus.ERROR;
			}
			logger.debug("The Service Provider allowed login with a valid InResponseTo attribute in the Response message");

			/**
			 * Check if the target SP rejects a login attempt when the InResponseTo attribute is invalid in SubjectConfirmationData
			 */

			browser = SPTestRunner.getNewBrowser();
			requestID = null;
			response = null;
			assertions = null;
			assertion = null;
			subConfs = null;
			acs = null;

			acs = SPTestRunner.initiateLoginAttempt(browser, true);
			requestID = SAMLUtil.getSamlMessageID(SPTestRunner.getAuthnRequest());
			response = createMinimalWebSSOResponse();
			assertions = response.getAssertions();
			assertion = assertions.get(0);
			subConfs = assertion.getSubject().getSubjectConfirmations();
			for (SubjectConfirmation subConf : subConfs) {
				SubjectConfirmationData subConfData = subConf.getSubjectConfirmationData();
				subConfData.setInResponseTo(requestID + "_");
			}
			addTargetSPAttributes(assertion);
			SAMLUtil.sign(assertion, getX509Credentials(null));
			response.setInResponseTo(requestID);
			Boolean loginInvalidIRTSubConfData = SPTestRunner.completeLoginAttempt(browser, acs, SAMLUtil.toXML(response));
			
			/**
			 * Check if the target SP rejects a login attempt when the InResponseTo attribute is invalid in Response
			 */

			browser = SPTestRunner.getNewBrowser();
			requestID = null;
			response = null;
			assertions = null;
			assertion = null;
			subConfs = null;
			acs = null;

			acs = SPTestRunner.initiateLoginAttempt(browser, true);
			requestID = SAMLUtil.getSamlMessageID(SPTestRunner.getAuthnRequest());
			response = createMinimalWebSSOResponse();
			assertions = response.getAssertions();
			assertion = assertions.get(0);
			subConfs = assertion.getSubject().getSubjectConfirmations();
			for (SubjectConfirmation subConf : subConfs) {
				SubjectConfirmationData subConfData = subConf.getSubjectConfirmationData();
				subConfData.setInResponseTo(requestID);
			}
			addTargetSPAttributes(assertion);
			SAMLUtil.sign(assertion, getX509Credentials(null));
			response.setInResponseTo(requestID + "_");
			Boolean loginInvalidIRTResponse = SPTestRunner.completeLoginAttempt(browser, acs, SAMLUtil.toXML(response));

			if (loginInvalidIRTSubConfData == null || loginInvalidIRTResponse == null) {
				resultMessage = "The login attempt could not be completed";
				return TestStatus.CRITICAL;
			} else if (loginInvalidIRTSubConfData) {
				if (loginInvalidIRTResponse) {
					resultMessage = "The Service Provider did not verify that the InResponseTo ID on either the SubjectConfirmationData or the Response matches the ID from the AuthnRequest";
					return TestStatus.ERROR;
				} else {
					resultMessage = "The Service Provider did not verify that the InResponseTo ID on the SubjectConfirmationData matches the ID from the AuthnRequest";
					return TestStatus.ERROR;
				}
			} else {
				if (loginInvalidIRTResponse) {
					resultMessage = "The Service Provider did not verify that the InResponseTo ID on the Response matches the ID from the AuthnRequest";
					return TestStatus.ERROR;
				} else {
					resultMessage = "The Service Provider verifed that the InResponseTo ID on both the SubjectConfirmationData and the Response matches the ID from the AuthnRequest";
					return TestStatus.OK;
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
			return "Test if the Service Provider verifies that the InResponseTo attribute is not present on IdP-initiated logins (MUST requirement)";
		}

		@Override
		public String getResultMessage() {
			return resultMessage;
		}

		@Override
		public TestStatus checkLogin() {
			// get a browser to test in
			WebClient browser = SPTestRunner.getNewBrowser();
			// define the variables that can be used to store the components of the Response messages
			Response response;
			List<Assertion> assertions;
			Assertion assertion;
			List<SubjectConfirmation> subConfs;
			Node acs;
			/**
			 * Try to log in with an unsolicited Response without the InResponseTo attribute present
			 */
			acs = SPTestRunner.initiateLoginAttempt(browser, false);
			response = createMinimalWebSSOResponse();
			assertions = response.getAssertions();
			if (assertions.size() > 1) {
				logger.debug("The minimal Web SSO Response was created with more than 1 Assertion");
			}
			assertion = assertions.get(0);
			addTargetSPAttributes(assertion);
			SAMLUtil.sign(assertion, getX509Credentials(null));
			Boolean loginValidIRTIdP = SPTestRunner.completeLoginAttempt(browser, acs, SAMLUtil.toXML(response));

			if (loginValidIRTIdP == null) {
				resultMessage = "The IdP-initiated login attempt could not be completed";
				return TestStatus.CRITICAL;
			}
			else if (!loginValidIRTIdP) {
				resultMessage = "The Service Provider did not allow login with an unsolicited Response message without an InResponseTo attribute";
				return TestStatus.ERROR;
			}
			
			/**
			 * Try to log in with an unsolicited Response with an empty InResponseTo attribute present
			 */

			browser = SPTestRunner.getNewBrowser();
			response = null;
			assertions = null;
			assertion = null;
			subConfs = null;
			acs = null;
			
			acs = SPTestRunner.initiateLoginAttempt(browser, false);
			response = createMinimalWebSSOResponse();
			assertions = response.getAssertions();
			assertion = assertions.get(0);
			subConfs = assertion.getSubject().getSubjectConfirmations();
			for (SubjectConfirmation subConf : subConfs) {
				subConf.getSubjectConfirmationData().setInResponseTo("");
			}
			addTargetSPAttributes(assertion);
			SAMLUtil.sign(assertion, getX509Credentials(null));
			response.setInResponseTo("");
			Boolean loginInvalidIRTIdP = SPTestRunner.completeLoginAttempt(browser, acs, SAMLUtil.toXML(response));

			if (loginInvalidIRTIdP == null) {
				logger.debug("The login attempt could not be completed");
				return TestStatus.CRITICAL;
			}
			else if (loginInvalidIRTIdP) {
				resultMessage = "The Service Provider correctly verified that the InResponseTo attribute is not present on IdP-initiated logins";
				return TestStatus.OK;
			}
			else {
				resultMessage = "The Service Provider could not perform an IdP-initiated login";
				return TestStatus.CRITICAL;
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
	 * you are still logged in after a page refresh. Then we wait for the session to become invalid and check that we are no longer logged in 
	 * after a page refresh.
	 * 
	 * @author RiaasM
	 */
	public class LoginSessionValidity implements LoginTestCase {
		private String resultMessage;
	
		@Override
		public String getDescription() {
			return "Test if the Service Provider discards the security context when a SessionNotOnOrAfter is provided (MUST requirement)";
		}
	
		@Override
		public String getResultMessage() {
			return resultMessage;
		}
	
		@Override
		public TestStatus checkLogin() {
			// get a browser to test in
			WebClient browser = SPTestRunner.getNewBrowser();
			// define the variables that can be used to store the components of the Response messages
			String requestID;
			Response response;
			List<Assertion> assertions;
			Assertion assertion;
			List<SubjectConfirmation> subConfs;
			Node acs;
	
			acs = SPTestRunner.initiateLoginAttempt(browser, true);
			requestID = SAMLUtil.getSamlMessageID(SPTestRunner.getAuthnRequest());
			response = createMinimalWebSSOResponse();
			assertions = response.getAssertions();
			assertion = assertions.get(0);
			subConfs = assertion.getSubject().getSubjectConfirmations();
			for (SubjectConfirmation subConf : subConfs) {
				SubjectConfirmationData subConfData = (SubjectConfirmationData) subConf.getSubjectConfirmationData();
				subConfData.setInResponseTo(requestID);
			}
			List<AuthnStatement> authnstatements = assertion.getAuthnStatements();
			for (AuthnStatement authnstatement : authnstatements) {
				// make the session valid for only a second
				authnstatement.setSessionNotOnOrAfter(DateTime.now().plusMillis(1000));
			}
			addTargetSPAttributes(assertion);
			SAMLUtil.sign(assertion, getX509Credentials(null));
			response.setInResponseTo(requestID);
			Boolean loginSessionValidity = SPTestRunner.completeLoginAttempt(browser, acs, SAMLUtil.toXML(response));
	
			if (loginSessionValidity == null){
				resultMessage = "The login attempt could not be completed";
				return TestStatus.CRITICAL;
			}
			else if (!loginSessionValidity) {
				resultMessage = "The Service Provider's session's validity could not be verified because the login failed";
				return TestStatus.CRITICAL;
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
				if (!SPTestRunner.checkLoginContent(curPage) || !SPTestRunner.checkLoginCookies(browser.getCookies(curPage.getUrl()))
						|| !SPTestRunner.checkLoginHTTPStatusCode(curPage) || !SPTestRunner.checkLoginURL(curPage)) {
					resultMessage = "The Service Provider loses its login status after a refresh which should not happen";
					return TestStatus.ERROR;
				}
				// wait till the session is no longer valid
				Thread.sleep(SPTestRunner.getSPConfig().getClockSkew() + 1000);
				// refresh the page and check if you're still logged in
				curPage.refresh();
				// check if you're still logged in
				if (SPTestRunner.checkLoginContent(curPage) && SPTestRunner.checkLoginCookies(browser.getCookies(curPage.getUrl()))
						&& SPTestRunner.checkLoginHTTPStatusCode(curPage) && SPTestRunner.checkLoginURL(curPage)) {
					resultMessage = "The Service Provider does not correctly discard the security context when a SessionNotOnOrAfter is provided ";
					return TestStatus.ERROR;
				} else {
					resultMessage = "The Service Provider correctly discards the security context when a SessionNotOnOrAfter is provided ";
					return TestStatus.OK;
				}
			} catch (FailingHttpStatusCodeException e) {
				resultMessage = "Could not retrieve browser page for the LoginTestCase";
				return TestStatus.CRITICAL;
			} catch (MalformedURLException e) {
				resultMessage = "The URL for the start page was malformed";
				return TestStatus.CRITICAL;
			} catch (IOException e) {
				resultMessage = "An I/O exception occurred while trying to access the start page";
				return TestStatus.CRITICAL;
			} catch (InterruptedException e) {
				resultMessage = "The wait time intended to make the session invalid, was interrupted";
				return TestStatus.CRITICAL;
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
			return "Test if the Service Provider ensures that bearer assertions are not replayed (MUST requirement)";
		}

		@Override
		public String getResultMessage() {
			return resultMessage;
		}

		@Override
		public TestStatus checkLogin() {
			// TODO: This one still fails on TD55, maybe something to do with the linkinteraction, got tried 3 times and log is totally full (loop maybe)
			
			// get a browser to test in
			WebClient browser = SPTestRunner.getNewBrowser();
			// define the variables that can be used to store the components of the Response messages
			String requestID;
			Response response;
			List<Assertion> assertions;
			Assertion assertion;
			List<SubjectConfirmation> subConfs;
			Node acs;

			acs = SPTestRunner.initiateLoginAttempt(browser, true);
			requestID = SAMLUtil.getSamlMessageID(SPTestRunner.getAuthnRequest());
			response = createMinimalWebSSOResponse();
			assertions = response.getAssertions();
			assertion = assertions.get(0);
			subConfs = assertion.getSubject().getSubjectConfirmations();
			for (SubjectConfirmation subConf : subConfs) {
				SubjectConfirmationData subConfData = (SubjectConfirmationData) subConf.getSubjectConfirmationData();
				subConfData.setInResponseTo(requestID);
			}
			addTargetSPAttributes(assertion);
			SAMLUtil.sign(assertion, getX509Credentials(null));
			response.setInResponseTo(requestID);
			String responseBearer1 = SAMLUtil.toXML(response);
			Boolean loginBearer1 = SPTestRunner.completeLoginAttempt(browser, acs, responseBearer1);

			if (loginBearer1 == null){
				resultMessage = "The login attempt could not be completed";
				return TestStatus.CRITICAL;
			}
			else if (!loginBearer1) {
				resultMessage = "The test could not be run because the initial login failed";
				return TestStatus.CRITICAL;
			}
			// create a second browser with the same options as the current browser
			WebClient secondBrowser = SPTestRunner.getNewBrowser();
			
			// start another login attempt in the second browser
			response = null;
			assertions = null;
			assertion = null;
			subConfs = null;
			acs = null;
			
			acs = SPTestRunner.initiateLoginAttempt(secondBrowser, true);
			requestID = SAMLUtil.getSamlMessageID(SPTestRunner.getAuthnRequest());
			response = createMinimalWebSSOResponse();
			assertions = response.getAssertions();
			assertion = assertions.get(0);
			subConfs = assertion.getSubject().getSubjectConfirmations();
			for (SubjectConfirmation subConf : subConfs) {
				SubjectConfirmationData subConfData = (SubjectConfirmationData) subConf.getSubjectConfirmationData();
				subConfData.setInResponseTo(requestID);
			}
			addTargetSPAttributes(assertion);
			SAMLUtil.sign(assertion, getX509Credentials(null));
			response.setInResponseTo(requestID);
			String responseBearer2 = SAMLUtil.toXML(response);
			Boolean loginBearer2 = SPTestRunner.completeLoginAttempt(secondBrowser, acs, responseBearer2);

			if (loginBearer2 == null){
				resultMessage = "The login attempt could not be completed";
				return TestStatus.CRITICAL;
			}
			else if (!loginBearer2) {
				resultMessage = "The test could not be run because the initial login failed";
				return TestStatus.CRITICAL;
			}
			
			/**
			 * Check that logging in with the same responses is not allowed
			 */
			
			browser = SPTestRunner.getNewBrowser();
			secondBrowser = SPTestRunner.getNewBrowser();
			
			acs = SPTestRunner.initiateLoginAttempt(browser, true);
			Boolean loginBearer1Replay = SPTestRunner.completeLoginAttempt(browser, acs, responseBearer1);
			acs = SPTestRunner.initiateLoginAttempt(secondBrowser, true);
			Boolean loginBearer2Replay = SPTestRunner.completeLoginAttempt(secondBrowser, acs, responseBearer2);
			
			if(loginBearer1Replay || loginBearer2Replay){
				resultMessage = "The Service Provider does not ensure that bearer assertions are not replayed";
				return TestStatus.ERROR;
			}
			else{
				resultMessage = "The Service Provider ensures that bearer assertions are not replayed";
				return TestStatus.ERROR;
			}
		}
	}
}
