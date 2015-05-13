package saml2webssotest.sp.testsuites;

import java.util.ArrayList;
import java.util.List;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.Response;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.gargoylesoftware.htmlunit.WebClient;

import saml2webssotest.common.SAMLUtil;
import saml2webssotest.common.TestSuite;
import saml2webssotest.sp.SPTestRunner;


public class SAMLBind extends SPTestSuite {
	/**
	 * Logger for this class
	 */
	private final Logger logger = LoggerFactory.getLogger(SAMLBind.class);

	@Override
	public List<TestSuite> getDependencies() {
		ArrayList<TestSuite> dependencies = new ArrayList<TestSuite>();
		return dependencies;
	}

	/**
	 * Tests the following part of the following part of the SAMLBind Profile (POST binding): 
	 * 		If the message is signed, the Destination XML attribute in the root SAML element of the protocol
	 * 		message MUST contain the URL to which the sender has instructed the user agent to deliver the
	 * 		message. The recipient MUST then verify that the value matches the location at which the message has
	 * 		been received
	 * 
	 * @author RiaasM
	 */
	public class LoginPOSTSignedResponseNoDestination implements LoginTestCase{
		private String resultMessage;

		@Override
		public String getDescription() {
			return "Test if the Service Provider verifies the value of the Destination attribute on signed Responses over the POST binding";
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
			
			/**
			 * Check if the target SP allows a login attempt if the Destination attribute is valid
			 */

			response = createMinimalWebSSOResponse(PLACEHOLDER_REQUESTID, PLACEHOLDER_ACSURL);
			assertion = response.getAssertions().get(0);
			addTargetSPAttributes(assertion);
			SAMLUtil.sign(assertion, getX509Credentials(null));
			SPTestRunner.getInstance().setSamlResponse(SAMLUtil.toXML(response));
			Boolean loginValidDestination = SPTestRunner.getInstance().attemptLogin(browser, true);

			if (loginValidDestination == null) {
				resultMessage = "The login attempt could not be completed";
				return false;
			}
			else if (!loginValidDestination) {
				resultMessage = "The Service Provider did not allow login with a valid Destination attribute in the Response message";
				return false;
			}
			logger.debug("The Service Provider allowed login with a valid Destination attribute in the Response message");

			/**
			 * Check if the target SP rejects a login attempt when the Destination attribute is invalid
			 */

			browser = SPTestRunner.getInstance().getNewBrowser();
			response = null;
			assertions = null;
			assertion = null;
			
			// create the minimally required Response with requestID placeholder
			 response = createMinimalWebSSOResponse(PLACEHOLDER_REQUESTID, PLACEHOLDER_ACSURL);
			// add attributes and sign the assertions in the response
			assertions= response.getAssertions();
			assertion = assertions.get(0);
			// add the attributes
			addTargetSPAttributes(assertion);
			SAMLUtil.sign(assertion, getX509Credentials(null));
			
			// add invalid Destination attribute that is still a URL 
			response.setDestination("http://www.topdesk.com");
			// convert the Response to a String
			String responseString = SAMLUtil.toXML(response);
			// store the response in the test runner so the mock IdP can use it
			SPTestRunner.getInstance().setSamlResponse(responseString);
			//Attempt to log in 
			Boolean login = SPTestRunner.getInstance().attemptLogin(browser, true);
			SPTestRunner.getInstance().setSamlResponse(null);
			
			/**
			 * Check the results of the login attempts
			 */
			if (login == null){
				logger.debug("The login attempt could not be completed");
				return false;
			}
			else{	
				if (login){
					resultMessage = "The Service Provider did not verify the Destination attribute on the signed Response";
					return false;
				}
				else{
					resultMessage = "The Service Provider correctly verified the Destination attribute on the signed Response";
					return true;
				}
			}	
		}
	}
}
