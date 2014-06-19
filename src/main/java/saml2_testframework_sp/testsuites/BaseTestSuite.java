package saml2_testframework_sp.testsuites;

import java.io.BufferedReader;
import java.io.IOException;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.List;

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
public abstract class BaseTestSuite {
	/**
	 * The possible values for defining how a sequence of login attempts should be evaluated
	 */
	public enum LOGINS_ATTEMPTS {
		ALL, NONE, ONE, ONEORMORE;
	}

	/**
	 * Get the IdP metadata that should be used in the mock IdP for this test suite.
	 * 
	 * This allows you to use specific IdP metadata for each test suite, which is defined in this method. 
	 * 
	 * @return: a string containing the metadata XML that should be used by the mock IdP when running tests from this test suite
	 */
	public abstract String getIdPMetadata();

	/**
	 * Retrieve the X.509 Certificate that should be used by the mock IdP as a string.
	 * 
	 * @param certLocation is a string containing the location of the certificate file that should be used (e.g. "keys/mycert.pem")
	 * @return: a string representing the X.509 Certificate
	 */
	public String getIdPCertificate(String certLocation){
		String cert = "";
		Path certPath = Paths.get(certLocation); 
		try {
			BufferedReader reader = Files.newBufferedReader(certPath, Charset.defaultCharset());
			String line;
			while ( (line = reader.readLine()) != null){
				cert += line + "\n";
			}
		} catch (IOException e) {
			e.printStackTrace();
		}
		return cert;
	}

    /**
     * Retrieve RSA private key that corresponds to the X.509 Certificate as a string.
     * 
     * @param keyLocation is a string containing the location of the private key file that should be used (e.g. "keys/mykey.pem")
     * @return: a string representing the RSA private key
     */
	public String getIdPPrivateKey(String keyLocation){
		String key = "";
		Path keyPath = Paths.get(keyLocation); 
		try {
			BufferedReader reader = Files.newBufferedReader(keyPath, Charset.defaultCharset());
			String line;
			while ( (line = reader.readLine()) != null){
				key += line + "\n";
			}
		} catch (IOException e) {
			e.printStackTrace();
		}
		return key;
	}

    /**
     * Retrieve the name of the tag that should be used as SP Endpoint. This could be the name of any of the tags of the type 
     * EndpointType or IndexedEndpointType. You can use the predefined tag variables from the saml2test.saml_builders.metadata_builders 
     * module.
     * 
     * The tag will be used to decide where the mock IdP will send its responses (e.g. the Web SSO profile you would return the name 
     * of the AssertionConsumerService tag).
     * 
     * @return: a string containing the name of the SP Endpoint tag
     */
	public abstract String get_SP_endpoint_tag();

	/**
	 * The Attribute class contains the values pertaining to a single attribute
	 */
	public class Attribute {

		private String attributeName;
		private String nameFormat;
		private String attributeValue;
		
		public Attribute(String name, String format, String value){
			attributeName = name;
			nameFormat = format;
			attributeValue = value;
		}
		
		public String getAttributeName() {
			return attributeName;
		}

		public String getNameFormat() {
			return nameFormat;
		}

		public String getAttributeValue() {
			return attributeValue;
		}
	}
	
	/**
	 * The Attribute class contains the values pertaining to a single attribute
	 */
	public abstract class LoginAttempt {
		@SuppressWarnings("unused")
		private String request = "";
		@SuppressWarnings("unused")
		private String binding = "";
		private boolean spInitiated;
		
		public LoginAttempt(boolean spInitiated){
			this.spInitiated = spInitiated;
		}
		
		/**
		 * Determine whether the login attempt should be SP-initiated. If SP-initiated, the login attempt should start at the SP and
		 * the SP should send an authentication request before the mock IdP should send a Response (which can be retrieved with the 
		 * getResponse() method).
		 * 
		 * Note that when SP-initiated login is used, you must set the request (and possibly binding) appropriately before retrieving
		 * the Response message.  
		 *  
		 * @return true if the login attempt should be SP-initiated, false otherwise, i.e. when the login should be IdP-initiated 
		 */
		public boolean isSPInitiated(){
			return this.spInitiated;
		}

		/**
		 * Get the Response message that you want to send to the SP
		 * 
		 * @return a string containing the response message
		 */
		public abstract String getResponse();
		
		/**
		 * Set the request message that was received from the SP during the login attempt.
		 * This request message can be used when generating the response which the mock IdP will return to the SP. 
		 * 
		 * @param request is the request message that should be used for generating a response
		 */
		public void setRequest(String request){
			this.request = request;
		}
		
		public void setBinding(String binding){
			this.binding = binding;
		}
	}
	/**
	 * The base class for all test cases. Contains implemented, common methods and abstract methods that are required to be
	 * implemented by all inheriting classes.
	 * 
	 * @author RiaasM
	 *
	 */
	public abstract class TestCase{
		/**
		 * The human-readable name of the test case
		 */
		public String testcase_name;
		/**
		 * The description of the test case
		 */
		public String testcase_description;
		/**
		 * The kind of error that should be given if the test case fails 
		 */
		public int testcase_error_level;
		/**
		 * Defines how the message exchanges should be evaluated.
		 */
		public final LOGINS_ATTEMPTS TESTCASE_TEST_LOGINS_SUCCEEDED = LOGINS_ATTEMPTS.ALL;

		/**
		 * Get the prerequisite tests for this test case. 
		 * 
		 * @return a List of Strings representing the prerequisite tests
		 */
		public abstract List<String> getPrerequisites();
	}
	
	/**
	 * Test case for checking the metadata provided by the SP.
	 * 
	 * @author RiaasM
	 *
	 */
	public abstract class MetadataTestCase extends TestCase {

		@SuppressWarnings("unused")
		private String metadata;

		public MetadataTestCase(String metadata){
			this.metadata = metadata;
		}
		
		/**
		 * Check the provided metadata.  
		 * 
		 * @return a string representing the test result in JSON format
		 */
		public abstract String checkMetadata();
	}

	/**
	 * Test case for checking the Request message provided by the SP for the binding used by that SP.
	 * 
	 * @author RiaasM
	 *
	 */
	public abstract class RequestTestCase extends TestCase {

		@SuppressWarnings("unused")
		private String request = "";
		@SuppressWarnings("unused")
		private String binding = "";

		public RequestTestCase(String request, String binding){
			this.request = request;
			this.binding = binding;
		}
		
		/**
		 * Check the provided request for the provided binding
		 * 
		 * @return a string representing the test result in JSON format
		 */
		public abstract String checkRequest();
	}
	
	/**
	 * Test case for testing the SP's response to certain Response messages.
	 * 
	 * @author RiaasM
	 *
	 */
	public abstract class MessageTestCase extends TestCase {

		@SuppressWarnings("unused")
		private String metadata;
		@SuppressWarnings("unused")
		private List<Attribute> attributes;
		@SuppressWarnings("unused")
		private List<LoginAttempt> loginAttempts;

		public MessageTestCase(String metadata, List<Attribute> attributes){
			this.metadata = metadata;
			this.attributes = attributes;
		}
	}
}
