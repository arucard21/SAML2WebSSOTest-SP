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
	 * The LoginAttempt object can be used to define a login attempt at an SP
	 * 
	 * You must define the Response message that should be sent to the SP to see how the SP handles this.
	 */
	public class LoginAttempt {

		private boolean spInitiated;
		private String response;
		
		/**
		 * Create the LoginAttempt object.
		 * 
		 * @param spInitiated specifies if the login attempt should be SP-initiated
		 * @param response is the SAML Response message that the mock IdP should send to the SP 
		 */
		public LoginAttempt(boolean spInitiated, String response){
			this.spInitiated = spInitiated;
			this.response = response;
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
		public String getResponse(){
			return this.response;
		}

	}
	/**
	 * The base class for all test cases. Defines the variables and methods that are required for the test runner to correctly run
	 * the test case.
	 * 
	 * In the test case you can define what should be checked in the SAML SP Metadata or in the SAML Request. You can also
	 * provide LoginAttempt objects that specify the logins attempts that should be tested on the SP.  
	 * 
	 * @author RiaasM
	 *
	 */
	public abstract class BaseTestCase{
		/**
		 * The human-readable name of the test case
		 */
		public String testcase_name = "";
		/**
		 * The description of the test case
		 */
		public String testcase_description = "";
		/**
		 * Specify if the metadata should be tested
		 */
		public boolean testMetadata = false;
		/**
		 * Specify if the request should be tested
		 */
		public boolean testRequest = false;
		/**
		 * A list of the login attempts that should be tested on the SP
		 */
		public List<LoginAttempt> loginAttempts = null;

		/**
		 * Create an instance of the test case. 
		 * 
		 * @param tc_name is the name of the test case, intended to be shown in the test results
		 * @param tc_descr is a description of the test case, intended to be shown in the test results
		 * @param loginAttempts is a list of LoginAttempt objects representing all the logins that should be attempted on the SP (can be null) 
		 */
		public BaseTestCase(String tc_name, String tc_descr, List<LoginAttempt> loginAttempts){
			testcase_name = tc_name;
			testcase_description = tc_descr;
			this.loginAttempts = loginAttempts;
		}
		
		/**
		 * Determine if the SP's Metadata should be tested.
		 * 
		 * @return true if the metadata should be tested.
		 */
		public boolean testMetadata(){
			return testMetadata;
		}
		
		/**
		 * Determine if the SP's Request message should be tested.
		 * 
		 * @return true if the Request message should be tested.
		 */
		public boolean testRequest(){
			return testRequest;
		}
		
		/**
		 * Determine if login attempts should be tested. This can only be done if login attempts have been defined.
		 * 
		 * @return true if login attempts should be tested
		 */
		public boolean testLogins(){
			return (loginAttempts != null);
		}
		
		/**
		 * Check the provided metadata.  
		 * 
		 * @return a string representing the test result in JSON format
		 */
		public abstract String checkMetadata(String metadata);
		
		/**
		 * Check the provided request for the provided binding
		 * 
		 * @return a string representing the test result in JSON format
		 */
		public abstract String checkRequest(String request, String binding);
		
		/**
		 * Retrieve the list of login attempts that should be tested on the SP.
		 * 
		 * @return the list of login attempts that should be tested on the SP.
		 */
		public List<LoginAttempt> getLoginAttempts(){
			return this.loginAttempts;
		}
		
		/**
		 * Check the results from your login attempts and return an appropriate test result.
		 * 
		 * @param loginResults is the list of results for each login attempt (true if successful, false otherwise)
		 * @return a string representing the test result in JSON format
		 */
		public abstract String checkLoginResults(List<Boolean> loginResults);
	}
}
