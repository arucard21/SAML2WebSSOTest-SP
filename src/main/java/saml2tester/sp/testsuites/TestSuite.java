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

import org.w3c.dom.Document;

import saml2tester.common.TestStatus;
import saml2tester.sp.LoginAttempt;

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
			System.err.println("The URL of the mock IdP was malformed");
			e.printStackTrace();
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
				e.printStackTrace();
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
				e.printStackTrace();
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
