package saml2webssotest.sp;

import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.LinkedList;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.apache.commons.cli.BasicParser;
import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.CommandLineParser;
import org.apache.commons.cli.HelpFormatter;
import org.apache.commons.cli.Options;
import org.apache.commons.cli.ParseException;
import org.apache.http.client.ClientProtocolException;
import org.apache.log4j.BasicConfigurator;
import org.apache.log4j.PropertyConfigurator;
import org.eclipse.jetty.server.Server;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Document;
import org.w3c.dom.Node;

import com.gargoylesoftware.htmlunit.FailingHttpStatusCodeException;
import com.gargoylesoftware.htmlunit.HttpMethod;
import com.gargoylesoftware.htmlunit.WebClient;
import com.gargoylesoftware.htmlunit.WebRequest;
import com.gargoylesoftware.htmlunit.html.HtmlPage;
import com.gargoylesoftware.htmlunit.util.Cookie;
import com.gargoylesoftware.htmlunit.util.NameValuePair;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonSyntaxException;

import saml2webssotest.common.Interaction;
import saml2webssotest.common.InteractionDeserializer;
import saml2webssotest.common.MetadataDeserializer;
import saml2webssotest.common.StringPair;
import saml2webssotest.common.SAMLUtil;
import saml2webssotest.common.TestResult;
import saml2webssotest.common.TestRunnerUtil;
import saml2webssotest.common.TestStatus;
import saml2webssotest.common.TestSuite.TestCase;
import saml2webssotest.common.TestSuite.MetadataTestCase;
import saml2webssotest.common.standardNames.SAMLP;
import saml2webssotest.common.standardNames.SAMLmisc;
import saml2webssotest.sp.mockIdPHandlers.SamlWebSSOHandler;
import saml2webssotest.sp.testsuites.SPTestSuite;
import saml2webssotest.sp.testsuites.SPTestSuite.ConfigTestCase;
import saml2webssotest.sp.testsuites.SPTestSuite.LoginTestCase;
import saml2webssotest.sp.testsuites.SPTestSuite.RequestTestCase;

/**
 * This is the main class that is used to run the SP test. It will handle the
 * command-line arguments appropriately and run the test(s).
 * 
 * @author RiaasM
 * 
 */
public class SPTestRunner {
	/**
	 * Logger for this class
	 */
	private static final Logger logger = LoggerFactory.getLogger(SPTestRunner.class);
	private static final String logFile = "slf4j.properties";
	/**
	 * The package where all test suites can be found, relative to the package containing this class.
	 */
	private static String testSuitesPackage = "testsuites";
	/**
	 * The test suite that is being run
	 */
	private static SPTestSuite testsuite;
	/**
	 * Contains the SP configuration
	 */
	private static SPConfiguration spConfig;
	/**
	 * Contains the SAML Request that was retrieved by the mock IdP
	 */
	private static String samlRequest;
	/**
	 * Contains the SAML binding that was recognized by the mock IdP
	 */
	private static String samlRequestBinding;
	/**
	 * Contains the mock IdP server
	 */
	private static Server mockIdP;
	/**
	 * The browser which will be used to connect to the SP
	 */
	private static final WebClient browser = new WebClient();
	
	/**
	 * Contains the command-line options
	 */
	private static CommandLine command;

	public static void main(String[] args) {
		
		// initialize logging with properties file if it exists, basic config otherwise
		if(Files.exists(Paths.get(logFile))){
			PropertyConfigurator.configure(logFile);
		}
		else{
			BasicConfigurator.configure();
		}
		
		// define the command-line options
		Options options = new Options();
		options.addOption("h", "help", false, "Print this help message");
		options.addOption("i", "insecure", false,"Do not verify HTTPS server certificates");
		options.addOption("c", "spconfig", true,"The name of the properties file containing the configuration of the target SP");
		options.addOption("l", "listTestcases", false,"List all the test cases");
		options.addOption("L", "listTestsuites", false,"List all the test suites");
		options.addOption("m", "metadata", false,"Display the mock IdP metadata");
		options.addOption("T", "testsuite", true,"Specifies the test suite from which you wish to run a test case");
		options.addOption("t","testcase",true,"The name of the test case you wish to run. If omitted, all test cases from the test suite are run");

		LinkedList<TestResult> testresults = new LinkedList<TestResult>();
		try {
			// parse the command-line arguments
			CommandLineParser parser = new BasicParser();

			// parse the command line arguments
			command = parser.parse(options, args);

			// show the help message
			if (command.hasOption("help")) {
				new HelpFormatter().printHelp("SPTestRunner", options, true);
				System.exit(0);
			}

			// list the test suites, if necessary
			if (command.hasOption("listTestsuites")) {
				TestRunnerUtil.listTestSuites(SPTestRunner.class.getPackage().getName() + "." + testSuitesPackage);
				System.exit(0);
			}

			if (command.hasOption("testsuite")) {
				// load the test suite
				String ts_string = command.getOptionValue("testsuite");
				Class<?> ts_class = Class.forName(SPTestRunner.class.getPackage().getName() + "." + testSuitesPackage + "." + ts_string);
				Object testsuiteObj = ts_class.newInstance();
				if (testsuiteObj instanceof SPTestSuite) {
					testsuite = (SPTestSuite) testsuiteObj;

					// list the test cases, if necessary
					if (command.hasOption("listTestcases")) {
						TestRunnerUtil.listTestCases(testsuite);
						System.exit(0);
					}

					// show mock IdP metadata
					if (command.hasOption("metadata")) {
						TestRunnerUtil.outputMockedMetadata(testsuite);
						System.exit(0);
					}

					// configure the browser that will be used during testing
					browser.getOptions().setRedirectEnabled(true);
					if (command.hasOption("insecure")) {
						browser.getOptions().setUseInsecureSSL(true);
					}
					
					// load target SP config
					if (command.hasOption("spconfig")) {
						spConfig = new GsonBuilder()
											.registerTypeAdapter(Document.class, new MetadataDeserializer())
											.registerTypeAdapter(Interaction.class, new InteractionDeserializer())
											.create()
											.fromJson(Files.newBufferedReader(Paths.get(command.getOptionValue("spconfig")),Charset.defaultCharset()), SPConfiguration.class); 
						//new SPConfiguration(command.getOptionValue("spconfig"));
					} else {
						// use empty SP configuration
						spConfig = new SPConfiguration();
					}
					
					// initialize the mocked server
					mockIdP = TestRunnerUtil.newMockServer(testsuite.getMockServerURL(), new SamlWebSSOHandler());
					// start the mock IdP
					mockIdP.start();

					// load the requested test case(s)
					String testcaseName = command.getOptionValue("testcase");
					
					// get the test case(s) we want to run
					ArrayList<TestCase> testcases = TestRunnerUtil.getTestCases(testsuite, testcaseName);

					// run the test case(s) from the test suite
					for(TestCase testcase: testcases){
						TestStatus status = runTest(testcase);
						
						TestResult result = new TestResult(status, testcase.getResultMessage());
						result.setName(testcase.getClass().getSimpleName());
						result.setDescription(testcase.getDescription());
						// add this test result to the list of test results
						testresults.add(result);
					}
					TestRunnerUtil.outputTestResults(testresults);
				} else {
					logger.error("Provided class was not a TestSuite");
				}
			}
		} catch (ClassNotFoundException e) {
			// test suite or case could not be found
			if (testsuite == null)
				logger.error("Test suite could not be found", e);
			else
				logger.error("Test case could not be found", e);
			testresults.add(new TestResult(TestStatus.CRITICAL, ""));
		} catch (ClassCastException e) {
			logger.error("The test suite or case was not an instance of TestSuite", e);
		} catch (IOException e) {
			logger.error("I/O error occurred when creating HTTP server", e);
		} catch (ParseException e) {
			logger.error("Parsing of the command-line arguments has failed", e);
		} catch (JsonSyntaxException jsonExc) {
			logger.error("The JSON configuration file did not have the correct syntax", jsonExc);
		} catch (Exception e) {
			logger.error("The test(s) could not be run", e);
		} finally {
			// stop the mock IdP
			try {
				if (mockIdP!= null && mockIdP.isStarted()){
					mockIdP.stop();
				}
			} catch (Exception e) {
				logger.error("The mock IdP could not be stopped", e);
			}
		}
	}

	/**
	 * Run the test case that is provided.
	 * 
	 * @param testcase
	 *            represents the test case that needs to be run
	 * @param spconfig
	 *            contains the configuration required to run the test for the
	 *            target SP
	 * @return a string representing the test result in JSON format.
	 */
	private static TestStatus runTest(TestCase testcase) {
		logger.info("Running testcase: "+ testcase.getClass().getSimpleName());
		
		
		// run the test case according to what type of test case it is
		if (testcase instanceof ConfigTestCase) {
			ConfigTestCase cfTestcase = (ConfigTestCase) testcase;
			/**
			 * Check the SP's metadata according to the specifications of the
			 * test case and return the status of the test
			 */
			return cfTestcase.checkConfig(spConfig);
		}
		else if (testcase instanceof MetadataTestCase) {
			// Retrieve the SP Metadata from target SP configuration
			Document metadata = spConfig.getMetadata();
			MetadataTestCase mdTestcase = (MetadataTestCase) testcase;
			/**
			 * Check the SP's metadata according to the specifications of the
			 * test case and return the status of the test
			 */
			return mdTestcase.checkMetadata(metadata);
		} else if (testcase instanceof RequestTestCase) {
			RequestTestCase reqTC = (RequestTestCase) testcase;
			// make the SP send the AuthnRequest by starting an SP-initiated login attempt
			try {
				TestRunnerUtil.interactWithPage(browser.getPage(spConfig.getStartPage()), spConfig.getPreLoginInteractions());
			
				//retrieveLoginPage(true); 
			
				// the SAML Request should have been retrieved by the mock IdP and
				// set here during the execute() method
				if (samlRequest != null && !samlRequest.isEmpty()) {
					logger.debug("Received the SAML request");
					logger.trace(samlRequest);
					/**
					 * Check the SAML Request according to the specifications of the
					 * test case and return the status of the test
					 */
					return reqTC.checkRequest(samlRequest,samlRequestBinding);
				} else {
					logger.error("Could not retrieve the SAML Request that was sent by the target SP");
					return TestStatus.CRITICAL;
				}
			} catch (FailingHttpStatusCodeException e) {
				logger.error("The start page returned a failing HTTP status code", e);
				return TestStatus.CRITICAL;
			} catch (MalformedURLException e) {
				logger.error("The URL for the start page was malformed", e);
				return TestStatus.CRITICAL;
			} catch (IOException e) {
				logger.error("An I/O exception occurred while trying to access the start page", e);
				return TestStatus.CRITICAL;
			}
		} else if (testcase instanceof LoginTestCase) {
			LoginTestCase loginTC = (LoginTestCase) testcase;
			ArrayList<Boolean> testResults = new ArrayList<Boolean>();

			// get all login attempts that should be tested
			ArrayList<LoginAttempt> logins = (ArrayList<LoginAttempt>) loginTC.getLoginAttempts();

			// execute all login attempts
			for (LoginAttempt login : logins) {
				// start login attempt with target SP
				try {
					URL acsURL;
					String binding = null;
					// determine the ACS location and binding, depending on the received SAML Request
					if(login.isSPInitiated()){
						// retrieve the login page, thereby sending the AuthnRequest to the mock IdP
						TestRunnerUtil.interactWithPage(browser.getPage(spConfig.getStartPage()), spConfig.getPreLoginInteractions());
						// check if the saml request has correctly been retrieved by the mock IdP 
						// if not, most likely caused by trying to use artifact binding
						if (samlRequest == null || samlRequest.isEmpty()) {
							logger.error("Could not retrieve the SAML request");
							return null;
						}
						// try to retrieve the location and binding of the ACS where this should be sent from the request
						String acsLoc = getRequestACSURL();
						if (acsLoc == null){
							// no ACS location found in request, check for ACS index
							int acsIndex = getRequestACSIndex();
							if ( acsIndex >= 0 ){
								// ACS index found, so set location and binding accordingly
								acsLoc = spConfig.getMDACSLocation(acsIndex);
								binding = spConfig.getMDACSBinding(acsIndex);
							}
							else{
								// no ACS location or index found in request, so just use default
								acsLoc = spConfig.getDefaultMDACSLocation();
								binding = spConfig.getDefaultMDACSBinding();
							}
						}
						else{
							// found ACS location in request, must also have a binding then
							binding = getRequestACSBinding();
						}
						acsURL = new URL(acsLoc);
					}
					else{
						// go directly to the IdP page without an AuthnRequest (for idp-initiated authentication)
						TestRunnerUtil.interactWithPage(browser.getPage(testsuite.getMockServerURL().toString()), new ArrayList<Interaction>());
						// retrieve the location of the default ACS where this should be sent
						acsURL = new URL(spConfig.getDefaultMDACSLocation());
						binding = spConfig.getDefaultMDACSBinding();
						
					}
					// create HTTP request to send the SAML response to the SP's ACS url
					String samlResponse = login.getResponse(samlRequest);
					WebRequest sendResponse = new WebRequest(acsURL, HttpMethod.POST);
					ArrayList<NameValuePair> postParameters = new ArrayList<NameValuePair>();
					NameValuePair samlresponse;
					// set the SAML URL parameter according to the requested binding
					if (binding.equalsIgnoreCase(SAMLmisc.BINDING_HTTP_POST)){
						samlresponse = new NameValuePair(SAMLmisc.URLPARAM_SAMLRESPONSE_POST, SAMLUtil.encodeSamlMessageForPost(samlResponse));
					}
					else if (binding.equalsIgnoreCase(SAMLmisc.BINDING_HTTP_ARTIFACT)){
						// TODO: support artifact binding
						//samlresponse = new NameValuePair(SAMLmisc.URLPARAM_SAMLARTIFACT, SAMLUtil.encodeSamlMessageForArtifact(samlResponse));
						logger.debug("Response needs to be sent with Artifact binding, this is not yet supported");
						return TestStatus.CRITICAL;
					}
					else{
						logger.error("An invalid binding was requested for sending the Response to the SP");
						return TestStatus.CRITICAL;
					}
					postParameters.add(samlresponse);
					sendResponse.setRequestParameters(postParameters);
					
					logger.debug("Sending SAML Response to the SP");
					logger.trace(samlResponse);
					// send the SAML response to the SP
					HtmlPage responsePage = browser.getPage(sendResponse);
					
					logger.trace("The received page:\n"+responsePage.getWebResponse().getContentAsString());
					
					// the login succeeded when all configured matches are found
					if (checkLoginHTTPStatusCode(responsePage) 
							&& checkLoginURL(responsePage) 
							&& checkLoginContent(responsePage) 
							&& checkLoginCookies(responsePage)) {
						testResults.add(new Boolean(true));
					}
					else{
						testResults.add(new Boolean(false));
					}
					// close the browser windows
					browser.getCache().clear();
					browser.getCookieManager().clearCookies();
					browser.closeAllWindows();
				} catch (ClientProtocolException e) {
					logger.error("Could not execute HTTP request for the LoginTestCase", e);
					return null;
				}catch (FailingHttpStatusCodeException e){
					logger.error("Could not retrieve browser page for the LoginTestCase", e);
					return null;
				}catch (IOException e) {
					logger.error("Could not execute HTTP request for the LoginTestCase", e);
					return null;
				}
			}
			/**
			 * Check if the login attempts were valid according to the
			 * specifications of the test case and return the status of the test
			 */
			return loginTC.checkLoginResults(testResults);
		} else {
			logger.error("Trying to run an unknown type of test case");
			return null;
		}
	}

	/**
	 * Set the SAML Request that was received from the SP
	 * 
	 * This is set from the Handler that processes the SP's login attempt
	 * on the mock IdP.
	 * 
	 * @param request is the SAML Request
	 */
	public static void setSamlRequest(String request) {
		samlRequest = request;
	}

	/**
	 * Set the SAML Binding that the SP has used to send its AuthnRequest
	 * 
	 * This is set from the Handler that processes the SP's login attempt
	 * on the mock IdP.
	 * 
	 * @param binding is the name of the SAML Binding
	 */
	public static void setSamlRequestBinding(String binding) {
		samlRequestBinding = binding;
	}

	/**
	 * Retrieve the SPConfiguration object containing the target SP configuration info
	 * 
	 * @return the SPConfiguration object used in this test
	 */
	public static SPConfiguration getSPConfig() {
		return spConfig;
	}
	
	private static boolean checkLoginHTTPStatusCode(HtmlPage page){
		// check the HTTP Status code of the page to see if the login was successful
		if (spConfig.getLoginStatuscode() == 0) {
			// do not match against status code
			return true;
		} 
		else if (page.getWebResponse().getStatusCode() == spConfig.getLoginStatuscode()) {
			return true;
		}
		else{
			logger.debug("The page's HTTP status code did not match the expected HTTP status code");
			return false;
		}
	}

	private static boolean checkLoginURL(HtmlPage responsePage) {
		// check the URL of the page to see if the login was successful
		if (spConfig.getLoginURL() == null) {
			// do not match against URL
			return true;
		} else {
			URL responseURL = responsePage.getUrl();
			URL matchURL;
			try {
				matchURL = new URL(spConfig.getLoginURL());
			
				// check if the current location matches what we expect when we are
				// correctly logged in
				if (responseURL.equals(matchURL)) {
					return true;
				} else {
					logger.debug("Could not match the URL " + matchURL.toString()
							+ " against the returned page's URL "
							+ responseURL.toString());
					return false;
				}
			} catch (MalformedURLException e) {
				logger.debug("The expected URL " + spConfig.getLoginURL() + " is malformed");
				return false;
			}
		}
	}

	private static boolean checkLoginContent(HtmlPage responsePage) {
		// check if the page matches what we expect to see when we log in
		String page = responsePage.getWebResponse().getContentAsString();
		if (spConfig.getLoginContent() == null) {
			// do no match against page content
			return true;
		} else {
			String contentRegex = spConfig.getLoginContent();
			// compile the regex so it allows the dot character to also match new-line characters,
			// which is useful since this is a multi-line string
			Pattern regexP = Pattern.compile(contentRegex, Pattern.DOTALL);
			Matcher regexM = regexP.matcher(page);
			if (regexM.find()) {
				return true;
			} else {
				logger.debug("Could not match the following regex against the returned page:\n"+ contentRegex);
				return false;
			}
		}
	}

	private static boolean checkLoginCookies(HtmlPage responsePage) {
		// check the cookies
		if (spConfig.getLoginCookies().size() <= 0) {
			// do not check cookies
			return true;
		} else {
			ArrayList<StringPair> checkCookies = spConfig.getLoginCookies();
			Set<Cookie> sessionCookies;
			try {
				sessionCookies = browser.getCookies(new URL(spConfig.getMDACSLocation(SAMLmisc.BINDING_HTTP_POST)));

				// only check for cookies if we actually have some to match against
				if (checkCookies.size() > 0) {
					boolean found = false;
					// check if each user-supplied cookie name and value is
					// available
					for (StringPair checkCookie : checkCookies) {
						String name = checkCookie.getName();
						String value = checkCookie.getValue();
						// iterate through the session cookies to see if it contains
						// the the checked cookie
						for (Cookie sessionCookie : sessionCookies) {
							String cookieName = sessionCookie.getName();
							String cookieValue = sessionCookie.getValue();
							// compare the cookie names
							if (cookieName.equalsIgnoreCase(name)) {
								// if no value given, you don't need to compare it
								if (value == null || value.isEmpty()) {
									found = true;
									break;
								} else {
									if (cookieValue.equalsIgnoreCase(value)) {
										found = true;
										break;
									}
								}
							}
						}
						// this cookie could not be found, so we could not find a match
						if (!found) {
							logger.debug("Could not match the following cookie against the returned page:\n"+ checkCookie.getName()+ ", "+ checkCookie.getValue());
							return false;
						}
					}
					// you got through all cookies so all cookies matched
					return true;
				}
				else{
					// we could not find any cookies in the page, so this failed our check
					return false;
				}
			} catch (MalformedURLException e) {
				logger.debug("The ACS URL " + spConfig.getLoginURL() + " from the target's metadata is malformed");
				return false;
			}
		}
	}

	/**
	 * Retrieve the ACS URL provided by the SAML Request
	 * 
	 * @return the ACS URL provided by the SAML Request
	 */
	private static String getRequestACSURL() {
		Document authnRequest = SAMLUtil.fromXML(samlRequest);
		// retrieve the attributes for the first AuthnRequest (which should be the only one) element
		Node acsURL = authnRequest.getElementsByTagNameNS(SAMLP.NAMESPACE, SAMLP.AUTHNREQUEST).item(0).getAttributes().getNamedItem(SAMLP.ASSERTIONCONSUMERSERVICEURL);
		if (acsURL == null){
			return null;
		}
		else{
			return acsURL.getNodeValue();
		}
	}

	/**
	 * Retrieve the ACS URL provided by the SAML Request
	 * 
	 * @return the ACS URL provided by the SAML Request
	 */
	private static String getRequestACSBinding() {
		Document authnRequest = SAMLUtil.fromXML(samlRequest);
		// retrieve the attributes for the first AuthnRequest (which should be the only one) element
		Node acsURL = authnRequest.getElementsByTagNameNS(SAMLP.NAMESPACE, SAMLP.AUTHNREQUEST).item(0).getAttributes().getNamedItem(SAMLP.PROTOCOLBINDING);
		if (acsURL == null){
			return null;
		}
		else{
			return acsURL.getNodeValue();
		}
	}

	/**
	 * Retrieve the ACS index provided by the SAML Request
	 * 
	 * @return the ACS index provided by the SAML Request
	 */
	private static int getRequestACSIndex() {
		Document authnRequest = SAMLUtil.fromXML(samlRequest);
		// retrieve the attributes for the first AuthnRequest (which should be the only one) element
		Node acsURL = authnRequest.getElementsByTagNameNS(SAMLP.NAMESPACE, SAMLP.AUTHNREQUEST).item(0).getAttributes().getNamedItem(SAMLP.ASSERTIONCONSUMERSERVICEINDEX);
		if (acsURL == null){
			return -1;
		}
		else{
			return Integer.parseInt(acsURL.getNodeValue());
		}
	}
}
