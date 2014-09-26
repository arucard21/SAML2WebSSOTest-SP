package saml2tester.sp;

import java.io.IOException;
import java.lang.reflect.InvocationTargetException;
import java.net.InetSocketAddress;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;
import java.util.Map.Entry;
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
import org.apache.http.client.utils.URIBuilder;
import org.apache.log4j.BasicConfigurator;
import org.apache.log4j.PropertyConfigurator;
import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.server.handler.ContextHandler;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Document;

import com.gargoylesoftware.htmlunit.ElementNotFoundException;
import com.gargoylesoftware.htmlunit.FailingHttpStatusCodeException;
import com.gargoylesoftware.htmlunit.HttpMethod;
import com.gargoylesoftware.htmlunit.Page;
import com.gargoylesoftware.htmlunit.WebClient;
import com.gargoylesoftware.htmlunit.WebRequest;
import com.gargoylesoftware.htmlunit.html.HtmlAnchor;
import com.gargoylesoftware.htmlunit.html.HtmlForm;
import com.gargoylesoftware.htmlunit.html.HtmlInput;
import com.gargoylesoftware.htmlunit.html.HtmlPage;
import com.gargoylesoftware.htmlunit.html.HtmlSubmitInput;
import com.gargoylesoftware.htmlunit.util.Cookie;
import com.gargoylesoftware.htmlunit.util.NameValuePair;

import saml2tester.common.FormInteraction;
import saml2tester.common.LinkInteraction;
import saml2tester.common.SAMLUtil;
import saml2tester.common.TestStatus;
import saml2tester.common.standardNames.SAMLValues;
import saml2tester.sp.mockIdPHandlers.SamlWebSSOHandler;
import saml2tester.sp.testsuites.TestSuite;
import saml2tester.sp.testsuites.TestSuite.LoginTestCase;
import saml2tester.sp.testsuites.TestSuite.MetadataTestCase;
import saml2tester.sp.testsuites.TestSuite.RequestTestCase;
import saml2tester.sp.testsuites.TestSuite.TestCase;

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
	private static String testSuitesPackage = ".testsuites.";
	/**
	 * The test suite that is being run
	 */
	private static TestSuite testsuite;
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
		options.addOption("H", "humanreadable", false,"Print the test results in human-readable format (not yet supported)");
		options.addOption("i", "insecure", false,"Do not verify HTTPS server certificates");
		options.addOption("s", "spconfig", true,"The name of the properties file containing the configuration of the target SP");
		options.addOption("l", "listTestcases", false,"List all the test cases");
		options.addOption("L", "listTestsuites", false,"List all the test suites");
		options.addOption("m", "metadata", false,"Display the mock IdP metadata");
		options.addOption("t", "testsuite", true,"Specifies the test suite from which you wish to run a test case");
		options.addOption("c","testcase",true,"The name of the test case you wish to run. If omitted, all test cases from the test suite are run");

		HashMap<TestCase, TestStatus> testresults = null;
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
				listTestSuites();
				System.exit(0);
			}

			if (command.hasOption("testsuite")) {
				// load the test suite
				String ts_string = command.getOptionValue("testsuite");
				Class<?> ts_class = Class.forName(SPTestRunner.class.getPackage().getName() + testSuitesPackage + ts_string);
				Object testsuiteObj = ts_class.newInstance();
				if (testsuiteObj instanceof TestSuite) {
					testsuite = (TestSuite) testsuiteObj;

					// list the test cases, if necessary
					if (command.hasOption("listTestcases")) {
						listTestCases();
						System.exit(0);
					}

					// show mock IdP metadata
					if (command.hasOption("metadata")) {
						outputIdPMetadata(testsuite);
						System.exit(0);
					}

					// load target SP config
					if (command.hasOption("spconfig")) {
						spConfig = new SPConfiguration(command.getOptionValue("spconfig"));
					} else {
						// use default, empty SP configuration
						spConfig = new SPConfiguration(null);
					}

					// create the mock IdP and add all required handlers
					mockIdP = new Server(new InetSocketAddress(testsuite.getMockIdPHostname(),testsuite.getMockIdPPort()));
					
					// add a context handler to properly handle the sso path
					ContextHandler context = new ContextHandler();
					context.setContextPath(testsuite.getMockIdPSsoPath());
					mockIdP.setHandler(context);

					// add the SAML Request handler for all services
					mockIdP.setHandler(new SamlWebSSOHandler());
					// add the SAML Response handler

					// start the mock IdP
					mockIdP.start();

					// the test results are stored for each test case that is run
					testresults = new HashMap<TestCase, TestStatus>();

					// load the requested test case(s)
					String tc_string = command.getOptionValue("testcase");
					if (tc_string != null && !tc_string.isEmpty()) {
						Class<?> tc_class = Class.forName(testsuite.getClass().getName() + "$" + tc_string);
						Object testcaseObj = tc_class.getConstructor(testsuite.getClass()).newInstance(testsuite);
						// run test
						if (testcaseObj instanceof TestCase) {
							TestCase testcase = (TestCase) testcaseObj;
							testresults.put(testcase, runTest(testcase));
						} else {
							logger.error("Provided class was not a subclass of interface TestCase");
						}
					} else {
						// run all test cases from the test suite, ignore
						// classes that are not subclasses of TestCase
						Class<?>[] allTCs = ts_class.getDeclaredClasses();
						for (Class<?> testcaseClass : allTCs) {
							TestCase curTestcase = (TestCase) testcaseClass.getConstructor(testsuite.getClass()).newInstance(testsuite);
								testresults.put(curTestcase,runTest(curTestcase));
						}
					}
					// handle test result(s)
					outputTestResult(testresults);
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
			testresults.put(null, TestStatus.CRITICAL);
		} catch (ClassCastException e) {
			logger.error("The test suite or case was not an instance of TestSuite", e);
		} catch (InstantiationException e) {
			logger.error("Could not instantiate an instance of the test suite or case", e);
		} catch (IllegalAccessException e) {
			logger.error("Could not access the test suite class or test case class", e);
		} catch (IOException e) {
			logger.error("I/O error occurred when creating HTTP server", e);
		} catch (ParseException e) {
			logger.error("Parsing of the command-line arguments has failed", e);
		} catch (IllegalArgumentException e) {
			logger.error("Could not create a new instance of the test case", e);
		} catch (InvocationTargetException e) {
			logger.error("Could not create a new instance of the test case", e);
		} catch (NoSuchMethodException e) {
			logger.error("Could not retrieve the constructor of the test case class", e);
		} catch (SecurityException e) {
			logger.error("Could not retrieve the constructor of the test case class", e);
		} catch (Exception e) {
			logger.error("The test(s) could not be run", e);
		} finally {
			// stop the mock IdP
			try {
				if (mockIdP.isStarted()){
					mockIdP.stop();
				}
			} catch (Exception e) {
				logger.error("The mock IdP could not be stopped", e);
			}
		}
	}

	/**
	 * Display the list of test suites
	 * 
	 * When new test suites are created, they need to be added here manually to
	 * be listed though they can be used without being listed. (Doing this
	 * dynamically is not stable enough with Java Reflection)
	 */
	private static void listTestSuites() {
		// create a list of all available test suites
		ArrayList<String> availableTestSuites = new ArrayList<String>();
		availableTestSuites.add("SAML2Int");
		// availableTestSuites.add("YOURNEWTESTSUITE");

		// output the available test suites
		for (String ts : availableTestSuites) {
			System.out.println(ts);
		}
	}

	/**
	 * Display the list of test cases for the current test suite
	 */
	private static void listTestCases() {
		// iterate through all test cases
		for (Class<?> testcase : testsuite.getClass().getDeclaredClasses()) {
			// check if the class object is in fact a test case
			if (TestCase.class.isAssignableFrom(testcase)) {
				// output the name of the test case
				System.out.println(testcase.getSimpleName());
				TestCase tc;
				try {
					tc = (TestCase) testcase.getConstructor(testsuite.getClass()).newInstance(testsuite);
					// also output the description of the test case
					System.out.println("\t" + tc.getDescription());
				} catch (InstantiationException e) {
					logger.error("Could not create a new instance of the test case", e);
				} catch (IllegalAccessException e) {
					logger.error("Could not create a new instance of the test case", e);
				} catch (IllegalArgumentException e) {
					logger.error("Could not create a new instance of the test case", e);
				} catch (InvocationTargetException e) {
					logger.error("Could not create a new instance of the test case", e);
				} catch (NoSuchMethodException e) {
					logger.error("Could not retrieve the constructor of the test case class", e);
				} catch (SecurityException e) {
					logger.error("Could not retrieve the constructor of the test case class", e);
				}
				System.out.println("");
			} else {
				logger.error("Class was not a test case");
			}
		}
	}

	/**
	 * Display the mock IdP's metadata for the provided test suite.
	 * 
	 * @param testsuite
	 *            is the test suite for which we should display the metadata
	 */
	private static void outputIdPMetadata(TestSuite testsuite) {
		System.out.println(testsuite.getIdPMetadata());
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
		browser.getOptions().setRedirectEnabled(true);
		if (command.hasOption("insecure")) {
			browser.getOptions().setUseInsecureSSL(true);
		}
		// run the test case according to what type of test case it is
		if (testcase instanceof MetadataTestCase) {
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
			retrieveLoginPage(true); 

			// the SAML Request should have been retrieved by the mock IdP and
			// set here during the execute() method
			if (samlRequest != null && !samlRequest.isEmpty()) {
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
		} else if (testcase instanceof LoginTestCase) {
			LoginTestCase loginTC = (LoginTestCase) testcase;
			ArrayList<Boolean> testResults = new ArrayList<Boolean>();

			// get all login attempts that should be tested
			ArrayList<LoginAttempt> logins = (ArrayList<LoginAttempt>) loginTC.getLoginAttempts();

			// execute all login attempts
			for (LoginAttempt login : logins) {
				// start login attempt with target SP
				try {
					// retrieve the login page, thereby sending the AuthnRequest to the mock IdP
					retrieveLoginPage(login.isSPInitiated());
					
					// check if the saml request has correctly been retrieved by the mock IdP 
					// if not, most likely caused by trying to use artifact binding
					if (samlRequest == null || samlRequest.isEmpty()) {
						logger.error("Could not retrieve the SAML request");
						return null;
					}
					// create request to send the SAML response to the SP's ACS url
					URL acsURL = new URL(spConfig.getMDACSLocation(SAMLValues.BINDING_HTTP_POST));
					WebRequest sendResponse = new WebRequest(acsURL, HttpMethod.POST);
					ArrayList<NameValuePair> postParameters = new ArrayList<NameValuePair>();
					postParameters.add(new NameValuePair(SAMLValues.URLPARAM_SAMLRESPONSE_POST, SAMLUtil.encodeSamlMessageForPost(login.getResponse(samlRequest))));
					sendResponse.setRequestParameters(postParameters);
					// send the SAML response to the SP
					HtmlPage responsePage = browser.getPage(sendResponse);
					
					boolean statuscodeMatch = false;
					boolean urlMatch = false;
					boolean contentMatch = false;
					boolean cookiesMatch = false;

					// check the HTTP Status code of the page to see if the login was successful
					if (spConfig.getLoginStatuscode() == 0) {
						// do not match against status code
						statuscodeMatch = true;
					} else if (responsePage.getWebResponse().getStatusCode() == spConfig.getLoginStatuscode()) {
						statuscodeMatch = true;
					}
					
					// check the URL of the page to see if the login was successful
					if (spConfig.getLoginURL() == null) {
						// do not match against url
						urlMatch = true;
					} 
					else {
						String currentLocation = responsePage.getUrl().toString();
						// check if the current location matches what we expect when we are correctly logged in 
						if (currentLocation.matches(spConfig.getLoginURL())) {
							urlMatch = true;
						}
					}

					// check if the page matches what we expect to see when we log in
					String page = responsePage.getWebResponse().getContentAsString();
					logger.trace("The received page:\n"+page);
					if (spConfig.getLoginContent() == null) {
						// do no match against page content
						contentMatch = true;
					} else {	
						String contentRegex = spConfig.getLoginContent();
						// compile the regex so it allows the dot character to
						// also match new-line characters,
						// which is useful since this is a multi-line string
						Pattern regexP = Pattern.compile(contentRegex, Pattern.DOTALL);
						Matcher regexM = regexP.matcher(page);
						if (regexM.find()) {
							contentMatch = true;
						}
					}
					// check the cookies
					if (spConfig.getLoginCookies().isEmpty()) {
						// do not check cookies
						cookiesMatch = true;
					} else {
						HashMap<String, String> checkCookies = spConfig.getLoginCookies();
						Set<Cookie> sessionCookies = browser.getCookies(acsURL);
						
						// only check for cookies if we actually have some to match against
						if (checkCookies.size() > 0){
							int matchCount = 0;
							// check if each user-supplied cookie name and value is available
							for (Entry<String, String> checkCookie : checkCookies.entrySet()) {
								String name = checkCookie.getKey();
								String value = checkCookie.getValue();
								// iterate through the session cookies to see if it contains the the checked cookie
								for (Cookie sessionCookie : sessionCookies) {
									String cookieName = sessionCookie.getName();
									String cookieValue = sessionCookie.getValue();
									// compare the cookie names
									if (cookieName.equalsIgnoreCase(name)) {
										// if no value give, you don't need to compare it
										if (value == null || value.isEmpty()) {
											matchCount++;
											break;
										} else {
											if (cookieValue.equalsIgnoreCase(value)) {
												matchCount++;
												break;
											}
										}
									}
								}
							}
							// if all cookies have been found in the session's cookies, then this matches as well
							if (matchCount == checkCookies.size()) {
								cookiesMatch = true;
							}
						}
					}
					// the login succeeded when all configured matches are found
					if (statuscodeMatch && urlMatch && contentMatch && cookiesMatch) {
						testResults.add(new Boolean(true));
					}
					else{
						testResults.add(new Boolean(false));
					}
					// close the browser
					browser.closeAllWindows();
				} catch (ClientProtocolException e) {
					logger.error("Could not execute HTTP request for the LoginTestCase", e);
				} catch (IOException e) {
					logger.error("Could not execute HTTP request for the LoginTestCase", e);
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
	 * Retrieves the login page from the SP, thereby sending the SP's AuthnRequest to
	 * the mock IdP. 
	 * 
	 * @return the login page, or null if the login page could not be retrieved
	 */
	private static Page retrieveLoginPage(boolean spInitiated) {
		// start login attempt with target SP
		try {
			// create a URI of the start page (which also checks the validity of the string as URI)
			URI loginURI;
			if (spInitiated) {
				// login from the SP's start page
				loginURI = new URIBuilder(spConfig.getStartPage()).build();
			} else {
				// login from the IdP's page
				loginURI = new URIBuilder(
						testsuite.getMockIdPHostname()).setPort(
						testsuite.getMockIdPPort()).build();
			}
			Page retrievedPage = browser.getPage(loginURI.toURL());

			// interact with the login page in order to get logged in
			ArrayList<Object> interactions = spConfig.getPreloginInteractions();
			// execute all interactions
			for(Object interaction : interactions){
				if(retrievedPage instanceof HtmlPage){
					// cast the Page to an HtmlPage so we can interact with it
					HtmlPage loginPage = (HtmlPage) retrievedPage;
					logger.trace("Login page");
					logger.trace(loginPage.getWebResponse().getContentAsString());
				
					// cast the interaction to the correct class
					if(interaction instanceof FormInteraction) {
						FormInteraction forminteraction = (FormInteraction) interaction;
						HtmlForm preLoginForm = loginPage.getFormByName(forminteraction.getFormName());
						HtmlSubmitInput button = preLoginForm.getInputByName(forminteraction.getSubmitName());
						
						// fill in all provided input fields
						HashMap<String, String> inputs = forminteraction.getInputs();
						for(Map.Entry<String, String> input: inputs.entrySet()){
							// retrieve the first input field with the provided name
							HtmlInput textField = preLoginForm.getInputsByName(input.getKey()).get(0);	
							textField.setValueAttribute(input.getValue());
						}
					    // submit the form, updating the retrieved page
					    retrievedPage = button.click();
					    logger.trace("Login page (after form submit)");
					    logger.trace(loginPage.getWebResponse().getContentAsString());
					}
					else if(interaction instanceof LinkInteraction) {
						LinkInteraction linkinteraction = (LinkInteraction) interaction;
						String inputValue = linkinteraction.getLookupValue();
						HtmlAnchor input;
						if (linkinteraction.getLookupType() == LinkInteraction.LookupType.NAME)
							input = loginPage.getAnchorByName(inputValue);
						else if (linkinteraction.getLookupType() == LinkInteraction.LookupType.TEXT)
							input = loginPage.getAnchorByText(inputValue);
						else if (linkinteraction.getLookupType() == LinkInteraction.LookupType.HREF)
							input = loginPage.getAnchorByHref(inputValue);
						else{
							logger.error("Unknown lookup type found in link interaction object");
							input = null;
						}
						// click the link and update the retrieved page
						if (input != null) retrievedPage = input.click();
						
						logger.trace("Login page (after link click)");
					    logger.trace(loginPage.getWebResponse().getContentAsString());
					}
					else{
						logger.error("Unknown interaction class found");
					}
				}
				else{
					logger.error("The login page is not an HTML page, so it's not possible to interact with it");
					logger.trace("Retrieved page:");
					logger.trace(retrievedPage.getWebResponse().getContentAsString());
					break;
				}
			}
			// return the retrieved page
			return retrievedPage;
		} catch (FailingHttpStatusCodeException e) {
			logger.error("The login page did not return a valid HTTP status code");
		} catch (MalformedURLException e) {
			logger.error("THe login page's URL is not valid");
		} catch (IOException e) {
			logger.error("The login page could not be accessed due to an I/O error");
		} catch (URISyntaxException e) {
			logger.error("The URI syntax for the SP's startpage is incorrect", e);
		} catch (ElementNotFoundException e){
			logger.error("The interaction link lookup could not find the specified element");
		}
		return null;
	}

	/**
	 * Process the test results and output them appropriately
	 * 
	 * @param testresult
	 *            is the result of the test case that was run
	 */
	private static void outputTestResult(Map<TestCase, TestStatus> testresults) {
		// TODO maybe use a templating system to output nicely at some point, now just output to sysout
		for (Map.Entry<TestCase, TestStatus> testresult : testresults.entrySet()) {
			String name = testresult.getKey().getClass().getSimpleName();
			//String description = testresult.getKey().getDescription();
			String message;
			TestStatus status = testresult.getValue();
			if (status.equals(TestStatus.OK))
				message = status + ": " + testresult.getKey().getSuccessMessage();
			else
				message = status + ": " + testresult.getKey().getFailedMessage();

			System.out.println("Test Case: " + name);
			//System.out.println("Description: " + description);
			System.out.println("\t" + message);
			System.out.println("");
		}
	}

	/**
	 * Retrieve the SAML Request that was received from the SP
	 * 
	 * This can only be retrieved once it has been set by the mock IdP, 
	 * which happens after the SP has accessed the mock IdP.
	 * 
	 * @return the SAML Request
	 */
//	public static String getSamlRequest() {
//		return samlRequest;
//	}

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
	 * Retrieve the SAML Binding that the SP has used to send its AuthnRequest
	 * 
	 * This can only be retrieved once it has been set by the mock IdP, 
	 * which happens after the SP has accessed the mock IdP.
	 * 
	 * @return the name of SAML Binding
	 */
//	public static String getSamlRequestBinding() {
//		return samlRequestBinding;
//	}

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
}
