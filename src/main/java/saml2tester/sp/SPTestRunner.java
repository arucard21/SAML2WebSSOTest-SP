package saml2tester.sp;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.lang.reflect.InvocationTargetException;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Properties;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.apache.commons.cli.BasicParser;
import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.CommandLineParser;
import org.apache.commons.cli.HelpFormatter;
import org.apache.commons.cli.Options;
import org.apache.commons.cli.ParseException;
import org.apache.http.HttpResponse;
import org.apache.http.client.ClientProtocolException;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpUriRequest;
import org.apache.http.client.methods.RequestBuilder;
import org.apache.http.client.protocol.HttpClientContext;
import org.apache.http.client.utils.URIBuilder;
import org.apache.http.conn.ssl.AllowAllHostnameVerifier;
import org.apache.http.cookie.Cookie;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.server.handler.ContextHandler;
import org.w3c.dom.Document;
import org.w3c.dom.Node;

import saml2tester.common.SAMLUtil;
import saml2tester.common.TestStatus;
import saml2tester.common.standardNames.Attribute;
import saml2tester.common.standardNames.MD;
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
	 * The package where all test suites can be found, relative to the package containing this class.
	 */
	private static String testSuitesPackage = ".testsuites.";
	/**
	 * Define the keys used in the SP configuration properties file
	 */
	private static String configStartPage = "targetSP.startPage";
	private static String configMetadata = "targetSP.metadata";
	private static String configLoginStatuscode = "targetSP.login.httpstatuscode";
	private static String configLoginCookiePrefix = "targetSP.login.cookie";
	private static String configLoginContent = "targetSP.login.content";
	private static String configIdPAttributePrefix = "targetSP.idp.attribute";
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
	 * Contains the SAML Response that should be sent by the mock IdP
	 */
	private static String samlResponse;
	/**
	 * Contains the command-line options
	 */
	private static CommandLine command;

	public static void main(String[] args) {
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
		Server mockIdP = new Server();
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
						loadConfig(command.getOptionValue("spconfig"));
					} else {
						// use default, empty SP configuration
						spConfig = new SPConfiguration();
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
							System.err.println("Provided class was not a subclass of interface TestCase");
						}
					} else {
						// run all test cases from the test suite, ignore
						// classes that are not subclasses of TestCase
						Class<?>[] allTCs = ts_class.getDeclaredClasses();
						for (Class<?> testcaseClass : allTCs) {
							Object curTestcaseObj = testcaseClass.getConstructor(testsuite.getClass()).newInstance(testsuite);
							if (curTestcaseObj instanceof TestCase) {
								TestCase curTestcase = (TestCase) curTestcaseObj;
								testresults.put(curTestcase,runTest(curTestcase));
							} else {
								System.err.println("Provided class was not a subclass of interface TestCase");
							}
						}
					}
					// handle test result(s)
					outputTestResult(testresults);
				} else {
					System.err.println("Provided class was not TestSuite");
				}
			}
		} catch (ClassNotFoundException e) {
			// test suite or case could not be found
			if (testsuite == null)
				System.err.println("Test suite could not be found");
			else
				System.err.println("Test case could not be found");
			e.printStackTrace();
			testresults.put(null, TestStatus.CRITICAL);
		} catch (ClassCastException e) {
			// test suite or case was not an instance of TestSuite
			e.printStackTrace();
		} catch (InstantiationException e) {
			// could not create instance of test suite or case
			e.printStackTrace();
		} catch (IllegalAccessException e) {
			// could not access test suite or case class
			e.printStackTrace();
		} catch (IOException e) {
			// I/O error when creating HTTP server
			e.printStackTrace();
		} catch (ParseException e) {
			// could not parse the arguments
			System.err.println("Parsing of the command-line arguments has failed");
			e.printStackTrace();
		} catch (Exception e) {
			e.printStackTrace();
		} finally {
			// always stop the mock IdP
			try {
				mockIdP.stop();
			} catch (Exception e) {
				System.err.println("The mock IdP could not be stopped");
				e.printStackTrace();
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
					e.printStackTrace();
				} catch (IllegalAccessException e) {
					e.printStackTrace();
				} catch (IllegalArgumentException e) {
					e.printStackTrace();
				} catch (InvocationTargetException e) {
					e.printStackTrace();
				} catch (NoSuchMethodException e) {
					e.printStackTrace();
				} catch (SecurityException e) {
					e.printStackTrace();
				}
				System.out.println("");
			} else {
				System.err.println("Class was not a test case");
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
	 * Load the configuration of the target SP, provided in JSON format
	 * 
	 * @param targetSPConfig
	 *            is the configuration of the target SP in JSON format
	 */
	private static void loadConfig(String targetSPConfig) {
		spConfig = new SPConfiguration();

		try {
			Properties propConfig = new Properties();
			propConfig.load(Files.newBufferedReader(Paths.get(targetSPConfig),Charset.defaultCharset()));
			Set<String> configKeys = propConfig.stringPropertyNames();

			for (String key : configKeys) {
				// add the properties to the config object appropriately
				if (key.equalsIgnoreCase(configStartPage)){
					spConfig.setStartPage(propConfig.getProperty(configStartPage));
				}
				else if (key.equalsIgnoreCase(configMetadata)) {
					String mdVal = propConfig.getProperty(configMetadata);
					spConfig.setMetadata(SAMLUtil.fromXML(mdVal));
				} 
				else if (key.equalsIgnoreCase(configLoginStatuscode)){
					String scProp = propConfig.getProperty(configLoginStatuscode);
					if(scProp != null && !scProp.isEmpty()){
						spConfig.setLoginStatuscode(Integer.valueOf(scProp));
					}
				}
				else if (key.equalsIgnoreCase(configLoginContent)){
					spConfig.setLoginContent(propConfig.getProperty(configLoginContent));
				}
				else if (key.startsWith(configLoginCookiePrefix)) {
					String cookieProp = propConfig.getProperty(key);
					// make sure the properties file actually has a value for the cookie
					if (cookieProp != null && !cookieProp.isEmpty()){
						String[] cookie = cookieProp.split(",");
						
						if(cookie.length > 0 && cookie[0] != null){
							String name = cookie[0].trim();
							String value;
							if (cookie.length > 1 && cookie[1] != null){
								value = cookie[1].trim();
							}
							else{
								value = null;
							}
							spConfig.addLoginCookie(name, value);
						}
					}
				}
				else if (key.startsWith(configIdPAttributePrefix)) {
					String[] attribute = propConfig.getProperty(key).split(",");
					String name = attribute[0].trim();
					String nameformat = attribute[1].trim();
					String value = attribute[1].trim();
					spConfig.addAttribute(name, nameformat, value);
				}
				else {
					System.err
							.println("Unknown property in target SP configuration file");
				}

			}
		} catch (IOException e) {
			System.err.println("Could not read the target SP configuration file");
			e.printStackTrace();
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

			// The mock IdP does not need to send a specific/valid SAML Response
			setSamlResponse(null);

			// start login attempt with target SP
			try {
				// create and execute the HTTP Request to access the target SP
				// login page
				HttpUriRequest request = new HttpGet(new URIBuilder(spConfig.getStartPage()).build());

				if (command.hasOption("insecure")) {
					HttpClients
							.custom()
							.setHostnameVerifier(new AllowAllHostnameVerifier())
							.build().execute(request);
				} else {
					HttpClients.createDefault().execute(request);
				}
			} catch (URISyntaxException e) {
				// URI syntax is incorrect
				e.printStackTrace();
			} catch (ClientProtocolException e) {
				// occurs with execute()
				e.printStackTrace();
			} catch (IOException e) {
				// occurs with execute()
				e.printStackTrace();
			}

			// the SAML Request should have been retrieved by the mock IdP and
			// set here during the execute() method
			if (getSamlRequest() != null && !getSamlRequest().isEmpty()) {
				// DEBUG show saml request
				//System.out.println(getSamlRequest());
				/**
				 * Check the SAML Request according to the specifications of the
				 * test case and return the status of the test
				 */
				return reqTC.checkRequest(getSamlRequest(),getSamlRequestBinding());
			} else {
				System.err.println("Could not retrieve the SAML Request that was sent by the target SP");
				return TestStatus.CRITICAL;
			}
		} else if (testcase instanceof LoginTestCase) {
			LoginTestCase loginTC = (LoginTestCase) testcase;
			ArrayList<Boolean> testResults = new ArrayList<Boolean>();

			// get all login attempts that should be tested
			ArrayList<LoginAttempt> logins = (ArrayList<LoginAttempt>) loginTC
					.getLoginAttempts();

			// execute all login attempts
			for (LoginAttempt login : logins) {
				// set the response that should be sent
				setSamlResponse(login.getResponse());

				// start login attempt with target SP
				try {
					URI loginpage;
					if (login.isSPInitiated()) {
						// login from the SP's start page
						loginpage = new URIBuilder(spConfig.getStartPage())
								.build();
					} else {
						// login from the IdP's page
						loginpage = new URIBuilder(
								testsuite.getMockIdPHostname()).setPort(
								testsuite.getMockIdPPort()).build();
					}

					// create and execute the HTTP Request to access the target
					// SP login page
					HttpUriRequest request = new HttpGet(loginpage);
					// create the httpclient, optionally configured to ignore
					// https certificates
					CloseableHttpClient userAgent;
					if (command.hasOption("insecure")) {
						userAgent = HttpClients
								.custom()
								.setHostnameVerifier(
										new AllowAllHostnameVerifier()).build();
					} else {
						userAgent = HttpClients.createDefault();
					}
					// create context to maintain session information
					HttpClientContext session = HttpClientContext.create();
					HttpResponse httpResponse = userAgent.execute(request,
							session);

					// check if the response was redirected (which should be due
					// to the artifact binding)
					if (session.getRedirectLocations().size() > 1) {
						System.err
								.println("Trying to use Artifact binding, this is not yet supported");
						BufferedReader artContent = new BufferedReader(
								new InputStreamReader(httpResponse.getEntity()
										.getContent()));
						String artPage = "";
						while (artContent.ready()) {
							artPage += artContent.readLine() + "\n";
						}
						System.err.println(artPage);
						return null;
					}

					RequestBuilder reqBldr = RequestBuilder
							.post()
							.setUri(getACSLocation(SAMLValues.BINDING_HTTP_POST))
							.addParameter(
									SAMLValues.URLPARAM_SAMLRESPONSE_POST,
									SAMLUtil.encodeSamlMessageForPost(getSamlResponse()));

					HttpResponse response = userAgent.execute(reqBldr.build(),
							session);

					boolean statuscodeMatch = false;
					boolean contentMatch = false;
					boolean cookiesMatch = false;

					// check the HTTP Status code of the page to see if the
					// login was successful
					if (spConfig.getLoginStatuscode() == 0) {
						// do not match against status code
						statuscodeMatch = true;
					} else if (response.getStatusLine().getStatusCode() == spConfig
							.getLoginStatuscode()) {
						statuscodeMatch = true;
					}

					// check the page content to see if the login was successful
					if (spConfig.getLoginContent() == null) {
						// do no match against page content
						contentMatch = true;
					} else {
						// retrieve the page content from the response
						BufferedReader responseContent = new BufferedReader(
								new InputStreamReader(response.getEntity()
										.getContent()));
						// read the page into a string and check if it matches
						// what we expect to see when we log in
						String page = "";
						while (responseContent.ready()) {
							page += responseContent.readLine() + "\n";
						}
						String contentRegex = spConfig.getLoginContent();
						// compile the regex so it allows the dot character to
						// also match new-line characters,
						// which is useful since this is a multi-line string
						Pattern regexP = Pattern.compile(contentRegex,
								Pattern.DOTALL);
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
						List<Cookie> sessionCookies = session.getCookieStore().getCookies();
						
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
										if (value.isEmpty()) {
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

					if (statuscodeMatch && contentMatch && cookiesMatch) {
						testResults.add(new Boolean(true));
					}
					// close the HTTPClient
					userAgent.close();
				} catch (URISyntaxException e) {
					// URI syntax is incorrect
					e.printStackTrace();
				} catch (ClientProtocolException e) {
					// occurs with execute()
					e.printStackTrace();
				} catch (IOException e) {
					// occurs with execute()
					e.printStackTrace();
				}
			}
			/**
			 * Check if the login attempts were valid according to the
			 * specifications of the test case and return the status of the test
			 */
			return loginTC.checkLoginResults(testResults);
		} else {
			System.err.println("Trying to run an unknown type of test case");
			return null;
		}
	}

	/**
	 * Process the test results and output them appropriately
	 * 
	 * @param testresult
	 *            is the result of the test case that was run
	 */
	private static void outputTestResult(Map<TestCase, TestStatus> testresults) {
		// TODO maybe use a templating system to output nicely at some point,
		// now just output to sysout
		// if testcase is null, an error occurred before or after running the
		// test.
		for (Map.Entry<TestCase, TestStatus> testresult : testresults.entrySet()) {
			String name = testresult.getKey().getClass().getSimpleName();
			//String description = testresult.getKey().getDescription();
			String message;
			TestStatus status = testresult.getValue();
			if (status.equals(TestStatus.OK))
				message = status + ": " + testresult.getKey().getSuccessMessage();
			else
				message = status + ": " + testresult.getKey().getFailedMessage();

			System.out.println("Name: " + name);
			//System.out.println("Description: " + description);
			System.out.println("Result: " + message);
			System.out.println("");
		}
	}

	/**
	 * Retrieve the SAML Request
	 * 
	 * @return the SAML Request
	 */
	public static String getSamlRequest() {
		return samlRequest;
	}

	/**
	 * Set the SAML Request
	 * 
	 * @param request
	 *            is the SAML Request
	 */
	public static void setSamlRequest(String request) {
		samlRequest = request;
	}

	/**
	 * Retrieve the SAML Binding
	 * 
	 * @return the SAML Binding
	 */
	public static String getSamlRequestBinding() {
		return samlRequestBinding;
	}

	/**
	 * Set the SAML Binding
	 * 
	 * @param request
	 *            is the SAML Binding
	 */
	public static void setSamlRequestBinding(String binding) {
		samlRequestBinding = binding;
	}

	/**
	 * @return the samlResponse
	 */
	public static String getSamlResponse() {
		return samlResponse;
	}

	/**
	 * @param samlResponse
	 *            the samlResponse to set
	 */
	public static void setSamlResponse(String samlResponse) {
		SPTestRunner.samlResponse = samlResponse;
	}

	/**
	 * Retrieve the location of the AssertionConsumerService for a specific
	 * binding
	 * 
	 * @param binding
	 *            specifies for which binding the location should be retrieved
	 * @return the location for the requested binding
	 */
	public static String getACSLocation(String binding) {
		ArrayList<Node> acsNodes = (ArrayList<Node>) spConfig.getTags(MD.ASSERTIONCONSUMERSERVICE);
		// check all ACS nodes for the requested binding
		for (Node acs : acsNodes) {
			if (acs.getAttributes().getNamedItem(Attribute.BINDING)
					.getNodeValue().equalsIgnoreCase(binding))
				// return the location for the requested binding
				return acs.getAttributes().getNamedItem(Attribute.LOCATION)
						.getNodeValue();
		}
		// the requested binding could not be found
		return "";
	}

	/**
	 * Retrieve the SAML Bindings over which SAML Responses can be sent.
	 * 
	 * This is defined by the AssertionConsumerService Binding attribute in the
	 * SP's metadata
	 * 
	 * @return a list of the SAML Bindings that can be used
	 */
	public static List<String> getSamlSPBindings() {
		return spConfig.getAttributes(MD.ASSERTIONCONSUMERSERVICE, Attribute.BINDING);
	}
}
