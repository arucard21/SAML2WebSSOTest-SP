package saml2webssotest.sp;

import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.net.ssl.SSLHandshakeException;

import org.apache.commons.cli.BasicParser;
import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.HelpFormatter;
import org.apache.commons.cli.Options;
import org.apache.commons.cli.ParseException;
import org.apache.log4j.BasicConfigurator;
import org.apache.log4j.PropertyConfigurator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Document;

import com.gargoylesoftware.htmlunit.FailingHttpStatusCodeException;
import com.gargoylesoftware.htmlunit.Page;
import com.gargoylesoftware.htmlunit.ScriptException;
import com.gargoylesoftware.htmlunit.WebClient;
import com.gargoylesoftware.htmlunit.html.HtmlPage;
import com.gargoylesoftware.htmlunit.util.Cookie;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonIOException;
import com.google.gson.JsonSyntaxException;

import saml2webssotest.common.Interaction;
import saml2webssotest.common.InteractionDeserializer;
import saml2webssotest.common.MetadataDeserializer;
import saml2webssotest.common.StringPair;
import saml2webssotest.common.TestRunner;
import saml2webssotest.common.TestSuite.TestCase;
import saml2webssotest.common.TestSuite.MetadataTestCase;
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
public class SPTestRunner extends TestRunner {
	private static SPTestRunner instance = null;
	/**
	 * Logger for this class
	 */
	private final Logger logger = LoggerFactory.getLogger(SPTestRunner.class);
	/**
	 * Contains the SP configuration
	 */
	private SPConfiguration spConfig;
	/**
	 * Contains the SAML Request that was retrieved by the mock IdP
	 */
	private String samlRequest;
	/**
	 * Contains the SAML binding that was recognized by the mock IdP
	 */
	private String samlRequestBinding;
	/**
	 * Contains the SAML Response that should be sent by the mock IdP
	 */
	private String samlResponse;
	/**
	 * Determines if the test runner is allowed to update signatures on SAML Response elements
	 * (true by default, but might need to be disabled if you wish to test with invalid signatures)
	 */
	private boolean sigUpdateResponseAllowed = true;
	/**
	 * Determines if the test runner is allowed to update signatures on SAML Response elements
	 * (true by default, but might need to be disabled if you wish to test with invalid signatures)
	 */
	private boolean sigUpdateAssertionAllowed = true;
	/**
	 * Contains the command-line options
	 */
	private CommandLine command;
	private final String logFile = "slf4j.properties";
	/**
	 * The package where all test suites can be found, relative to the package containing this class.
	 */
	private String testSuitesPackage = "testsuites";

	private SPTestRunner(String[] args) {
		// initialize logging with properties file if it exists, basic config otherwise
		if (Files.exists(Paths.get(logFile))) {
			PropertyConfigurator.configure(logFile);
		}
		else {
			BasicConfigurator.configure();
		}

		try {
			// define the command-line options
			Options options = new Options();
			options.addOption("h", "help", false, "Print this help message");
			options.addOption("c", "config", true,"The name of the properties file containing the configuration of the target SAML entity");
			options.addOption("e", "showEmbedded", false, "Show test results for tests that are performed within the testing framework");
			options.addOption("l", "listTestcases", false,"List all the test cases");
			options.addOption("L", "listTestsuites", false,"List all the test suites");
			options.addOption("m", "metadata", false,"Display the mock SAML entity's metadata");
			options.addOption("r", "recursive", false,"Run the test suites that your test suite depends on as well (ignored if \"-t, --testcase\" is used)");
			options.addOption("T", "testsuite", true,"Specifies the test suite from which you wish to run a test case");
			options.addOption("t","testcase",true,"The name of the test case you wish to run. If omitted, all test cases from the test suite are run");

			// parse the command line arguments
			command = new BasicParser().parse(options, args);

			// show the help message
			if (command.hasOption("help")) {
				new HelpFormatter().printHelp("SPTestRunner", options, true);
				System.exit(0);
			}

			// list the test suites, if necessary
			if (command.hasOption("listTestsuites")) {
				listTestSuites(SPTestRunner.class.getPackage().getName() + "." + testSuitesPackage);
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
						listTestCases(testsuite);
						System.exit(0);
					}

					// show mock IdP metadata
					if (command.hasOption("metadata")) {
						outputMockedMetadata(testsuite);
						System.exit(0);
					}
					
					// store setting for running depending test suites
					if (command.hasOption("recursive")){
						recursive = true;
					}
					else{
						recursive = false;
					}
					
					// store setting for showing embedded test results
					if (command.hasOption("showEmbedded")){
						showEmbedded = true;
					}
					else{
						showEmbedded = false;
					}

					// load target SP config
					if (command.hasOption("config")) {
						loadConfig(command.getOptionValue("config"));
					}

					// load the requested test case(s)
					testcaseName = command.getOptionValue("testcase");

				} else {
					logger.error("Provided class was not a TestSuite");
				}
			}
		} catch (ClassNotFoundException e) {
			logger.error("Test suite could not be found", e);
		} catch (ClassCastException e) {
			logger.error("The test suite or case was not an instance of TestSuite", e);
		} catch (JsonSyntaxException jsonExc) {
			logger.error("The JSON configuration file did not have the correct syntax", jsonExc);
		} catch (InstantiationException e) {
			logger.error("Could not create an instance of the Test Suite", e);
		} catch (IllegalAccessException e) {
			logger.error("The Test Suite could not be accessed", e);
		} catch (ParseException e) {
			logger.error("The command-line arguments could not be parsed correctly", e);
		}
	}

	public static void main(String[] args) {
		if (instance == null){
			instance = new SPTestRunner(args);
		}
		else{
			System.out.println("SPTestRunner is already running, only one instance can be running at the same time");
		}
		instance.runTestSuite(instance.getMainTestSuite());
		instance.outputTestResults();
	}
	
	public static SPTestRunner getInstance(){
		if (instance == null){
			throw new IllegalStateException("The SPTestRunner instance has not been created yet");
		}
		return instance;
	}
	
	/**
	 * Create the mock server, set its handlers and start the server
	 */
	@Override
	public void initMockServer() {
		mockServer = newMockServer(testsuite.getMockServerURL(), new SamlWebSSOHandler());
		// start the mock IdP
		try {
			mockServer.start();
		} catch (Exception e) {
			logger.error("Could not start the mock server", e);
		}		
	}
	
	/**
	 * Kill the mock server
	 */
	@Override
	public void killMockServer() {
		// start the mock IdP
		try {
			if (mockServer != null && mockServer.isStarted()) {
				mockServer.stop();
			}
		} catch (Exception e) {
			logger.error("Could not kill the mock server", e);
		}
		
	}

	@Override
	public void loadConfig(String file){
		if (file != null && !file.isEmpty()) {
			try {
				spConfig = new GsonBuilder()
						.registerTypeAdapter(Document.class, new MetadataDeserializer())
						.registerTypeAdapter(Interaction.class, new InteractionDeserializer())
						.create()
						.fromJson(Files.newBufferedReader(Paths.get(command.getOptionValue("config")), Charset.defaultCharset()),
								SPConfiguration.class);
			} catch (JsonSyntaxException e) {
				logger.error("The JSON syntax in the configuration was invalid", e);
			} catch (JsonIOException e) {
				logger.error("The target configuration could not be read", e);
			} catch (IOException e) {
				logger.error("The target configuration could be opened", e);
			}
		} else {
			// use empty SP configuration
			spConfig = new SPConfiguration();
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
	@Override
	public boolean runTest(TestCase testcase) {
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
				WebClient browser = getNewBrowser();
				attemptLogin(browser, true);
				browser = getNewBrowser();
				
				//TestRunnerUtil.interactWithPage(browser.getPage(spConfig.getStartPage()), spConfig.getPreLoginInteractions());
				if (samlRequest != null && !samlRequest.isEmpty()) {
					logger.debug("Testing the AuthnRequest");
					logger.trace(samlRequest);
					/**
					 * Check the SAML Request according to the specifications of the
					 * test case and return the status of the test
					 */
					boolean requestResult = reqTC.checkRequest(samlRequest,samlRequestBinding);
					
					return requestResult;
				} else {
					logger.error("Could not retrieve the SAML Request that was sent by the target SP");
					return false;
				}
			} catch (FailingHttpStatusCodeException e) {
				logger.error("The start page returned a failing HTTP status code", e);
				return false;
			}
		} else if (testcase instanceof LoginTestCase) {
			LoginTestCase loginTC = (LoginTestCase) testcase;
			/**
			 * Check if login attempts are handled correctly
			 */
			boolean loginResult = loginTC.checkLogin();
			return loginResult;
		} else {
			logger.error("Trying to run an unknown type of test case");
			return false;
		}
	}

	/**
	 * Attempt to log in to the target SP.
	 * 
	 * This will attempt to log in to the target SP, either SP-initiated or IdP-initiated, and
	 * returns whether or not the attempt was successful.
	 * 
	 * @param browser
	 *            is the browser in which to attempt the login
	 * @param spInitiated
	 *            defines whether the login attempt should be SP-initiated or not
	 * @return true if the login attempt was successful, false if it was unsuccessful and null if
	 * the login procedure could not be completed
	 */
	public Boolean attemptLogin(WebClient browser, boolean spInitiated){
		// determine the ACS location and binding, depending on the received SAML Request
		try {
			HtmlPage responsePage;
			if (spInitiated) {
				// retrieve the login page, thereby sending the AuthnRequest to the mock IdP
				Page startPage = null;
				try{
					startPage = browser.getPage(spConfig.getStartPage());
				}
				catch(SSLHandshakeException badSSL){
					// log the problem with the insecure SSL
					logger.warn("The start page of the target SP uses invalid SSL, retrying without validating SSL certificates");
					// the startpage has insecure SSL so get it without validating
					
					browser.getOptions().setUseInsecureSSL(true);
					// reset browser to apply setting
					browser.closeAllWindows();
					startPage = browser.getPage(spConfig.getStartPage());
					// reset insecure SSL option for future use
					browser.getOptions().setUseInsecureSSL(false);
				}
				responsePage = interactWithPage(startPage, spConfig.getPreLoginInteractions());
			}
			else {
				try{
					// go directly to the IdP page without an AuthnRequest (for idp-initiated authentication)
					responsePage = browser.getPage(testsuite.getMockServerURL().toString());
				}
				catch(Exception badSSL){
					// log the problem with the insecure SSL
					logger.warn("The start page of the target SP uses invalid SSL, retrying without validating SSL certificates");
					// the startpage has insecure SSL so get it without validating
					
					browser.getOptions().setUseInsecureSSL(true);
					// reset browser to apply setting
					browser.closeAllWindows();
					responsePage = browser.getPage(testsuite.getMockServerURL().toString());
					// reset insecure SSL option for future use
					browser.getOptions().setUseInsecureSSL(false);
				}
			}
			// the login succeeded when all configured matches are found
			if (checkLoginHTTPStatusCode(responsePage) 
					&& checkLoginURL(responsePage) 
					&& checkLoginContent(responsePage) 
					&& checkLoginCookies(browser.getCookies(responsePage.getUrl()))) {
				return new Boolean(true);
			}
			else{
				return new Boolean(false);
			}
		} catch (ScriptException e){
			logger.error("Could not correctly redirect back to target SP", e);
		} catch (FailingHttpStatusCodeException e) {
			logger.error("Could not retrieve browser page for the LoginTestCase", e);
		} catch (MalformedURLException e) {
			logger.error("The URL for the start page was malformed", e);
		} catch (IOException e) {
			logger.error("An I/O exception occurred while trying to access the start page", e);
		}
		return null;
	}
	/**
	 * Retrieves a browser that can be used by the test runner. 
	 * 
	 * The browser is created and configured according to any user-supplied options 
	 * 
	 * @return a new WebClient object that can be used as browser by the test runner.
	 */
	public WebClient getNewBrowser(){
		WebClient browser = new WebClient();
		// configure the browser that will be used during testing
		browser.getOptions().setRedirectEnabled(true);
		return browser;
	}

	/**
	 * Retrieves the SAML Request that was received from the SP
	 * 
	 * This is set from the Handler that processes the SP's login attempt
	 * on the mock IdP so it should only be retrieved after a login 
	 * attempt has been initiated
	 * 
	 * @param request is the SAML Request
	 */
	public String getAuthnRequest() {
		return samlRequest;
	}
	/**
	 * Set the SAML Request that was received from the SP
	 * 
	 * This is set from the Handler that processes the SP's login attempt
	 * on the mock IdP.
	 * 
	 * @param request is the SAML Request
	 */
	public void setSamlRequest(String request) {
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
	public void setSamlRequestBinding(String binding) {
		samlRequestBinding = binding;
	}

	/**
	 * Set the SAML Response that should be sent to the SP
	 * 
	 * This is set from the test case, which determines what kind 
	 * of response should be given by the mock IdP
	 * 
	 * @param response is the SAML Response
	 */
	public void setSamlResponse(String response) {
		samlResponse = response;
	}
	
	/**
	 * Retrieve the SAML Response that should be sent to the SP
	 * 
	 * This is mainly used by the mock IdP to retrieve the response 
	 * it should return
	 * 
	 * @return the SAML Response string
	 */
	public String getSamlResponse(){
		return samlResponse;
	}
	/**
	 * Retrieve the SPConfiguration object containing the target SP configuration info
	 * 
	 * @return the SPConfiguration object used in this test
	 */
	public SPConfiguration getSPConfig() {
		return spConfig;
	}

	public boolean checkLoginHTTPStatusCode(HtmlPage page){
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

	public boolean checkLoginURL(HtmlPage responsePage) {
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

	public boolean checkLoginContent(HtmlPage responsePage) {
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

	public boolean checkLoginCookies(Set<Cookie> sessionCookies) {
		// check the cookies
		if (spConfig.getLoginCookies().size() <= 0) {
			// do not check cookies
			return true;
		} else {
			ArrayList<StringPair> checkCookies = spConfig.getLoginCookies();

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
		}
	}

	/**
	 * Check if the test runner is configured to allow updating signatures 
	 * on SAML Response elements
	 * 
	 * @return whether the test runner is allowed to update the signature of 
	 * changed Response elements to keep them valid (default: true) 
	 */
	public boolean isSigUpdateResponseAllowed() {
		return sigUpdateResponseAllowed;
	}

	/**
	 * Configure if the test runner is allowed to update signatures on SAML
	 * Response elements.
	 * 
	 * When signed Response elements are changed in the test runner, usually by
	 * filling in some values found in the AuthnRequest, the Response needs to 
	 * have its signature updated in order for it to be valid. If your test 
	 * requires you to have an invalid signature, you can use this method to 
	 * prevent the test runner from updating the signature. Note that if the
	 * Response element contains no placeholders, the element, including its
	 * signature, will not be changed.
	 * 
	 * @param sigUpdateResponseAllowed is the boolean that determines if signature updates are allowed
	 */
	public void setSigUpdateResponseAllowed(boolean sigUpdateResponseAllowed) {
		this.sigUpdateResponseAllowed = sigUpdateResponseAllowed;
	}

	/**
	 * Check if the test runner is configured to allow updating signatures 
	 * on SAML Assertion elements.  
	 * 
	 * @return whether the test runner is allowed to update the signature of 
	 * changed Assertion elements to keep them valid (default: true)
	 */
	public boolean isSigUpdateAssertionAllowed() {
		return sigUpdateAssertionAllowed;
	}

	/**
	 * Configure if the test runner is allowed to update signatures on SAML
	 * Assertion elements.
	 * 
	 * When signed Assertion elements are changed in the test runner, usually by
	 * filling in some values found in the AuthnRequest, the Assertion needs to 
	 * have its signature updated in order for it to be valid. If your test 
	 * requires you to have an invalid signature, you can use this method to 
	 * prevent the test runner from updating the signature. Note that if the
	 * Assertion element contains no placeholders, the element, including its
	 * signature, will not be changed.
	 * 
	 * @param sigUpdateAssertionAllowed the sigUpdateAssertionAllowed to set
	 */
	public void setSigUpdateAssertionAllowed(boolean sigUpdateAssertionAllowed) {
		this.sigUpdateAssertionAllowed = sigUpdateAssertionAllowed;
	}
}
