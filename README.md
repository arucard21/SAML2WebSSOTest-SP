SAML2_SPTester
============

Framework for testing the Web SSO profile of SAML 2.0 SP entities, written in Java.

This is currently functional and can be used to test SP's, although there aren't many tests written yet.

Limitations:
- Artifact binding is not supported
- output is only sent to the console, no formatting and templating options yet

Prerequisites:
- You need to have an SP available and you must be able to add IdP metadata to it as well as retrieve the SP's metadata.

Usage:
1.	Retrieve the mock IdP metadata by running SAML2Tester-SP with the parameters "-t/--testsuite" and "-m/--metadata", 
	e.g "java -jar SAML2Tester-SP -t SAML2Int" -m" when running from JAR
	or "SAML2Tester-SP.SPTestRunner -t SAML2Int -m" when running in an IDE.
	This will retrieve the metadata for the test suite you specified with "-t/--testsuite"
   
2.	Configure your SP to use the mock IdP's metadata

3. 	Copy the "targetSP.properties" file and fill in the necessary options. 
	The properties file has extensive documentation to help with this.

4.	Optionally copy the slf4j.properties file as well to specify the logging configuration

5.	Run the test cases in a test suite with the parameters "-t/--testsuite", "-s/--spconfig" and "-c/--testcase",
	e.g. "java -jar SAML2Tester-SP -t SAML2Int -s /path/to/targetSP.properties -c MetadataAvailable" when running from JAR
	or "SAML2Tester-SP.SPTestRunner -t SAML2Int -s /path/to/targetSP.properties -c MetadataAvailable" when running in an IDE
	You can also run this without the "-c/--testcase" parameter, this will cause the test to run all test cases in the test suite.

Some additional useful commands are:
- "SAML2Tester-SP.SPTestRunner -h" : Show the help message, containing an overview of all available parameters.
- "SAML2Tester-SP.SPTestRunner -L" : Show a list of all available test suites 
- "SAML2Tester-SP.SPTestRunner -t SAML2Int -l" : Show a list of all available test cases in the test suite "SAML2Int"