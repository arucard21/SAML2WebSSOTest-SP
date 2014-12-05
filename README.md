# SAML2WebSSOTest-SP
Framework for automated testing of SAML 2.0 SP entities, written in Java.

# Description
SAML2WebSSOTest-SP provides a framework for the automated testing of SAML 2.0 SP entities that use the Web SSO profile. This is commonly known as Single Sign-On (though not all Single Sign-On solutions use SAML). This framework allows you to create new test cases or run existing ones. Currently, only a test suite for the SAML2Int (http://saml2int.org) profile is available, but more can be added to the repository if they are supplied. When you run the test(s), the test results are output in JSON format.

### Limitations:
- Artifact binding is not supported

### Prerequisites
- You need to have an SP available and you must be able to add IdP metadata to it as well as retrieve the SP's metadata.

## Usage:

1. Retrieve the mock IdP metadata by running SAML2WebSSOTest-SP with the parameters ```-t/--testsuite``` and ```-m/--metadata```, e.g ```java -jar SAML2WebSSOTest-SP -t SAML2Int" -m``` when running from JAR or ```SAML2WebSSOTest.SP.SPTestRunner -t SAML2Int -m``` when running in an IDE. This will retrieve the metadata for the test suite you specified with ```-t/--testsuite```
2. Configure your SP to use the mock IdP's metadata
3. Copy the ```targetSP.json``` file and fill in the necessary options. This is described in the Configuration section below
4. Optionally copy the ```slf4j.properties``` file as well to specify the logging configuration
5. Run the test cases in a test suite with the parameters ```-t/--testsuite```, ```-s/--spconfig``` and ```-c/--testcase```, e.g. ```java -jar SAML2WebSSOTest-SP -t SAML2Int -s /path/to/targetSP.properties -c MetadataAvailable``` when running from JAR or ```SAML2WebSSOTest.SP.SPTestRunner -t SAML2Int -s /path/to/targetSP.properties -c MetadataAvailable``` when running in an IDE. You can also run this without the ```-c/--testcase``` parameter, this will cause the test to run all test cases in the test suite.

Some additional useful commands are:
- ```SAML2WebSSOTest.SP.SPTestRunner -h``` : Show the help message, containing an overview of all available parameters.
- ```SAML2WebSSOTest.SP.SPTestRunner -L``` : Show a list of all available test suites 
- ```SAML2WebSSOTest.SP.SPTestRunner -t <test suite> -l``` : Show a list of all available test cases in the given test suite

## Configuration:

The configuration is stored in a `targetSP.json` file, which you can edit and keep in your current working directory.

```
{
	"startPage": "<url>",
	"metadata": "<string>",
	"loginStatuscode": 200,
	"loginURL": "<url>",
	"loginContent": "<regex>",
	"loginCookies": [ {"name": "<name>", "value": <value>} ],
	"attributes": [
	{ "namespace": "<namespace>", "prefix": "<prefix>", "attributeName": "<name>", "nameFormat": "<nameformat>", "friendlyName": "<friendlyname>", "attributeValue": "<value>", "customAttributes":[ { "name": "<customname>", "value": "<customvalue>" } ] }
	],
	preloginInteractions: [
		{ interactionType: "<form/link/element>", lookupAttribute: "<id/name/href/text>", lookupValue: "<value>" }
	],
	postResponseInteractions: [
		{ interactionType: "<form/link/element>", lookupAttribute: "<id/name/href/text>", lookupValue: "<value>", submitName: "<name>", inputs: [ { name: "<inputname>", value: "<inputvalue>" } ] }
	]
}
```

You need to provide the following information (make sure the resulting JSON file is valid, e.g. by using a validator like on http://jsonlint.com/):
- `startPage`: The URL for the startpage of your target SP
- `metadata`: Either the actual XML string on a single line or a URL to the metadata
- `loginStatuscode`: The HTTP statuscode that you should get when you are correctly logged in
- `loginURL`: The URL that you should be on when you are correctly logged in
- `loginContent`: A regular expression that matches some of the content of the page you should be on when you are correctly logged in 
- `loginCookies`: A list of the cookies you expect to have when you are correctly logged in
  - You can specify the `name` and/or the `value` of the cookie you expect to have. If you wish to omit one of them, you can specify it as `null`
- `attributes`: A list of SAML attributes that the IdP should provide the target SP in order to log in correctly. For each SAML attribute you must specify the following XML attributes (Note that the SAML attribute is the "saml:Attribute" element and the XML attributes are the attributes on that element):
  - `namespace`: the namespace of the SAML attribute 
  - `prefix`: the prefix for the given namespace
  - `attributeName`: the name of the SAML attribute
  - `nameFormat`: the format in which the name is specified
  - `friendlyName`: a human-readable representation of the SAML attribute's name
  - `attributeValue`: the value of the attribute
  - `customAttributes`: a list of additional, custom XML attributes for this SAML attribute, specified by `name` and `value`
  - `preLoginInteractions`: a list of interactions that should be executed on the login page. The interactions are executed sequentially and should cause the target SP to send its authentication request to the IdP (e.g. clicking an IdP selection link). Each interaction is specified as follows: 
    - `interactionType`: This specifies how you wish to interact with the page. This should be `form`, `link` or `element`.
      - `form`: Allows you to look up a form on the page, fill in some of the fields and submit it
      - `link`: Allows you to look up a link (with some link-specific attributes) on the page and click it
      - `element`: Allows you to look up any HTML element on the page and click it
    - `lookupAttribute`: This should be `id`, `name`, `href` or `text`. Note that `href` and `text` can only be used when interactionType is `link`. 
      - `id`, `name`: The element you wish to interact with will be looked up by its "id" or "name" attribute
      - `href` (link only): The link (anchor) element you wish to interact with will be looked up by its "href" attribute 
      - `text` (link only):  The link (anchor) element you wish to interact with will be looked up by the entire text of the link
    - `lookupValue`: This should be the value of the attribute or text for the element you wish to interact with
    - `submitName` (form only): is the value of the "name" attribute on the submit button
    - `inputs` (form only): is a list of `name`s of the input fields on the form and the corresponding `value`s you wish to fill in 
  - `postResponseInteractions`: a list of interactions that should be executed after the IdP sent its SAML Response. The interactions should cause you to be logged in to the target SP (e.g. by accepting the attributes sent in the SAML Response). The interactions are specified in the same way as the preLoginInteractions.

## Creating your own test suite:

You can create your own test suite in the `saml2webssotest.sp.testsuites` package by extending the provided TestSuite class. You can use the SAML2Int test case as an example.

Each test suite must define the characteristics of its mock IdP. This mock IdP is then used to test the target SP. In order to define your mock IdP, you should implement the abstract methods from the TestSuite class. You need to define the Entity ID, URL and IdP metadata XML for your mock IdP. Aside from these abstract methods, the TestSuite class also contains some utility methods.  

You can then create the test cases. Each test case must be created as an inner class that extends one of the TestCase interfaces that define as specific type of test case:

- `ConfigTestCase`: this type of test case can be used to test aspects of the user's configuration. You can do this by implementing the `checkConfig(SPConfiguration)` method, which supplies the user's configuration so you can check all aspects of it.
- `MetadataTestCase`: this type of test case can be used to test the metadata of the target SP. You can do this by implementing the `checkMetadata(Document)` method, which supplies the SP metadata that was found so you can check all aspects of it.
- `RequestTestCase`: this type of test case can be used to test the SAML Authentication Request XML that was sent by the target SP. You can do this by implementing the `checkRequest(Document)` method, which supplies the Authentication Request, as received by the mock IdP, so you can check all aspects of it.
- `LoginTestCase`: this type of test case can be used to test if you can successfully login to the target SP with different types of SAML Responses by the mock IdP. You can do this by creating a class (or multiple classes, preferably as inner classes) that extend(s) the LoginAttempt interface in order to describe a login attempt. You must then implement the `getLoginAttempts()` method which should return a list of these LoginAttempt objects (you can attempt to login multiple times, for the cases where only one of many attempts need to succeed). Then you should implement the `checkLoginResults(List<Boolean>)` method which provides the results from the list of login attempts you defined so you can evaluate whether these results are as expected. Note that in most cases, you should define a list of only 1 LoginAttempt and check its results. 

Each TestCase should ultimately return a TestStatus, which is an enum of the following values: UNKNOWN, INFORMATION, OK, WARNING, ERROR, CRITICAL.
They should be used as follows:

- `INFORMATION`: This status level is used when nothing can be said about the status of the test. It allows you to return a neutral status, which might sometimes be required.
- `OK`: This status level is used when the test is successful.
- `WARNING`: This status level is used when a test failed, but the failure does not mean non-compliance with the specification. This occurs when testing the recommendations of a specification instead of its requirements.
- `ERROR`: This status level is used when a test failed and its failure indicates non-compliance with the specification.

The values `UNKNOWN` and `CRITICAL` should not be used in the test cases. UNKNOWN is a fallback status, which should never be used, and CRITICAL is used to show that the test itself failed, whenever possible (exceptions can and most likely will still be thrown) 
