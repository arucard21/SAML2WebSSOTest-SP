SAML2WebSSOTest-SP
============

Framework for testing the Web SSO profile of SAML 2.0 SP entities, written in Java.

This is currently functional and can be used to test SP's, although there aren't many tests written yet.

Limitations:
- Artifact binding is not supported
- output is only sent to the console, no formatting and templating options yet

Prerequisites
- You need to have an SP available and you must be able to add IdP metadata to it as well as retrieve the SP's metadata.

Usage:

1. Retrieve the mock IdP metadata by running SAML2WebSSOTest-SP with the parameters ```-t/--testsuite``` and ```-m/--metadata```, e.g ```java -jar SAML2WebSSOTest-SP -t SAML2Int" -m``` when running from JAR or ```SAML2WebSSOTest.SP.SPTestRunner -t SAML2Int -m``` when running in an IDE. This will retrieve the metadata for the test suite you specified with ```-t/--testsuite```
2. Configure your SP to use the mock IdP's metadata
3. Copy the ```targetSP.json``` file and fill in the necessary options. This is described in the Configuration section below
4. Optionally copy the ```slf4j.properties``` file as well to specify the logging configuration
5. Run the test cases in a test suite with the parameters ```-t/--testsuite```, ```-s/--spconfig``` and ```-c/--testcase```, e.g. ```java -jar SAML2WebSSOTest-SP -t SAML2Int -s /path/to/targetSP.properties -c MetadataAvailable``` when running from JAR or ```SAML2WebSSOTest.SP.SPTestRunner -t SAML2Int -s /path/to/targetSP.properties -c MetadataAvailable``` when running in an IDE. You can also run this without the ```-c/--testcase``` parameter, this will cause the test to run all test cases in the test suite.

Some additional useful commands are:
- ```SAML2WebSSOTest.SP.SPTestRunner -h``` : Show the help message, containing an overview of all available parameters.
- ```SAML2WebSSOTest.SP.SPTestRunner -L``` : Show a list of all available test suites 
- ```SAML2WebSSOTest.SP.SPTestRunner -t <test suite> -l``` : Show a list of all available test cases in the given test suite

Configuration:

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
- The startPage url
- The metadata, either the actual XML string on a single line or a URL to the metadata
- The statuscode that you should get when you are correctly logged in
- The URL that you should be on when you are correctly logged in
- A regular expression that matches some of the content of the page you should be on when you are correctly logged in
- A list of the cookies you expect to have when you are correctly logged in
  - You can specify the name and/or the value of the cookie you expect to have. If you wish to omit one of them, you can specify it as "null"
- A list of SAML attributes that the IdP should provide the target SP in order to log in correctly. For each SAML attribute you must specify the following XML attributes (Note that the SAML attribute is the `saml:Attribute` element and the XML attributes are the attributes on that element):
  - namespace: the namespace of the SAML attribute 
  - prefix: the prefix for the given namespace
  - attributeName: the name of the SAML attribute
  - nameFormat: the format in which the name is specified
  - friendlyName: a human-readable representation of the SAML attribute's name
  - attributeValue: the value of the attribute
  - customAttributes: a list of additional, custom XML attributes for this SAML attribute, specified by name and value
  - preLoginInteractions: a list of interaction that you should be executed on the login page. The interactions are executed sequentially and should cause the target SP to send its authentication request to the IdP (e.g. clicking an IdP selection link). Each interaction is specified as follows: 
    - interactionType: This specifies how you wish to interact with the page. This should be "form", "link" or "element".
      - form: Allows you to look up a form on the page, fill in some of the fields and submit it
      - link: Allows you to look up a link (with some link-specific attributes) on the page and click it
      - element: Allows you to look up any HTML element on the page and click it
    - lookupAttribute: This should be "id", "name", "href" or "text". Note that "href" and "text" can only be used when interactionType is "link". 
      - id, name: The element you wish to interact with will be looked up by its "id" or "name" attribute
      - href (link only): The link (anchor) element you wish to interact with will be looked up by its "href" attribute 
      - text (link only):  The link (anchor) element you wish to interact with will be looked up by the entire text of the link
    - lookupValue: This should be the value of the attribute or text for the element you wish to interact with
    - submitName (form only): is the value of the "name" attribute on the submit button
    - inputs (form only): is a list of names of the input fields on the form and the corresponding values you wish to fill in 
  - postResponseInteractions: a list of interaction that you should be executed after the IdP sent its SAML Response. The interactions should cause you to be logged in to the target SP (e.g. by accepting the attributes sent in the SAML Response). The interactions are specified in the same way as the preLoginInteractions.
