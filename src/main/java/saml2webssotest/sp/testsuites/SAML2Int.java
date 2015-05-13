package saml2webssotest.sp.testsuites;

import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;
import java.security.GeneralSecurityException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;

import org.opensaml.Configuration;
import org.opensaml.common.xml.SAMLConstants;
import org.opensaml.saml1.core.AttributeValue;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.Attribute;
import org.opensaml.saml2.core.AuthnContextComparisonTypeEnumeration;
import org.opensaml.saml2.core.AuthnRequest;
import org.opensaml.saml2.core.NameID;
import org.opensaml.saml2.core.NameIDPolicy;
import org.opensaml.saml2.core.RequestedAuthnContext;
import org.opensaml.saml2.core.Response;
import org.opensaml.saml2.core.Subject;
import org.opensaml.saml2.metadata.AssertionConsumerService;
import org.opensaml.saml2.metadata.AttributeConsumingService;
import org.opensaml.saml2.metadata.ContactPerson;
import org.opensaml.saml2.metadata.ContactPersonTypeEnumeration;
import org.opensaml.saml2.metadata.EmailAddress;
import org.opensaml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml2.metadata.IndexedEndpoint;
import org.opensaml.saml2.metadata.KeyDescriptor;
import org.opensaml.saml2.metadata.NameIDFormat;
import org.opensaml.saml2.metadata.SPSSODescriptor;
import org.opensaml.saml2.metadata.ServiceName;
import org.opensaml.xml.LangBearing;
import org.opensaml.xml.util.XMLConstants;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Document;
import org.w3c.dom.NamedNodeMap;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;

import com.gargoylesoftware.htmlunit.WebClient;

import saml2webssotest.common.SAMLAttribute;
import saml2webssotest.common.SAMLUtil;
import saml2webssotest.common.StandardNames;
import saml2webssotest.common.StringPair;
import saml2webssotest.common.TestSuite;
import saml2webssotest.sp.SPConfiguration;
import saml2webssotest.sp.SPTestRunner;


public class SAML2Int extends SPTestSuite {
	/**
	 * Logger for this class
	 */
	private final Logger logger = LoggerFactory.getLogger(SAML2Int.class);

	@Override
	public List<TestSuite> getDependencies() {
		ArrayList<TestSuite> dependencies = new ArrayList<TestSuite>();
		dependencies.add(new SAMLProf_WebSSO());
		dependencies.add(new SAMLBind());
		return dependencies;
	}

	/**
	 *  Tests the following part of the SAML2Int Profile:
	 *  	Identity Providers and Service Providers MUST provide a SAML 2.0 Metadata document representing its entity. 
	 *  	How metadata is exchanged is out of scope of this specification.
	 *   
	 * @author RiaasM
	 *
	 */
	public class MetadataAvailable implements MetadataTestCase {
		private String resultMessage;
		
		@Override
		public String getDescription() {
			return "Test if the Service Provider's metadata is available";
		}

		@Override
		public String getResultMessage() {
			return resultMessage;
		}

		@Override
		public boolean isMandatory() {
			return true;
		}

		@Override
		public boolean checkMetadata(Document metadata) {
			if(metadata != null){
				NodeList mdEDs = metadata.getElementsByTagNameNS(SAMLConstants.SAML20MD_NS, EntityDescriptor.DEFAULT_ELEMENT_LOCAL_NAME);
				// there should be only one entity descriptor
				if(mdEDs.getLength() > 1){
					resultMessage = "The provided metadata contained metadata for multiple SAML entities";
					return false;
				}
				else if(mdEDs.getLength() == 0){
					resultMessage = "The provided metadata contained no metadata for a SAML entity";
					return false;
				}
				Node mdED = mdEDs.item(0);
				String curNS = mdED.getNamespaceURI();
				// check if the provided document is indeed SAML Metadata (or at least uses the SAML Metadata namespace)
				if(curNS != null && curNS.equalsIgnoreCase(SAMLConstants.SAML20MD_NS)){
					resultMessage = "The Service Provider's metadata is available";
					return true;
				}
				else{
					resultMessage = "The Service Provider's metadata did not use the SAML Metadata namespace";
					return false;
				}
			}
			else{
				resultMessage = "The Service Provider's metadata was not available";
				return false;
			}
		}
		
	}

	/**
	 *  Tests the following part of the SAML2Int Profile:
	 *  	Metadata documents provided by a Service Provider MUST include an <md:SPSSODescriptor> element containing 
	 *  	all necessary <md:KeyDescriptor> and <md:AssertionConsumerService> elements.
	 * @author RiaasM
	 *
	 */
	public class MetadataElementsAvailable implements MetadataTestCase{
		private String resultMessage;
	
		@Override
		public String getDescription() {
			return "Test if the Service Provider's metadata contains all minimally required elements";
		}

		@Override
		public String getResultMessage() {
			return resultMessage;
		}
	
		@Override
		public boolean isMandatory() {
			return true;
		}

		/**
		 * Check that the metadata contains at least one SPSSODescriptor containing at least one KeyDescriptor and 
		 * at least one AssertionConsumerService element.
		 */
		@Override
		public boolean checkMetadata(Document metadata) {
			if (metadata != null){
				NodeList spssodList = metadata.getElementsByTagNameNS(SAMLConstants.SAML20MD_NS, SPSSODescriptor.DEFAULT_ELEMENT_LOCAL_NAME);
				
				// make sure you have at least one SPSSODescriptor
				if(spssodList.getLength() > 0){
					// go through all tags to check if they contain the required KeyDescriptor and AssertionConsumerService elements
					for (int i = 0 ; i < spssodList.getLength() ; i++){
						Node spssod = spssodList.item(i);
						// the elements must both be children of this node
						NodeList children = spssod.getChildNodes();
						
						// check all child nodes for the elements we need
						boolean kdFound = false;
						boolean acsFound = false;
						for (int j = 0 ; j < children.getLength() ; j++){
							Node curNode = children.item(j);
							if (curNode.getLocalName().equalsIgnoreCase(KeyDescriptor.DEFAULT_ELEMENT_LOCAL_NAME)){
								kdFound = true;
							}
							if (curNode.getLocalName().equalsIgnoreCase(AssertionConsumerService.DEFAULT_ELEMENT_LOCAL_NAME)){
								acsFound = true;
							}
						}
						// check if both elements were found
						if (kdFound && acsFound){
							resultMessage = "The Service Provider's metadata contains all minimally required elements";
							return true;
						}
					}
					resultMessage = "None of the SPSSODescriptor elements in the Service Provider's metadata contained both the KeyDescriptor and the AssertionConsumerService element";
					return false;
				}
				else{
					resultMessage = "The Service Provider's metadata did not contain an SPSSODescriptor";
					return false;
				}
			}
			else {
				resultMessage = "The test case could not be performed because there was no metadata available";
				return false;
			}
		}
	}

	/**
	 * Tests the following part of the SAML2Int Profile: 
	 * 		The <saml2p:AuthnRequest> message issued by a Service Provider MUST be communicated to the Identity Provider 
	 * 		using the HTTP-REDIRECT binding [SAML2Bind].
	 * 
	 * @author RiaasM
	 *
	 */
	public class RequestByRedirect implements RequestTestCase{
		private String resultMessage; 

		@Override
		public String getDescription() {
			return "Test if the Service Provider can send its Authentication Requests using the HTTP-Redirect binding";
		}

		@Override
		public String getResultMessage() {
			return resultMessage;
		}

		@Override
		public boolean isMandatory() {
			return true;
		}

		@Override
		public boolean checkRequest(String request, String binding) {
			if (binding.equalsIgnoreCase(SAMLConstants.SAML2_REDIRECT_BINDING_URI)){
				resultMessage = "The Service Provider sent its Authentication Request using the HTTP-Redirect binding";
				return true;
			}
			else {
				resultMessage = "The Service Provider did not send its Authentication request using the HTTP-Redirect Binding. Instead, it used: "+binding;
				return false;
			}
		}
		
	}
	
	/**
	 * Tests the following part of the SAML2Int Profile: 
	 * 		The <saml2p:AuthnRequest> message issued by a Service Provider MUST contain an AssertionConsumerServiceURL 
	 * 		attribute identifying the desired response location.
	 * @author RiaasM
	 *
	 */
	public class RequestContainsACSURL implements RequestTestCase{
		private String resultMessage; 

		@Override
		public String getDescription() {
			return "Test if the Service Provider's Authentication Request contains an AssertionConsumerServiceURL attribute";
		}

		@Override
		public String getResultMessage() {
			return resultMessage;
		}

		@Override
		public boolean isMandatory() {
			return true;
		}

		@Override
		public boolean checkRequest(String request, String binding) {
			Node acsURL = SAMLUtil.fromXML(request).getDocumentElement().getAttributes().getNamedItem(AuthnRequest.ASSERTION_CONSUMER_SERVICE_URL_ATTRIB_NAME);
			if (acsURL != null){
				resultMessage = "The Service Provider's Authentication Request contains an AssertionConsumerServiceURL attribute";
				return true;
			}
			else{
				resultMessage = "The Service Provider's Authentication Request did not contain an AssertionConsumerServiceURL attribute";
				return false;
			}
		}
	}

	/**
	 * Tests the following part of the SAML2Int Profile: 
	 * 		The ProtocolBinding attribute, if present, MUST be set to urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST.
	 * @author RiaasM
	 *
	 */
	public class RequestProtocolBinding implements RequestTestCase{
		private String resultMessage;
	
		@Override
		public String getDescription() {
			return "Test if the Service Provider's Authentication Request contains a ProtocolBinding attribute set to HTTP POST";
		}

		@Override
		public String getResultMessage() {
			return resultMessage;
		}
	
		@Override
		public boolean isMandatory() {
			return true;
		}

		@Override
		public boolean checkRequest(String request, String binding) {
			Node protBind = SAMLUtil.fromXML(request).getDocumentElement().getAttributes().getNamedItem(AuthnRequest.PROTOCOL_BINDING_ATTRIB_NAME);
			if (protBind == null){
				resultMessage = "The Service Provider's Authentication Request does not contain a ProtocolBinding attribute";
				return true;
			}
			else{
				if (protBind.getNodeValue().equals(SAMLConstants.SAML2_POST_BINDING_URI)){
					resultMessage = "The Service Provider's Authentication Request contained a ProtocolBinding attribute set to HTTP POST";
					return true;
				}
				else{
					// be more specific in the failed test's message, so it's easier to know what went wrong
					resultMessage = "The Service Provider's Authentication Request contained a ProtocolBinding attribute that was not set to '"+SAMLConstants.SAML2_POST_BINDING_URI+"'";
					return false;
				}
			}
		}
	}

	/**
	 * Tests the following part of the SAML2Int Profile: 
	 * 		The <saml2p:AuthnRequest> message MUST NOT contain a <saml2:Subject> element.
	 * @author RiaasM
	 *
	 */
	public class RequestNoSubject implements RequestTestCase{	
		private String resultMessage;
		@Override
		public String getDescription() {
			return "Test if the Service Provider's Authentication Request contains no Subject node";
		}

		@Override
		public String getResultMessage() {
			return resultMessage;
		}
	
		@Override
		public boolean isMandatory() {
			return true;
		}

		@Override
		public boolean checkRequest(String request, String binding) {
			NodeList subjects = SAMLUtil.fromXML(request).getElementsByTagNameNS(SAMLConstants.SAML20_NS, Subject.DEFAULT_ELEMENT_LOCAL_NAME);
			if (subjects.getLength() == 0){
				resultMessage = "The Service Provider's Authentication Request contains no Subject node";
				return true;
			}
			else{
				resultMessage = "The Service Provider's Authentication Request contained a Subject node";
				return false;
			}
		}
	}

	/**
	 * Tests the following part of the following part of the SAML2Int Profile: 
	 * Service Providers, if they rely at all on particular name identifier formats, MUST support one of the following:
	 * 		urn:oasis:names:tc:SAML:2.0:nameid-format:persistent
	 * 		urn:oasis:names:tc:SAML:2.0:nameid-format:transient
	 * 
	 * @author RiaasM
	 */
	public class LoginTransientPersistent implements LoginTestCase{
		private String resultMessage;

		@Override
		public String getDescription() {
			return "Test if the Service Provider allows logging in with either the persistent or transient name identifier format";
		}

		@Override
		public String getResultMessage() {
			return resultMessage;
		}

		@Override
		public boolean isMandatory() {
			return true;
		}

		@Override
		public boolean checkLogin() {
			// get a browser to test in
			WebClient browser = SPTestRunner.getInstance().getNewBrowser();
			/**
			 * Create the Response we wish the mock IdP to return 
			 */
			// create the minimally required Response with requestID placeholder
			Response response = createMinimalWebSSOResponse(PLACEHOLDER_REQUESTID, PLACEHOLDER_ACSURL);
			// add attributes and sign the assertions in the response
			List<Assertion> assertionsTransient = response.getAssertions();
			
			for (Assertion assertion : assertionsTransient){
				// create nameid with transient format
				NameID nameid = (NameID) Configuration.getBuilderFactory().getBuilder(NameID.DEFAULT_ELEMENT_NAME).buildObject(NameID.DEFAULT_ELEMENT_NAME);
				nameid.setValue("_"+UUID.randomUUID().toString());
				nameid.setFormat(NameID.TRANSIENT);
				assertion.getSubject().setNameID(nameid);

				// add the attributes
				addTargetSPAttributes(assertion);
				SAMLUtil.sign(assertion, getX509Credentials(null));
			}
			// add Destination attribute (mandatory for signed Responses) 
			// with a placeholder for the ACS URL which is the intended value
			response.setDestination(PLACEHOLDER_ACSURL);
			// convert the Response to a String
			String responseTransient = SAMLUtil.toXML(response);
			// store the response in the test runner so the mock IdP can use it
			SPTestRunner.getInstance().setSamlResponse(responseTransient);
			
			/**
			 * Attempt to log in
			 */
			Boolean loginTransient = SPTestRunner.getInstance().attemptLogin(browser, true);
			SPTestRunner.getInstance().setSamlResponse(null);
			
			/**
			 * Reset the browser so we can try another login attempt
			 */
			browser = SPTestRunner.getInstance().getNewBrowser();

			/**
			 * Create the Response we wish the mock IdP to return this time
			 */
			// create the minimally required persistent Response with requestID placeholder
			Response response2 = createMinimalWebSSOResponse(PLACEHOLDER_REQUESTID, PLACEHOLDER_ACSURL);		
			List<Assertion> assertionsPersistent = response2.getAssertions();
			for (Assertion assertion : assertionsPersistent){
				// set nameid to persistent format
				NameID nameid = (NameID) Configuration.getBuilderFactory().getBuilder(NameID.DEFAULT_ELEMENT_NAME).buildObject(NameID.DEFAULT_ELEMENT_NAME);
				nameid.setValue("_"+UUID.randomUUID().toString());
				nameid.setFormat(NameID.PERSISTENT);
				assertion.getSubject().setNameID(nameid);

				// add the attributes
				addTargetSPAttributes(assertion);
				SAMLUtil.sign(assertion, getX509Credentials(null));
			}
			// add Destination attribute (mandatory for signed Responses) 
			// with a placeholder for the ACS URL which is the intended value
			response2.setDestination(PLACEHOLDER_ACSURL);
			// convert the Response to a string
			String responsePersistent = SAMLUtil.toXML(response2);
			// store the response in the test runner so the mock IdP can use it
			SPTestRunner.getInstance().setSamlResponse(responsePersistent);
			
			/**
			 * Complete this second login attempt
			 */
			Boolean loginPersistent = SPTestRunner.getInstance().attemptLogin(browser, true);
			SPTestRunner.getInstance().setSamlResponse(null);

			/**
			 * Check the results of the login attempts
			 */
			if (loginTransient == null || loginPersistent == null){
				logger.debug("The login attempt could not be completed");
				return false;
			}
			else if (loginTransient){	
				if (loginPersistent){
					resultMessage = "The Service Provider could log in with both transient and persistent name identifier format";
					return true;
				}
				else{
					resultMessage = "The Service Provider could log in with transient name identifier format";
					return true;
				}
			}
			else{
				if (loginPersistent){
					resultMessage = "The Service Provider could log in with persistent name identifier format";
					return true;
				}
				else{
					resultMessage = "The Service Provider could log in with neither transient nor persistent name identifier format";
					return false;
				}
			}	
		}
	}
	
	/**
	 * Tests the following part of the following part of the SAML2Int Profile: 
	 * Service Providers MUST support unsolicited <saml2p:Response> messages (i.e., responses that are not the result of an 
	 * earlier <saml2p:AuthnRequest> message).
	 * 
	 * @author RiaasM
	 */
	public class LoginIdPInitiated implements LoginTestCase{
		private String resultMessage;

		@Override
		public String getDescription() {
			return "Test if the Service Provider allows IdP-initiated login";
		}

		@Override
		public String getResultMessage() {
			return resultMessage;
		}

		@Override
		public boolean isMandatory() {
			return true;
		}

		@Override
		public boolean checkLogin() {
			// get a browser to test in
			WebClient browser = SPTestRunner.getInstance().getNewBrowser();
			
			/**
			 * Create the Response we wish the mock IdP to return
			 */
			Response response = createMinimalWebSSOResponse(null, null);
			// add attributes and sign the assertions in the response
			List<Assertion> assertions = response.getAssertions();
			for (Assertion assertion : assertions){
				// create nameid with transient format
				NameID nameid = (NameID) Configuration.getBuilderFactory().getBuilder(NameID.DEFAULT_ELEMENT_NAME).buildObject(NameID.DEFAULT_ELEMENT_NAME);
				nameid.setValue("_"+UUID.randomUUID().toString());
				nameid.setFormat(NameID.TRANSIENT);
				assertion.getSubject().setNameID(nameid);

				// add the attributes
				addTargetSPAttributes(assertion);
				SAMLUtil.sign(assertion, getX509Credentials(null));
			}
			// add Destination attribute (mandatory for signed Responses) 
			// with a placeholder for the ACS URL which is the intended value
			response.setDestination(PLACEHOLDER_ACSURL);
			String responseIdPInitiated = SAMLUtil.toXML(response);
			SPTestRunner.getInstance().setSamlResponse(responseIdPInitiated);
			
			/**
			 * Attempt to log in
			 */
			Boolean loginIdPInitiated = SPTestRunner.getInstance().attemptLogin(browser, false);
			
			/**
			 * Check the result of the login attempt
			 */
			if(loginIdPInitiated == null) {
				logger.debug("The login attempt could not be completed");
				return false;
			}
			else if (loginIdPInitiated) {
				resultMessage = "The Service Provider allowed IdP-initiated login";
				return true;
			}
			else{
				resultMessage = "The Service Provider did not allow IdP-initiated login";
				return false;
			}
		}
	}
	
	/**
	 * Tests the following part of the following part of the SAML2Int Profile:
	 * 		Any <saml2:Attribute> elements exchanged via any SAML 2.0 messages, assertions, [...] MUST contain 
	 * 		a NameFormat of urn:oasis:names:tc:SAML:2.0:attrname-format:uri.
	 * 
	 * @author RiaasM
	 *
	 */
	public class ConfigAttrNameFormatURI implements ConfigTestCase{
		private String resultMessage;
	
		@Override
		public String getDescription() {
			return "Test if the correct NameFormat is configured for attributes";
		}

		@Override
		public String getResultMessage() {
			return resultMessage;
		}
	
		@Override
		public boolean isMandatory() {
			return true;
		}

		@Override
		public boolean checkConfig(SPConfiguration config) {
			ArrayList<SAMLAttribute> attrs = config.getAttributes();
			if (attrs.size() == 0){
				resultMessage = "No attributes were configured so the NameFormat restriction doesn't apply";
				return true;
			}
			else{
				// make sure all attributes use the correct NameFormat
				for (SAMLAttribute attr : attrs){
					if(!attr.getNameFormat().equals(Attribute.URI_REFERENCE)){
						// be more specific in the failed test's message, so it's easier to know what went wrong
						resultMessage = "A configured attribute uses a NameFormat other than '"+Attribute.URI_REFERENCE+"'";
						return false;
					}
				}
				resultMessage = "All attributes were configured with the correct NameFormat";
				return true;
			}
		}
		
	}

	/**
	 * Tests the following part of the SAML2Int Profile:
	 *  	Entities SHOULD publish its metadata using the Well-Known Location method defined in [SAML2Meta].
	 * This means that the metadata should be available on a URL that is represented by the Entity ID
	 * @author RiaasM
	 *
	 */
	public class MetadataWellKnownLocation implements MetadataTestCase {
		private String resultMessage;
		
		@Override
		public String getDescription() {
			return "Test if the Service Provider's metadata is available at the Well-Known Location";
		}

		@Override
		public String getResultMessage() {
			return resultMessage;
		}
	
		@Override
		public boolean isMandatory() {
			return false;
		}

		@Override
		public boolean checkMetadata(Document metadata) {
			if(metadata != null){
				NodeList mdEDs = metadata.getElementsByTagNameNS(SAMLConstants.SAML20MD_NS, EntityDescriptor.DEFAULT_ELEMENT_LOCAL_NAME);
				// there should be only one entity descriptor
				if(mdEDs.getLength() > 1){
					resultMessage = "The provided metadata contained metadata for multiple SAML entities";
					return false;
				}
				else if(mdEDs.getLength() == 0){
					resultMessage = "The provided metadata contained no metadata for a SAML entity";
					return false;
				}
				Node mdED = mdEDs.item(0);
				String entityID = mdED.getAttributes().getNamedItem(EntityDescriptor.ENTITY_ID_ATTRIB_NAME).getNodeValue();
				// try to access the URL represented by the Entity ID and try to retrieve the metadata XML from it
				try{
					DocumentBuilderFactory docBuilderFac = DocumentBuilderFactory.newInstance();
					docBuilderFac.setNamespaceAware(true);
					docBuilderFac.setValidating(false);
					Document mdFromURL = docBuilderFac.newDocumentBuilder().parse(entityID);
					// normalize both XML documents before comparison
					metadata.normalizeDocument();
					mdFromURL.normalizeDocument();
					// check if the document is actually XML
					if(mdFromURL.getXmlVersion() == null){
						resultMessage = "The content found at the Well-Known Location was not an XML document";
						return false;
					}
					// check if the retrieved XML document is the same as the provided metadata
					else if (mdFromURL.isEqualNode(metadata)){
						resultMessage = "The Service Provider's metadata is available at the Well-Known Location";
						return true;
					}
					else{
						resultMessage = "The metadata found at the Well-Known Location was not the same as the target SP's metadata";
						return false;
					}
				}
				catch(MalformedURLException malf){
					resultMessage = "The URL to the Well-Known Location (the URL represented by the Entity ID) was malformed";
					return false;
				} catch (ParserConfigurationException e) {
					resultMessage = "The content found at the Well-Known Location could not be parsed as an XML document due to an incorrectly configured parser";
					return false;
				} catch (SAXException e) {
					resultMessage = "The content found at the Well-Known Location could not be parsed as an XML document";
					return false;
				} catch (IOException e) {
					resultMessage = "The content found at the Well-Known Location could not be accessed (IOException)";
					return false;
				}
			}
			else {
				resultMessage = "The test case could not be performed because there was no metadata available";
				return false;
			}
		}
		
	}

	/**
	 * Tests the following part of the SAML2Int Profile:
	 *  	The metadata SHOULD also include one or more <md:NameIDFormat> elements indicating which <saml2:NameID> 
	 *  	Format values are supported 
	 * 
	 * @author RiaasM
	 *
	 */
	public class MetadataNameIDFormat implements MetadataTestCase {
		private String resultMessage;
		
		@Override
		public String getDescription() {
			return "Test if the Service Provider's metadata contains at least one NameIDFormat element";
		}

		@Override
		public String getResultMessage() {
			return resultMessage;
		}
	
		@Override
		public boolean isMandatory() {
			return false;
		}

		@Override
		public boolean checkMetadata(Document metadata) {
			if(metadata != null){
				NodeList nameidformats = metadata.getElementsByTagNameNS(SAMLConstants.SAML20MD_NS, NameIDFormat.DEFAULT_ELEMENT_LOCAL_NAME);
				// check if there is at least one NameIDFormat
				if(nameidformats.getLength() > 0){
					resultMessage = "The Service Provider's metadata contains a NameIDFormat element";
					return true;
				}
				else {
					resultMessage = "The Service Provider's metadata does not contain a NameIDFormat element";
					return false;
				}
			}
			else {
				resultMessage = "The test case could not be performed because there was no metadata available";
				return false;
			}
		}
		
	}

	/**
	 * Tests the following part of the SAML2Int Profile:
	 *  	Any <saml2:Attribute> elements exchanged via any SAML 2.0 [...] metadata MUST contain 
	 * 		a NameFormat of urn:oasis:names:tc:SAML:2.0:attrname-format:uri.
	 * 
	 * @author RiaasM
	 *
	 */
	public class MetadataAttrNameFormatURI implements MetadataTestCase {
		private String resultMessage;
		
		@Override
		public String getDescription() {
			return "Test if the Service Provider's metadata contains only one attributes with NameFormat value of '"+Attribute.URI_REFERENCE+"'";
		}

		@Override
		public String getResultMessage() {
			return resultMessage;
		}
	
		@Override
		public boolean isMandatory() {
			return true;
		}

		@Override
		public boolean checkMetadata(Document metadata) {
			if(metadata == null){
				resultMessage = "The test case could not be performed because there was no metadata available";
				return false;
			}
			
			NodeList attrs = metadata.getElementsByTagNameNS(SAMLConstants.SAML20MD_NS, Attribute.DEFAULT_ELEMENT_LOCAL_NAME);
			
			if (attrs.getLength() == 0){
				resultMessage = "The Service Provider's metadata contains no attributes, so the requirement does not apply";
				return true;
			}

			// make sure all attributes use the correct NameFormat
			for (int i = 0; i < attrs.getLength(); i++){
				NamedNodeMap attr = attrs.item(i).getAttributes();
				Node nameformat = attr.getNamedItem(Attribute.NAME_FORMAT_ATTRIB_NAME);
					
				// check if the nameformat value is URI
				if(nameformat == null || !nameformat.getNodeValue().equals(Attribute.URI_REFERENCE)){
					// be more specific in the failed test's message, so it's easier to know what went wrong
					resultMessage = "The Service Provider's metadata contain an attribute with a NameFormat value other than '"+Attribute.URI_REFERENCE+"'";
					return false;
				}
			}
			resultMessage = "All attributes were configured with the correct NameFormat";
			return true;
		}
		
	}

	/**
	 * Tests the following part of the SAML2Int Profile:
	 *  	The metadata SHOULD also include [...] and one or more <md:AttributeConsumingService> elements describing 
	 *  	the service(s) offered and their attribute requirements.
	 * This means that the metadata should be available on a URL that is represented by the Entity ID
	 * @author RiaasM
	 *
	 */
	public class MetadataAttrConsumingService implements MetadataTestCase {
		private String resultMessage;
		
		@Override
		public String getDescription() {
			return "Test if the Service Provider's metadata contains at least one AttributeConsumingService element";
		}

		@Override
		public String getResultMessage() {
			return resultMessage;
		}
	
		@Override
		public boolean isMandatory() {
			return false;
		}

		@Override
		public boolean checkMetadata(Document metadata) {
			if(metadata != null){
				NodeList attrConsServs = metadata.getElementsByTagNameNS(SAMLConstants.SAML20MD_NS, AttributeConsumingService.DEFAULT_ELEMENT_LOCAL_NAME);
				// check if there is at least one AttributeConsumingService
				if(attrConsServs.getLength() > 1){
					resultMessage = "The Service Provider's metadata contains a AttributeConsumingService element";
					return true;
				}
				else {
					resultMessage = "The Service Provider's metadata does not contain a AttributeConsumingService element";
					return false;
				}
			}
			else {
				resultMessage = "The test case could not be performed because there was no metadata available";
				return false;
			}
		}
		
	}

	/**
	 * Tests the following part of the SAML2Int Profile:
	 *  	Metadata provided by Service Provider SHOULD also contain a descriptive name of the service that the 
	 *  	Service Provider represents (not the company) [...] The name 
	 *  	should be placed in the <md:ServiceName> in the <md:AttributeConsumingService> container.
	 * 
	 * @author RiaasM
	 *
	 */
	public class MetadataServiceNameAvailable implements MetadataTestCase {
		private String resultMessage;
		
		@Override
		public String getDescription() {
			return "Test if the Service Provider's metadata contains at least one ServiceName element";
		}

		@Override
		public String getResultMessage() {
			return resultMessage;
		}
	
		@Override
		public boolean isMandatory() {
			return false;
		}

		@Override
		public boolean checkMetadata(Document metadata) {
			if(metadata != null){
				NodeList servNames = metadata.getElementsByTagNameNS(SAMLConstants.SAML20MD_NS, ServiceName.DEFAULT_ELEMENT_LOCAL_NAME);
				// check if there is at least one ServiceName
				if(servNames.getLength() > 1){
					resultMessage = "The Service Provider's metadata contains at least one ServiceName element";
					return true;
				}
				else {
					resultMessage = "The Service Provider's metadata does not contain any ServiceName elements";
					return false;
				}
			}
			else {
				resultMessage = "The test case could not be performed because there was no metadata available";
				return false;
			}
		}
		
	}

	/**
	 * Tests the following part of the SAML2Int Profile:
	 *  	Metadata provided by Service Provider SHOULD also contain a descriptive name of the service that the 
	 *  	Service Provider represents (not the company) [...] The name 
	 *  	should be placed in the <md:ServiceName> in the <md:AttributeConsumingService> container.
	 * 
	 * @author RiaasM
	 *
	 */
	public class MetadataServiceNameEnglish implements MetadataTestCase {
		private String resultMessage;
		
		@Override
		public String getDescription() {
			return "Test if the Service Provider's metadata contains at least one ServiceName with language set to English";
		}
	
		@Override
		public String getResultMessage() {
			return resultMessage;
		}
	
		@Override
		public boolean isMandatory() {
			return false;
		}

		@Override
		public boolean checkMetadata(Document metadata) {
			if(metadata != null){
				NodeList servNames = metadata.getElementsByTagNameNS(SAMLConstants.SAML20MD_NS, ServiceName.DEFAULT_ELEMENT_LOCAL_NAME);
				// check if there is at least one AttributeConsumingService
				if(servNames.getLength() > 1){
					// check for service name element in each AttributeConsumingService
					for (int i = 0; i < servNames.getLength(); i++){
						Node servName = servNames.item(i);
						String lang = servName.getAttributes().getNamedItemNS(XMLConstants.XML_NS, LangBearing.XML_LANG_ATTR_LOCAL_NAME).getNodeValue();
						if (lang.contains(StandardNames.LANG_ENGLISH)){
							resultMessage = "The Service Provider's metadata contains at least one English ServiceName with language set to English";
							return true;
						}
					}
					resultMessage = "The Service Provider's metadata does not contain any ServiceName elements with language set to English";
					return false;
				}
				else {
					resultMessage = "The Service Provider's metadata does not contain any ServiceName elements";
					return false;
				}
			}
			else {
				resultMessage = "The test case could not be performed because there was no metadata available";
				return false;
			}
		}
		
	}

	/**
	 * Tests the following part of the SAML2Int Profile:
	 *  	If a Service Provider forgoes the use of TLS/SSL for its Assertion Consumer Service endpoints, then [...]
	 *  	Note that use of TLS/SSL is RECOMMENDED.
	 * 
	 * @author RiaasM
	 *
	 */
	public class MetadataHTTPS implements MetadataTestCase {
		private String resultMessage;
		
		@Override
		public String getDescription() {
			return "Test if the Service Provider uses TLS/SSL for its Assertion Consumer Service endpoints";
		}

		@Override
		public String getResultMessage() {
			return resultMessage;
		}
	
		@Override
		public boolean isMandatory() {
			return false;
		}

		@Override
		public boolean checkMetadata(Document metadata) {
			if(metadata != null){
				NodeList ACSs = metadata.getElementsByTagNameNS(SAMLConstants.SAML20MD_NS, AssertionConsumerService.DEFAULT_ELEMENT_LOCAL_NAME);
				// check if there is at least one ACS
				if(ACSs.getLength() > 0){
					// check for each ACS if they are using TLS/SSL
					int HTTPScount = 0;
					for (int i = 0; i < ACSs.getLength(); i++){
						Node ACS = ACSs.item(i);
						String ACSLoc = ACS.getAttributes().getNamedItem(IndexedEndpoint.LOCATION_ATTRIB_NAME).getNodeValue();
						try {
							URL ACSLocURL = new URL(ACSLoc);
							if (ACSLocURL.getProtocol().equalsIgnoreCase("https")){
								// Create a trust manager that does not validate certificate chains since we are not 
								// trying to test the certificate validity
								TrustManager[] trustAllCerts = new TrustManager[] { 
								    new X509TrustManager() {
										
										@Override
										public X509Certificate[] getAcceptedIssuers() {
											return new X509Certificate[0];
										}
										
										@Override
										public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {				
										}
										
										@Override
										public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {
										}
									}};

								// Install the all-trusting trust manager
								try {
								    SSLContext sc = SSLContext.getInstance("SSL"); 
								    sc.init(null, trustAllCerts, new java.security.SecureRandom()); 
								    HttpsURLConnection.setDefaultSSLSocketFactory(sc.getSocketFactory());
								} catch (GeneralSecurityException e) {
								} 
								// connect to the URL to retrieve which cipher is actually used
								HttpsURLConnection acsConn = (HttpsURLConnection) ACSLocURL.openConnection();
								acsConn.connect();
								String cipher = acsConn.getCipherSuite();
								acsConn.disconnect();
								// check if cipher belongs to TLS or SSL v3.0 protocol
								if (cipher.startsWith("TLS_")){
									// accept all TLS ciphers
									HTTPScount++;
								}
								else if (StandardNames.sslv3.contains(cipher)){
									// cipher is part of SSLv3 protocol
									HTTPScount++;
								}
							}
						} catch (MalformedURLException e) {
							logger.debug("The Service Provider's metadata contains at least one malformed Assertion Consumer Service Locations URL", e);						
						} catch (IOException e) {
							logger.debug("The Service Provider's metadata could not be accessed", e);
						}
					}
					if (HTTPScount == 0){
						resultMessage = "The Service Provider neglects using TLS/SSL on any of its Assertion Consumer Service endpoints";
						return false;
					}
					else if (HTTPScount < ACSs.getLength()){
						resultMessage = "The Service Provider neglect using TLS/SSL on some of its Assertion Consumer Service endpoints";
						return false;
					}
					else if (HTTPScount == ACSs.getLength()){
						resultMessage = "The Service Provider uses TLS/SSL for all its Assertion Consumer Service endpoints";
						return true;
					}
					else{
						// HTTPScount is larger than the the length of the ACSs Nodelist, which should never be possible
						resultMessage = "Error occurred in the MetadataHTTPS test case while checking the ACS URLs";
						return false;
					}
					
				}
				else {
					resultMessage = "The Service Provider's metadata does not contain any Assertion Consumer Service elements";
					return false;
				}
			}
			else {
				resultMessage = "The test case could not be performed because there was no metadata available";
				return false;
			}
		}
		
	}

	/**
	 * Tests the following part of the SAML2Int Profile:
	 *  	If a Service Provider forgoes the use of TLS/SSL for its Assertion Consumer Service endpoints, 
	 *  	then its metadata SHOULD include a <md:KeyDescriptor> suitable for XML Encryption. 
	 * 
	 * @author RiaasM
	 *
	 */
	public class MetadataEncryptionKey implements MetadataTestCase {
		private String resultMessage;
		
		@Override
		public String getDescription() {
			return "Test if the Service Provider's metadata contains an encryption key when not using TLS/SSL for its Assertion Consumer Service endpoints";
		}
	
		@Override
		public String getResultMessage() {
			return resultMessage;
		}
	
		@Override
		public boolean isMandatory() {
			return false;
		}

		@Override
		public boolean checkMetadata(Document metadata) {
			if(metadata != null){
				NodeList ACSs = metadata.getElementsByTagNameNS(SAMLConstants.SAML20MD_NS, AssertionConsumerService.DEFAULT_ELEMENT_LOCAL_NAME);
				// check if there is at least one ACS
				if(ACSs.getLength() > 0){
					// check for each ACS if they are using TLS/SSL
					int HTTPScount = 0;
					for (int i = 0; i < ACSs.getLength(); i++){
						Node ACS = ACSs.item(i);
						String ACSLoc = ACS.getAttributes().getNamedItem(IndexedEndpoint.LOCATION_ATTRIB_NAME).getNodeValue();
						try {
							URL ACSLocURL = new URL(ACSLoc);
							if (ACSLocURL.getProtocol().equalsIgnoreCase("https")){
								HTTPScount++;
							}
						} catch (MalformedURLException e) {
							resultMessage = "The Service Provider's metadata contains at least one malformed Assertion Consumer Service Locations URL";
							return false;
						}
					}
					// check if all ACSs are using TLS/SSL
					if (HTTPScount < ACSs.getLength()){
						// check if at least one encryption key is available
						NodeList KDs = metadata.getElementsByTagNameNS(SAMLConstants.SAML20MD_NS, KeyDescriptor.DEFAULT_ELEMENT_LOCAL_NAME);
						if(KDs.getLength() > 0){
							for (int i = 0; i < KDs.getLength(); i++){
								Node KD = KDs.item(i);
								NamedNodeMap KDattr = KD.getAttributes();
								if (KDattr == null){
									// no attributes found, so no "use" attribute found
									// without use attribute, key is used for both signing and encryption,
									// so we have found an encryption key
									resultMessage = "The Service Provider's metadata contains an encryption key";
									return true;
								}
								else {
									Node KDuse = KDattr.getNamedItem(KeyDescriptor.USE_ATTRIB_NAME);
									if (KDuse == null){
										// value should only be "signing" or "encryption" so metadata is invalid
										resultMessage = "The Service Provider's metadata contains an empty 'use' attribute, which makes the metadata invalid";
										return false;
									}
									else{
										String use = KDuse.getNodeValue();
										if (use.isEmpty()){
											// value should only be "signing" or "encryption" so metadata is invalid
											resultMessage = "The Service Provider's metadata contains an empty 'use' attribute, which makes the metadata invalid";
											return false;
										}
										else if (use.equals(StandardNames.USE_ENCRYPTION)){
											resultMessage = "The Service Provider's metadata contains an encryption key";
											return true;
										}
									}
								}
							}
							resultMessage = "The Service Provider's metadata does not contain an encryption key and neglects to use TLS/SSL for all of its Assertion Consumer Service endpoints";
							return false;
						}
						else{
							resultMessage = "The Service Provider's metadata does not contain any keys and neglects to use TLS/SSL for all of its Assertion Consumer Service endpoints";
							return false;
						}
					}
					else if (HTTPScount == ACSs.getLength()){
						resultMessage = "The Service Provider uses TLS/SSL on all of its Assertion Consumer Service endpoints, so this requirement does not apply";
						return true;
					}
					else{
						// HTTPScount is larger than the the length of the ACSs Nodelist, which should never be possible
						resultMessage = "Error occurred in the MetadataHTTPS test case while checking the ACS URLs";
						return false;
					}
				}
				else {
					resultMessage = "The Service Provider's metadata does not contain any Assertion Consumer Service elements";
					return false;
				}
			}
			else {
				resultMessage = "The test case could not be performed because there was no metadata available";
				return false;
			}
		}
		
	}

	/**
	 * Tests the following part of the SAML2Int Profile: 
	 * 		Metadata provided by
	 * 		both Identity Providers and Service Provider SHOULD contain contact
	 * 		information for support and for a technical contact. The
	 * 		<md:EntityDescriptor> element SHOULD contain both a <md:ContactPerson>
	 * 		element with a contactType of "support" and a <md:ContactPerson> element
	 * 		with a contactType of "technical".
	 * 
	 * @author LaurentB, RiaasM
	 * 
	 */
	public class MetadataContactInfo implements MetadataTestCase {
		private String resultMessage;
		
		@Override
		public String getDescription() {
			return "Test if the Service Provider's metadata contains contact information for a support and a technical contact";
		}

		@Override
		public String getResultMessage() {
			return resultMessage;
		}
	
		@Override
		public boolean isMandatory() {
			return false;
		}

		@Override
		public boolean checkMetadata(Document metadata) {
			if(metadata == null){
				resultMessage = "The test case could not be performed because there was no metadata available";
				return false;
			}
			
			NodeList contactPersons = metadata.getElementsByTagNameNS(SAMLConstants.SAML20MD_NS, ContactPerson.DEFAULT_ELEMENT_LOCAL_NAME);
			
			// check if there is not none contact persons
			if(contactPersons.getLength() == 0){
				resultMessage = "The Service Provider's metadata contains no Contact Persons";
				return false;
			}
			
			// check if there is not one contact persons
			if(contactPersons.getLength() == 1){
				resultMessage = "The Service Provider's metadata contains only one Contact Person";
				return false;
			}
			
			// check if there is at least one support and one technical contact person
			boolean supportFound = false;
			boolean technicalFound = false;
			for (int i = 0; i < contactPersons.getLength(); i++){
				Node contactPerson = contactPersons.item(i);
				String contactType = contactPerson.getAttributes().getNamedItem(ContactPerson.CONTACT_TYPE_ATTRIB_NAME).getNodeValue();
				if (contactType.equals(ContactPersonTypeEnumeration.SUPPORT)) {
					supportFound = true;
				}
				else if (contactType.equals(ContactPersonTypeEnumeration.TECHNICAL)){
					technicalFound = true;
				}
			}
			
			if (supportFound && technicalFound){
				resultMessage = "The Service Provider's metadata contains contact information for both a support and a technical contact";
				return true;
			}
			else if (supportFound){
				resultMessage = "The Service Provider's metadata contains only support Contact Persons";
				return false;
			}
			else if (technicalFound){
				resultMessage = "The Service Provider's metadata contains only technical Contact Persons";
				return false;
			}
			else {
				resultMessage = "The Service Provider's metadata contains no support or technical Contact Persons";
				return false;
			}
		}
		
	}

	/**
	 * Tests the following part of the SAML2Int Profile: 
	 * 		The <md:ContactPerson> elements SHOULD contain at least one <md:EmailAddress>. 
	 * 
	 * @author RiaasM
	 * 
	 */
	public class MetadataContactEmail implements MetadataTestCase {
		private String resultMessage;
		
		@Override
		public String getDescription() {
			return "Test if the Service Provider's metadata contains EmailAddress elements for all its ContactPerson elements";
		}
	
		@Override
		public String getResultMessage() {
			return resultMessage;
		}
	
		@Override
		public boolean isMandatory() {
			return false;
		}

		@Override
		public boolean checkMetadata(Document metadata) {
			if(metadata == null){
				resultMessage = "The test case could not be performed because there was no metadata available";
				return false;
			}
			
			NodeList contactPersons = metadata.getElementsByTagNameNS(SAMLConstants.SAML20MD_NS, ContactPerson.DEFAULT_ELEMENT_LOCAL_NAME);
			
			// check if there are contactpersons found
			if(contactPersons.getLength() == 0){
				resultMessage = "The Service Provider's metadata contains no Contact Persons";
				return false;
			}
			
			// check if each contactperson has at least one emailaddress
			int emailCount = 0;
			for (int i = 0; i < contactPersons.getLength(); i++){
				Node contactPerson = contactPersons.item(i);
				NodeList emailaddresses = contactPerson.getChildNodes();
				for (int j = 0; j < emailaddresses.getLength(); j++){
					if (emailaddresses.item(j).getNodeName().equals(EmailAddress.DEFAULT_ELEMENT_LOCAL_NAME)){
						// found an emailaddress element for this contactperson 
						emailCount++;
						break;
					}
				}
			}
			
			if (emailCount == 0){
				resultMessage = "The Service Provider's metadata contains no EmailAddress elements for any of its ContactPerson elements";
				return false;
			}
			else if (emailCount < contactPersons.getLength()){
				resultMessage = "The Service Provider's metadata contains EmailAddress elements for some, but not all, of its ContactPerson elements";
				return false;
			}
			else if (emailCount == contactPersons.getLength()){
				resultMessage = "The Service Provider's metadata contains EmailAddress elements for all its ContactPerson elements";
				return true;
			}
			else {
				// emailCount is larger than the the length of the contactPersons Nodelist, which should never be possible
				resultMessage = "Error occurred in the MetadataContactEmail test case while checking the ContactPerson elements";
				return false;
			}
		}
	}

	/**
	 * Tests the following part of the SAML2Int Profile:
	 *  	Reliance on other formats by Service Providers is NOT RECOMMENDED.
	 *  This can only partially be tested, namely by checking what NameIDFormat is configured in the SP's metadata
	 * 
	 * @author RiaasM
	 *
	 */
	public class MetadataNameIDFormatOther implements MetadataTestCase {
		private String resultMessage;
		
		@Override
		public String getDescription() {
			return "Test if the Service Provider's metadata contains only NameIDFormat values of other than '"+NameID.TRANSIENT+"' or '"+NameID.PERSISTENT+"'";
		}
	
		@Override
		public String getResultMessage() {
			return resultMessage;
		}
	
		@Override
		public boolean isMandatory() {
			return false;
		}

		@Override
		public boolean checkMetadata(Document metadata) {
			if(metadata == null){
				resultMessage = "The test case could not be performed because there was no metadata available";
				return false;
			}
					
			NodeList nameidformats = metadata.getElementsByTagNameNS(SAMLConstants.SAML20MD_NS, NameIDFormat.DEFAULT_ELEMENT_LOCAL_NAME);
			
			// check if there is at least one NameIDFormat
			if(nameidformats.getLength() == 0){
				resultMessage = "The Service Provider's metadata does not contain a NameIDFormat element";
				return false;
			}
			
			// check the value of all NameIDFormats
			for (int i = 0; i < nameidformats.getLength(); i++){
				String nameidformatValue = nameidformats.item(i).getTextContent();
				if (nameidformatValue == null){
					resultMessage = "The Service Provider's metadata contains an empty 'NameIDFormat' element, which makes the metadata invalid";
					return false;
				}
				else if(!nameidformatValue.equals(NameID.TRANSIENT) && !nameidformatValue.equals(NameID.PERSISTENT)){
					// SP uses a NameIDFormat other than transient and persistent
					resultMessage = "The Service Provider's metadata contains at least one NameIDFormat value other than '"+NameID.TRANSIENT+"' or '"+NameID.PERSISTENT+"'";
					return false;
				}
			}
			resultMessage = "The Service Provider's metadata contains only NameIDFormat values of other than '"+NameID.TRANSIENT+"' or '"+NameID.PERSISTENT+"'";
			return true;
		}	
	}

	/**
	 * Tests the following part of the following part of the SAML2Int Profile:
	 * 		The use of LDAP/X.500 attributes and the LDAP/X.500 attribute profile [X500SAMLattr] is RECOMMENDED where possible.
	 * 
	 * The LDAP/X.500 attribute profile is used when the attributes are configured to use the X.500 namespace with an 
	 * Encoding attribute set to "LDAP".
	 * 
	 * @author RiaasM
	 *
	 */
	public class ConfigAttrLDAP implements ConfigTestCase{
		private String resultMessage;

		@Override
		public String getDescription() {
			return "Test if the attributes that are configured are using the LDAP/X.500 profile";
		}

		@Override
		public String getResultMessage() {
			return resultMessage;
		}
	
		@Override
		public boolean isMandatory() {
			return false;
		}

		@Override
		public boolean checkConfig(SPConfiguration config) {
			ArrayList<SAMLAttribute> attrs = config.getAttributes();
			if (attrs.size() == 0){
				resultMessage = "No attributes were configured so this test case doesn't apply";
				return true;
			}
			else{
				// make sure all attributes use the LDAP/X.500 profile
				for (SAMLAttribute attr : attrs){
					// check if the LDAP/X.500 namespace is used
					if (!attr.getNamespace().equals(StandardNames.NAMESPACE_ATTR_X500)) {
						// be more specific in the failed test's message, so it's easier to know what went wrong
						resultMessage = "The configured SAML attribute does not use the LDAP/X.500 attribute profile";
						return false;
					}
					// check if the LDAP/X.500 Encoding attribute is supplied, and if so, if the correct value is filled in
					ArrayList<StringPair> customAttrs = attr.getCustomAttributes();
					boolean encodingValid = false;
					for (StringPair customAttr : customAttrs) {
						if (customAttr.getName().equalsIgnoreCase(StandardNames.X500_ENCODING)) {
							if (customAttr.getValue().equalsIgnoreCase(StandardNames.X500_ENCODING_LDAP)) {
								encodingValid = true;
							}
							else {
								resultMessage = "The configured SAML attribute has an Encoding attribute with a value other than 'LDAP'";
								return false;
							}
						}
					}
					if (!encodingValid){
						resultMessage = "The configuration contained an attribute without an Encoding attribute";
						return false;
					}
				}
				resultMessage = "The attributes that are configured are using the LDAP/X.500 profile";
				return true;
			}
		}
	}

	/**
	 * Tests the following part of the SAML2Int Profile:
	 *  	The use of LDAP/X.500 attributes and the LDAP/X.500 attribute profile [X500SAMLattr] is RECOMMENDED where possible.
	 * 
	 * @author RiaasM
	 *
	 */
	public class MetadataAttrLDAP implements MetadataTestCase {
		private String resultMessage;
		
		@Override
		public String getDescription() {
			return "Test if the attributes that are requested in the Service Provider's metadata are using the LDAP/X.500 profile";
		}
	
		@Override
		public String getResultMessage() {
			return resultMessage;
		}

		@Override
		public boolean isMandatory() {
			return false;
		}

		@Override
		public boolean checkMetadata(Document metadata) {
			if(metadata == null){
				resultMessage = "The test case could not be performed because there was no metadata available";
				return false;
			}
			
			NodeList attrs = metadata.getElementsByTagNameNS(SAMLConstants.SAML20MD_NS, Attribute.DEFAULT_ELEMENT_LOCAL_NAME);
			
			if (attrs.getLength() == 0){
				resultMessage = "The Service Provider's metadata contains no attributes, so the test case does not apply";
				return true;
			}
			
			// make sure all attributes use the LDAP/X.500 profile
			for (int i = 0; i < attrs.getLength(); i++){
				Node attr = attrs.item(i);
				
				// check if the LDAP/X.500 namespace is used
				if(!attr.getNamespaceURI().equals(StandardNames.NAMESPACE_ATTR_X500)){
					// be more specific in the failed test's message, so it's easier to know what went wrong
					resultMessage = "A configured SAML attribute does not use the LDAP/X.500 attribute profile";
					return false;
				}
				// check if the LDAP/X.500 Encoding attribute is supplied, and if so, if the correct value is filled in
				Node x500Enc = attr.getAttributes().getNamedItemNS(StandardNames.NAMESPACE_ATTR_X500, StandardNames.X500_ENCODING);
				if (x500Enc != null){
					if (!x500Enc.getNodeValue().equals(StandardNames.X500_ENCODING_LDAP)){
						resultMessage = "A configured SAML attribute has an x500:Encoding attribute with a value other than 'LDAP'";
						return false;
					}
				}
			}
			resultMessage = "The attributes that are configured are using the LDAP/X.500 profile";
			return true;
		}
		
	}

	/**
	 * Tests the following part of the following part of the SAML2Int Profile:
	 * 		It is RECOMMENDED that the content of <saml2:AttributeValue> elements exchanged via any SAML 2.0 messages, assertions, 
	 * 		or metadata be limited to a single child text node (i.e., a simple string value).
	 * 
	 * @author RiaasM
	 *
	 */
	public class ConfigAttrValueSimple implements ConfigTestCase{
		private String resultMessage;
	
		@Override
		public String getDescription() {
			return "Test if the attributes that are configured have simple string values";
		}
	
		@Override
		public String getResultMessage() {
			return resultMessage;
		}
	
		@Override
		public boolean isMandatory() {
			return false;
		}

		@Override
		public boolean checkConfig(SPConfiguration config) {
			ArrayList<SAMLAttribute> attrs = config.getAttributes();
			if (attrs.size() == 0){
				resultMessage = "No attributes were configured so this test case doesn't apply";
				return true;
			}
			else{
				// make sure all attributes use the LDAP/X.500 profile
				for (SAMLAttribute attr : attrs){
					// check if the attribute contains XML instead of a simple string value
					if(attr.getAttributeValue().startsWith("<")){
						// be more specific in the failed test's message, so it's easier to know what went wrong
						resultMessage = "The configured SAML attribute does not have a simple string value";
						return false;
					}
				}
				resultMessage = "The attributes that are configured have simple string values";
				return true;
			}
		}
	}

	/**
	 * Tests the following part of the SAML2Int Profile:
	 *  	It is RECOMMENDED that the content of <saml2:AttributeValue> elements exchanged via any SAML 2.0 messages, assertions, 
	 *  	or metadata be limited to a single child text node (i.e., a simple string value).
	 * 
	 * @author RiaasM
	 *
	 */
	public class MetadataAttrValueSimple implements MetadataTestCase {
		private String resultMessage;
		
		@Override
		public String getDescription() {
			return "Test if the attributes that are requested in the Service Provider's metadata have simple string values";
		}
	
		@Override
		public String getResultMessage() {
			return resultMessage;
		}
	
		@Override
		public boolean isMandatory() {
			return false;
		}

		@Override
		public boolean checkMetadata(Document metadata) {
			if(metadata == null){
				resultMessage = "The test case could not be performed because there was no metadata available";
				return false;
			}
			
			NodeList attrvals = metadata.getElementsByTagNameNS(SAMLConstants.SAML20MD_NS, AttributeValue.DEFAULT_ELEMENT_LOCAL_NAME);
			
			if (attrvals.getLength() == 0){
				resultMessage = "The Service Provider's metadata contains no attributes, so the test case does not apply";
				return true;
			}
			
			// make sure all attributes use the LDAP/X.500 profile
			for (int i = 0; i < attrvals.getLength(); i++){
				Node attrval = attrvals.item(i);
				
				// check if the AttributeValue element has only a single child text node
				if(attrval.getChildNodes().getLength() == 1 && attrval.getChildNodes().item(0).getNodeType() == Node.TEXT_NODE){
					// be more specific in the failed test's message, so it's easier to know what went wrong
					resultMessage = "A configured SAML attribute does not have simple string values";
					return false;
				}
			}
			resultMessage = "The attributes that are configured have simple string values";
			return true;
		}
		
	}

	/**
	 * Tests the following part of the SAML2Int Profile: 
	 * 		It is OPTIONAL to apply any form of URL canonicalization, which means the Service Provider SHOULD NOT rely on differently 
	 * 		canonicalized values in these two locations [refers to the ACSURL of the request and the Location of the ACS element in 
	 * 		the SP metadata]. As an example, the Service Provider SHOULD NOT use a hostname with port number (such as 
	 * 		https://sp.example.no:80/acs) in its request and without (such as https://sp.example.no/acs) in its metadata.
	 * @author RiaasM
	 *
	 */
	public class RequestACSURLCanonicalization implements RequestTestCase{
		private String resultMessage; 
	
		@Override
		public String getDescription() {
			return "Test if the Service Provider's Authentication Request's AssertionConsumerServiceURL attribute uses the same canonicalization as in the Service Provider's metadata";
		}

		@Override
		public String getResultMessage() {
			return resultMessage;
		}
	
		@Override
		public boolean isMandatory() {
			return false;
		}

		@Override
		public boolean checkRequest(String request, String binding) {
			Node acsURL = SAMLUtil.fromXML(request).getDocumentElement().getAttributes().getNamedItem(AuthnRequest.ASSERTION_CONSUMER_SERVICE_URL_ATTRIB_NAME);
			if (acsURL != null){
				NodeList acss = SPTestRunner.getInstance().getSPConfig().getMetadata().getElementsByTagNameNS(SAMLConstants.SAML20MD_NS, AssertionConsumerService.DEFAULT_ELEMENT_LOCAL_NAME);
				// check if acsURL is available as location in the list of acs's 
				// when comparing the URL's directly as strings without compensating for canonicalization 
				for (int i = 0; i < acss.getLength(); i++){
					if (acss.item(i).getAttributes().getNamedItem(IndexedEndpoint.LOCATION_ATTRIB_NAME).getNodeValue().equals(acsURL.getNodeValue())){
						resultMessage = "The Service Provider's Authentication Request's AssertionConsumerServiceURL attribute uses the same canonicalization as in the Service Provider's metadata";
						return true;
					}
				}
				resultMessage = "The Service Provider's Authentication Request's AssertionConsumerServiceURL attribute did not use the same canonicalization as in the Service Provider's metadata";
				return false;
			}
			else{
				resultMessage = "The Service Provider's Authentication Request's AssertionConsumerServiceURL attribute was not available";
				return false;
			}
		}
	}

	/**
	 * Tests the following part of the SAML2Int Profile: 
	 * 		The <saml2p:AuthnRequest> message SHOULD contain a <saml2p:NameIDPolicy> element with an AllowCreate attribute of "true". 
	 * @author RiaasM
	 *
	 */
	public class RequestNameIDPolicy implements RequestTestCase{
		private String resultMessage; 
	
		@Override
		public String getDescription() {
			return "Test if the Service Provider's Authentication Request contains a NameIDPolicy with an AllowCreate attribute of true";
		}

		@Override
		public String getResultMessage() {
			return resultMessage;
		}
	
		@Override
		public boolean isMandatory() {
			return false;
		}

		@Override
		public boolean checkRequest(String request, String binding) {
			NodeList nameIDPolicies = SAMLUtil.fromXML(request).getElementsByTagNameNS(SAMLConstants.SAML20P_NS, NameIDPolicy.DEFAULT_ELEMENT_LOCAL_NAME);
			// check if the request has any NameIDPolicy elements
			if (nameIDPolicies.getLength() == 0){
				resultMessage = "The Service Provider's Authentication Request does not contain a NameIDPolicy";
				return false;
			}
			// check if at least one of the NameIDPolicy elements has an AllowCreate attribute of true
			boolean found = false;
			for (int i = 0; i < nameIDPolicies.getLength(); i++){
				Node allowcreate = nameIDPolicies.item(i).getAttributes().getNamedItem(NameIDPolicy.ALLOW_CREATE_ATTRIB_NAME);
				if (allowcreate != null && allowcreate.getNodeValue().equalsIgnoreCase("true"))
					found = true;
			}
			if (found){
				resultMessage = "The Service Provider's Authentication Request contains a NameIDPolicy with an AllowCreate attribute of true";
				return true;
			}
			else{
				resultMessage = "The Service Provider's Authentication Request does not contain a NameIDPolicy with an AllowCreate attribute of true";
				return false;
			}
			
		}
	}

	/**
	 * Tests the following part of the SAML2Int Profile: 
	 * 		Its [refers to the NameIDPolicy element] Format attribute, if present, SHOULD be set to one of the following values: 
	 * 		urn:oasis:names:tc:SAML:2.0:nameid-format:persistent
	 * 		urn:oasis:names:tc:SAML:2.0:nameid-format:transient
	 * @author RiaasM
	 *
	 */
	public class RequestNameIDPolicyFormat implements RequestTestCase{
		private String resultMessage; 
	
		@Override
		public String getDescription() {
			return "Test if the Service Provider's Authentication Request's NameIDPolicy elements have a Format attribute that is either "+NameID.TRANSIENT+" nor "+NameID.PERSISTENT+", if present";
		}

		@Override
		public String getResultMessage() {
			return resultMessage;
		}
	
		@Override
		public boolean isMandatory() {
			return false;
		}

		@Override
		public boolean checkRequest(String request, String binding) {
			NodeList nameIDPolicies = SAMLUtil.fromXML(request).getElementsByTagNameNS(SAMLConstants.SAML20P_NS, NameIDPolicy.DEFAULT_ELEMENT_LOCAL_NAME);
			// check if the request has any NameIDPolicy elements
			if (nameIDPolicies.getLength() == 0){
				resultMessage = "The Service Provider's Authentication Request does not contain a NameIDPolicy";
				return false;
			}
			// check if all NameIDPolicy elements either have a transient or persistent format attribute, or no format attribute at all
			for (int i = 0; i < nameIDPolicies.getLength(); i++){
				Node format = nameIDPolicies.item(i).getAttributes().getNamedItem(NameID.FORMAT_ATTRIB_NAME);
				if (format != null){
					if (!format.getNodeValue().equalsIgnoreCase(NameID.TRANSIENT) && !format.getNodeValue().equalsIgnoreCase(NameID.PERSISTENT)){
						resultMessage = "The Service Provider's Authentication Request contains a NameIDPolicy with a Format attribute that is neither "+NameID.TRANSIENT+" nor "+NameID.PERSISTENT;
						return false;
					}
				}
			}	
			resultMessage = "The Service Provider's Authentication Request's NameIDPolicy elements have a valid Format attribute value";
			return true;
		}
	}

	/**
	 * Tests the following part of the SAML2Int Profile: 
	 * 		The <saml2p:AuthnRequest> message MAY contain a <saml2p:RequestedAuthnContext> element ... The Comparison attribute 
	 * 		SHOULD be omitted or be set to "exact". 
	 * @author RiaasM
	 *
	 */
	public class RequestRequestedAuthnContext implements RequestTestCase{
		private String resultMessage;
		
		@Override
		public String getDescription() {
			return "Test if the Service Provider's Authentication Request contains a RequestedAuthnContext with a Comparison attribute that is set to exact or omitted";
		}
	
		@Override
		public String getResultMessage() {
			return resultMessage;
		}
	
		@Override
		public boolean isMandatory() {
			return false;
		}

		@Override
		public boolean checkRequest(String request, String binding) {
			NodeList requestedAuthnContexts = SAMLUtil.fromXML(request).getElementsByTagNameNS(SAMLConstants.SAML20P_NS, RequestedAuthnContext.DEFAULT_ELEMENT_LOCAL_NAME);
			if (requestedAuthnContexts.getLength() == 0){
				resultMessage = "There are no RequestedAuthnContext elements in the request so this test case does not apply";
				return true;
			}
			// check if all RequestedAuthnContext elements have an exact Comparison attribute, or no Comparison attribute at all
			for (int i = 0; i < requestedAuthnContexts.getLength(); i++){
				Node comparison = requestedAuthnContexts.item(i).getAttributes().getNamedItem(RequestedAuthnContext.COMPARISON_ATTRIB_NAME);
				if (comparison != null){
					if (!comparison.getNodeValue().equals(AuthnContextComparisonTypeEnumeration.EXACT)){
						resultMessage = "The Service Provider's Authentication Request contains a RequestedAuthnContext with a Comparison attribute that is not set to exact";
						return false;
					}
				}
			}
			resultMessage = "The Service Provider's Authentication Request contains a RequestedAuthnContext with a Comparison attribute that is set to exact or omitted";
			return true;
		}
	}
}
