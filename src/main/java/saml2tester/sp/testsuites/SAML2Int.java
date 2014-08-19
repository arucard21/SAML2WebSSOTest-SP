package saml2tester.sp.testsuites;

import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

import org.opensaml.Configuration;
import org.opensaml.DefaultBootstrap;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.NameID;
import org.opensaml.saml2.core.Response;
import org.opensaml.saml2.core.SubjectConfirmation;
import org.opensaml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml2.metadata.IDPSSODescriptor;
import org.opensaml.saml2.metadata.SingleSignOnService;
import org.opensaml.xml.ConfigurationException;
import org.opensaml.xml.XMLObjectBuilderFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Document;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import saml2tester.common.SAMLUtil;
import saml2tester.common.TestStatus;
import saml2tester.common.standardNames.Attribute;
import saml2tester.common.standardNames.MD;
import saml2tester.common.standardNames.SAMLValues;
import saml2tester.sp.LoginAttempt;
import saml2tester.sp.SPTestRunner;


public class SAML2Int extends TestSuite {
	/**
	 * Logger for this class
	 */
	private final Logger logger = LoggerFactory.getLogger(SPTestRunner.class);
	
	@Override
	public String getMockIdPProtocol() {
		return "http";
	}

	@Override
	public String getMockIdPHostname() {
		return "localhost";
	}

	@Override
	public int getMockIdPPort() {
		return 8080;
	}

	@Override
	public String getMockIdPSsoPath() {
		return "/sso";
	}

	@Override
	public String getmockIdPEntityID() {
		return "http://localhost:8080/sso";
	}

	@Override
	public String getIdPMetadata() {
		try {
			DefaultBootstrap.bootstrap();
		} catch (ConfigurationException e) {
			logger.error("Could not bootstrap OpenSAML", e);
		}
		XMLObjectBuilderFactory xmlbuilderfac = Configuration.getBuilderFactory();		
		EntityDescriptor ed = (EntityDescriptor) xmlbuilderfac.getBuilder(EntityDescriptor.DEFAULT_ELEMENT_NAME).buildObject(EntityDescriptor.DEFAULT_ELEMENT_NAME);
		IDPSSODescriptor idpssod = (IDPSSODescriptor) xmlbuilderfac.getBuilder(IDPSSODescriptor.DEFAULT_ELEMENT_NAME).buildObject(IDPSSODescriptor.DEFAULT_ELEMENT_NAME);
		SingleSignOnService ssos = (SingleSignOnService) xmlbuilderfac.getBuilder(SingleSignOnService.DEFAULT_ELEMENT_NAME).buildObject(SingleSignOnService.DEFAULT_ELEMENT_NAME);
		
		ssos.setBinding(SAMLValues.BINDING_HTTP_REDIRECT);
		ssos.setLocation(getMockIdPURL());
		
		idpssod.addSupportedProtocol(SAMLValues.SAML20_PROTOCOL);
		idpssod.getSingleSignOnServices().add(ssos);
		
		ed.setEntityID(getmockIdPEntityID());
		ed.getRoleDescriptors().add(idpssod);
		
		// return the metadata as a string
		return SAMLUtil.toXML(ed);
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
		private String failedMessage;
		
		@Override
		public String getDescription() {
			return "Test if the Service Provider's metadata is available";
		}

		@Override
		public String getSuccessMessage() {
			return "The Service Provider's metadata is available";
		}

		@Override
		public String getFailedMessage() {
			return failedMessage;
		}

		@Override
		public TestStatus checkMetadata(Document metadata) {
			if(metadata != null){
				String curNS = metadata.getDocumentElement().getNamespaceURI();
				// check if the provided document is indeed SAML Metadata (or at least uses the SAML Metadata namespace)
				if(curNS != null && curNS.equalsIgnoreCase(MD.NAMESPACE)){
					return TestStatus.OK;
				}
				else{
					failedMessage = "The Service Provider's metadata did not use the SAML Metadata namespace";
					return TestStatus.ERROR;
				}
			}
			else{
				failedMessage = "The Service Provider's metadata was not available";
				return TestStatus.ERROR;
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
		private String failedMessage;

		@Override
		public String getDescription() {
			return "Test if the minimally required elements are available in the metadata";
		}

		@Override
		public String getSuccessMessage() {
			return "All minimally required elements are available in the metadata";
		}

		@Override
		public String getFailedMessage() {
			return failedMessage;
		}

		/**
		 * Check that the metadata contains at least one SPSSODescriptor containing at least one KeyDescriptor and 
		 * at least one AssertionConsumerService element.
		 */
		@Override
		public TestStatus checkMetadata(Document metadata) {
			if (metadata != null){
				NodeList spssodList = metadata.getElementsByTagNameNS(MD.NAMESPACE, "SPSSODescriptor");
				
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
							if (curNode.getLocalName().equalsIgnoreCase(MD.KEYDESCRIPTOR)){
								kdFound = true;
							}
							if (curNode.getLocalName().equalsIgnoreCase(MD.ASSERTIONCONSUMERSERVICE)){
								acsFound = true;
							}
						}
						// check if both elements were found
						if (kdFound && acsFound){
							return TestStatus.OK;
						}
					}
					failedMessage = "None of the SPSSODescriptor elements in the Service Provider's metadata contained both the KeyDescriptor and the AssertionConsumerService element";
					return TestStatus.ERROR;
				}
				else{
					failedMessage = "The Service Provider's metadata did not contain an SPSSODescriptor";
					return TestStatus.ERROR;
				}
			}
			else {
				failedMessage = "The test case could not be performed because there was no metadata available";
				return TestStatus.CRITICAL;
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
		private String failedMessage; 

		@Override
		public String getDescription() {
			return "Test if the Service Provider can send its Authentication Requests using the HTTP-Redirect binding";
		}

		@Override
		public String getSuccessMessage() {
			return "The Service Provider sent its Authentication Request using the HTTP-Redirect binding";
		}

		@Override
		public String getFailedMessage() {
			return failedMessage;
		}

		@Override
		public TestStatus checkRequest(String request, String binding) {
			if (binding.equalsIgnoreCase(SAMLValues.BINDING_HTTP_REDIRECT)){
				return TestStatus.OK;
			}
			else {
				failedMessage = "The Service Provider did not send its Authentication request using the HTTP-Redirect Binding. Instead, it used: "+binding;
				return TestStatus.ERROR;
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
		private String failedMessage; 

		@Override
		public String getDescription() {
			return "Test if the Service Provider's Authentication Request contains an AssertionConsumerServiceURL attribute";
		}

		@Override
		public String getSuccessMessage() {
			return "The Service Provider's Authentication Request contains an AssertionConsumerServiceURL attribute";
		}

		@Override
		public String getFailedMessage() {
			return failedMessage;
		}

		@Override
		public TestStatus checkRequest(String request, String binding) {
			Node acsURL = SAMLUtil.fromXML(request).getDocumentElement().getAttributes().getNamedItem(Attribute.ASSERTIONCONSUMERSERVICEURL);
			if (acsURL != null){
				return TestStatus.OK;
			}
			else{
				failedMessage = "The Service Provider's Authentication Request did not contain an AssertionConsumerServiceURL attribute";
				return TestStatus.ERROR;
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
		private String failedMessage;
		private String successMessage;

		@Override
		public String getDescription() {
			return "The Service Provider must allow logging in with either the persistent or transient name identifier format";
		}

		@Override
		public String getSuccessMessage() {
			return successMessage;
		}

		@Override
		public String getFailedMessage() {
			return failedMessage;
		}

		@Override
		public List<LoginAttempt> getLoginAttempts() {
			ArrayList<LoginAttempt> attempts = new ArrayList<LoginAttempt>();
		
			// create the classes that will contain the login attempts and SAML Responses
			class LoginAttemptTransient implements LoginAttempt{

				@Override
				public boolean isSPInitiated() {
					return true;
				}
				
				@Override
				public String getResponse(String request) {
					// retrieve the request ID from the request
					String requestID = SAMLUtil.getSamlMessageID(request);
					
					// create the minimally required Response
					Response responseTransient = createMinimalWebSSOResponse();
					// add attributes and sign the assertions in the response
					List<Assertion> assertions = responseTransient.getAssertions();
					for (Assertion assertion : assertions){
						// create nameid with transient format
						NameID nameid = (NameID) Configuration.getBuilderFactory().getBuilder(NameID.DEFAULT_ELEMENT_NAME).buildObject(NameID.DEFAULT_ELEMENT_NAME);
						nameid.setValue("_"+UUID.randomUUID().toString());
						nameid.setFormat(SAMLValues.NAMEID_FORMAT_TRANSIENT);
						assertion.getSubject().setNameID(nameid);

						// set the InReplyTo attribute on the subjectconfirmationdata of all subjectconfirmations
						List<SubjectConfirmation> subconfs = assertion.getSubject().getSubjectConfirmations();
						for (SubjectConfirmation subconf : subconfs){
							subconf.getSubjectConfirmationData().setInResponseTo(requestID);
						}
						// add the attributes
						addTargetSPAttributes(assertion);
						SAMLUtil.sign(assertion, getIdPPrivateKey(null), getIdPCertificate(null));
					}
					// add the InReplyTo attribute to the Response as well
					responseTransient.setInResponseTo(requestID);

					return SAMLUtil.toXML(responseTransient);
				}
			}
			
			class LoginAttemptPersistent implements LoginAttempt{

				@Override
				public boolean isSPInitiated() {
					return true;
				}
				
				@Override
				public String getResponse(String request) {
					// retrieve the request ID from the request
					String requestID = SAMLUtil.getSamlMessageID(request);
					
					// create the minimally required Response
					Response responseTransient = createMinimalWebSSOResponse();
					// add attributes and sign the assertions in the response
					List<Assertion> assertions = responseTransient.getAssertions();
					for (Assertion assertion : assertions){
						// create nameid with persistent format
						NameID nameid = (NameID) Configuration.getBuilderFactory().getBuilder(NameID.DEFAULT_ELEMENT_NAME).buildObject(NameID.DEFAULT_ELEMENT_NAME);
						nameid.setValue("_"+UUID.randomUUID().toString());
						nameid.setFormat(SAMLValues.NAMEID_FORMAT_PERSISTENT);
						assertion.getSubject().setNameID(nameid);

						// set the InReplyTo attribute on the subjectconfirmationdata of all subjectconfirmations
						List<SubjectConfirmation> subconfs = assertion.getSubject().getSubjectConfirmations();
						for (SubjectConfirmation subconf : subconfs){
							subconf.getSubjectConfirmationData().setInResponseTo(requestID);
						}
						// add the attributes
						addTargetSPAttributes(assertion);
						SAMLUtil.sign(assertion, getIdPPrivateKey(null), getIdPCertificate(null));
					}
					// add the InReplyTo attribute to the Response as well
					responseTransient.setInResponseTo(requestID);

					return SAMLUtil.toXML(responseTransient);
				}
			}
			attempts.add(new LoginAttemptTransient());
			attempts.add(new LoginAttemptPersistent());
			return attempts;
		}

		@Override
		public TestStatus checkLoginResults(List<Boolean> loginResults) {
			// the results should come back in the same order as they were provided, so we can check which login attempts succeeded
			if (loginResults.get(0).booleanValue()){	
				if (loginResults.get(1).booleanValue()){
					successMessage = "The Service Provider could log in with both transient and persistent name identifier format";
					return TestStatus.OK;
				}
				else{
					successMessage = "The Service Provider could log in with transient name identifier format";
					return TestStatus.OK;
				}
			}
			else{
				if (loginResults.get(1).booleanValue()){
					successMessage = "The Service Provider could log in with persistent name identifier format";
					return TestStatus.OK;
				}
				else{
					failedMessage = "The Service Provider could not log in with either transient or persistent name identifier format";
					return TestStatus.ERROR;
				}
			}
		}
	}
}
