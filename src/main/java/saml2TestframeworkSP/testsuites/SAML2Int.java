package saml2TestframeworkSP.testsuites;

import org.opensaml.Configuration;
import org.opensaml.DefaultBootstrap;
import org.opensaml.common.SAMLObjectBuilder;
import org.opensaml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml2.metadata.IDPSSODescriptor;
import org.opensaml.saml2.metadata.SingleSignOnService;
import org.opensaml.xml.ConfigurationException;
import org.opensaml.xml.XMLObjectBuilderFactory;
import org.w3c.dom.Document;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import saml2TestframeworkCommon.SAMLUtil;
import saml2TestframeworkCommon.TestStatus;
import saml2TestframeworkCommon.standardNames.Attribute;
import saml2TestframeworkCommon.standardNames.MD;
import saml2TestframeworkCommon.standardNames.SAMLValues;


public class SAML2Int extends TestSuite {

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
			e.printStackTrace();
		}
		XMLObjectBuilderFactory xmlbuilderfac = Configuration.getBuilderFactory();
		
		@SuppressWarnings("unchecked")
		SAMLObjectBuilder<EntityDescriptor> edBuilder = (SAMLObjectBuilder<EntityDescriptor>) xmlbuilderfac.getBuilder(EntityDescriptor.DEFAULT_ELEMENT_NAME);
		@SuppressWarnings("unchecked")
		SAMLObjectBuilder<IDPSSODescriptor> idpssodBuilder = (SAMLObjectBuilder<IDPSSODescriptor>) xmlbuilderfac.getBuilder(IDPSSODescriptor.DEFAULT_ELEMENT_NAME);
		@SuppressWarnings("unchecked")
		SAMLObjectBuilder<SingleSignOnService> ssosBuilder = (SAMLObjectBuilder<SingleSignOnService>) xmlbuilderfac.getBuilder(SingleSignOnService.DEFAULT_ELEMENT_NAME);
		
		EntityDescriptor ed = edBuilder.buildObject();
		IDPSSODescriptor idpssod = idpssodBuilder.buildObject();
		SingleSignOnService ssos = ssosBuilder.buildObject();
		
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
					// DEBUG: show actual metadata
					//System.out.println(toXML(metadata));
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
 * 
 * TODO implement tests for specification sections below
 * 
 * 
 * 
 * Tests the following part of the following part of the SAML2Int Profile: 
 * 		Service Providers, if they rely at all on particular name identifier formats, MUST support one of the following:
 * 			urn:oasis:names:tc:SAML:2.0:nameid-format:persistent
 * 			urn:oasis:names:tc:SAML:2.0:nameid-format:transient
 * 
 **/
}
