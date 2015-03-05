package saml2webssotest.sp;

import java.util.ArrayList;
import java.util.List;

import org.opensaml.common.xml.SAMLConstants;
import org.opensaml.saml2.core.AuthnRequest;
import org.opensaml.saml2.metadata.AssertionConsumerService;
import org.opensaml.saml2.metadata.IndexedEndpoint;
import org.w3c.dom.Document;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import saml2webssotest.common.Interaction;
import saml2webssotest.common.StringPair;
import saml2webssotest.common.SAMLAttribute;

public class SPConfiguration {
	/**
	 * Contains the start page of the target SP. It should be the URL where SSO for the mock IdP is started
	 */
	private String startPage;
	/**
	 * Contains the clock skew (in milliseconds) that is allowed on the target SP
	 */
	private int clockSkew;
	/**
	 * Contains the metadata from the target SP. This is used for metadata test cases and to register the target SP with the mock IdP
	 */
	private Document metadata;
	/**
	 * Contains the HTTP Status code that should be given when you are correctly logged in. 
	 * If it is 0 (default value), it will not be checked.
	 */
	private int loginStatuscode;
	/**
	 * Contains the URL that should be reached when you are correctly logged in. 
	 */
	private String loginURL;
	/**
	 * Contains the cookies that should be present when you are correctly logged in. 
	 */
	private ArrayList<StringPair> loginCookies = new ArrayList<StringPair>();
	/**
	 * Contains a regex that should match the content of the page that is shown when you are correctly logged in. 
	 * If it is null (default value), the content of the page will not be checked.
	 */
	private String loginContent;
	/**
	 * Contains the attributes that the mock IdP should send along with its SAML Response.
	 * The attributes should be valid for the target SP.
	 */
	private ArrayList<SAMLAttribute> attributes = new ArrayList<SAMLAttribute>();
	/**
	 * Contains the interactions to be used before logging in
	 */
	private ArrayList<Interaction> preLoginInteractions = new ArrayList<Interaction>();
	/**
	 * Contains the interactions to be used after receiving the response
	 */
	private ArrayList<Interaction> postResponseInteractions = new ArrayList<Interaction>();

	/*
	 * Simple getters and setters
	 */
	
	public String getStartPage() {
		return startPage;
	}
	public void setStartPage(String startPage) {
		this.startPage = startPage;
	}
	public int getClockSkew() {
		return clockSkew;
	}
	public void setClockSkew(int clockSkew) {
		this.clockSkew = clockSkew;
	}
	public Document getMetadata() {
		return metadata;
	}
	public void setMetadata(Document md) {
		metadata = md;
	}
	public int getLoginStatuscode() {
		return loginStatuscode;
	}
	public void setLoginStatuscode(int loginStatuscode) {
		this.loginStatuscode = loginStatuscode;
	}
	public String getLoginURL() {
		return loginURL;
	}
	public void setLoginURL(String loginURL) {
		this.loginURL = loginURL;
	}
	public ArrayList<StringPair> getLoginCookies() {
		return loginCookies;
	}
	public void setLoginCookies(ArrayList<StringPair> loginCookies) {
		this.loginCookies = loginCookies;
	}
	public String getLoginContent() {
		return loginContent;
	}
	public void setLoginContent(String loginContent) {
		this.loginContent = loginContent;
	}
	public ArrayList<SAMLAttribute> getAttributes() {
		return attributes;
	}
	public void setAttributes(ArrayList<SAMLAttribute> attributes) {
		this.attributes = attributes;
	}
	public ArrayList<Interaction> getPreLoginInteractions() {
		return preLoginInteractions;
	}
	public void setPreLoginInteractions(ArrayList<Interaction> preLoginInteractions) {
		this.preLoginInteractions = preLoginInteractions;
	}
	public ArrayList<Interaction> getPostResponseInteractions() {
		return postResponseInteractions;
	}
	public void setPostResponseInteractions(ArrayList<Interaction> postResponseInteractions) {
		this.postResponseInteractions = postResponseInteractions;
	}

	/*
	 * Utility methods
	 */

	/**
	 * Retrieve all nodes with the requested tag name from the metadata
	 * 
	 * @param tagName is the name of the requested nodes
	 * @return a list of nodes with the requested tag name
	 */
	public List<Node> getMDNodes(String tagName) {
		// make sure the metadata is available
		if (metadata == null)
			return null;
		
		ArrayList<Node> nodes = new ArrayList<Node>();
		NodeList allNodes = metadata.getElementsByTagNameNS(SAMLConstants.SAML20MD_NS, tagName);
		//convert NodeList to List of Node objects
		for (int i = 0; i < allNodes.getLength(); i++){
			nodes.add(allNodes.item(i));
		}
		return nodes;
	}
	
	/**
	 * Retrieve the values of the requested attributes for the nodes with the requested tag name
	 * from the metadata
	 *  
	 * @param tagName is the name of the requested nodes
	 * @param attrName is the name of the attribute that should be present on the requested nodes
	 * @return a list of the values of the requested attributes for the requested nodes
	 */
	public List<String> getMDAttributes(String tagName, String attrName) {
		//make sure the metadata is available
		if (metadata == null)
			return null;
		
		ArrayList<String> resultAttributes = new ArrayList<String>();
		NodeList allNodes = metadata.getElementsByTagNameNS(SAMLConstants.SAML20MD_NS, tagName);
		for (int i = 0; i < allNodes.getLength(); i++){
			Node acs = allNodes.item(i);
			resultAttributes.add(acs.getAttributes().getNamedItem(attrName).getNodeValue());
		}
		return resultAttributes;
	}
	
	/**
	 * Retrieve the value of a single attribute for the node with the requested tag name from 
	 * the metadata. 
	 * 
	 * If more than one attribute is found, this will return null. 
	 * Use {@link #getMDAttributes(String, String)} instead.
	 *  
	 * @param tagName is the name of the requested nodes
	 * @param attrName is the name of the attribute that should be present on the requested nodes
	 * @return the value of the requested attribute, or null if none or multiple attributes were found
	 */
	public String getMDAttribute(String tagName, String attrName) {
		List<String> allAttrs = getMDAttributes(tagName, attrName);
		if(allAttrs.size() == 1){
			return allAttrs.get(0);
		}
		else {
			return null;
		}
	}
	
	/**
	 * Retrieve the applicable AssertionConsumerService node from the SP metadata, taking into account the given AuthnRequest.
	 * 
	 * It checks if the request contains an ACS location or index and returns the corresponding ACS information (as a StringPair),
	 * otherwise it just returns the default ACS node found in the SP metadata. 
	 * 
	 * @param authnRequest is the AuthnRequest that was received (or null if IdP-initiated)
	 * @return the applicable ACS' location and binding as name and value of a StringPair or null if no matching ACS could be found
	 */
	public StringPair getApplicableACS(Document authnRequest) {
		Node authnRequestNode = null;
		Node acsURL = null;
		Node acsIndex = null;
		Node returnACS = null;
		// only retrieve the information from the authnrequest if it is actually provided
		if (authnRequest != null){
			// retrieve the ACS URL that was provided in the AuthnRequest
			authnRequestNode = authnRequest.getElementsByTagNameNS(SAMLConstants.SAML20P_NS, AuthnRequest.DEFAULT_ELEMENT_LOCAL_NAME).item(0);
			acsURL = authnRequestNode .getAttributes().getNamedItem(AuthnRequest.ASSERTION_CONSUMER_SERVICE_URL_ATTRIB_NAME);
			// retrieve the ACS index that was provided in the AuthnRequest
			acsIndex = authnRequestNode.getAttributes().getNamedItem(AuthnRequest.ASSERTION_CONSUMER_SERVICE_INDEX_ATTRIB_NAME);
		}
		
		// find the applicable ACS
		if (acsURL == null){
			ArrayList<Node> acsNodes = (ArrayList<Node>) getMDNodes(AssertionConsumerService.DEFAULT_ELEMENT_LOCAL_NAME);
			
			// no ACS location found in request, check the ACS index
			if ( acsIndex  == null ){
				// no ACS location or index found in request, so just use default
				
				Node firstACS = null;
				// check if one of the nodes is set as default and return its location
				for (Node acs : acsNodes) {
					if (acs.getAttributes().getNamedItem(IndexedEndpoint.IS_DEFAULT_ATTRIB_NAME) != null) {
						if(acs.getAttributes().getNamedItem(IndexedEndpoint.IS_DEFAULT_ATTRIB_NAME).getNodeValue().equalsIgnoreCase("true")){
							returnACS = acs;
							break;
						}
					}
					else{
						if (firstACS == null){
							// save the first ACS found without isDefault attribute so it can be returned 
							// later if no ACS with isDefault=true can be found
							firstACS = acs;
						}
					}
				}
				// no ACS found with isDefault set to true, so return the first ACS without isDefault attribute
				if (returnACS == null){
					returnACS = firstACS;
				}
			}
			else{
				// ACS index found, so set location and binding accordingly
				int acsIndexInt = Integer.parseInt(acsIndex.getNodeValue());
				// look for ACS with specified index
				for (Node acs : acsNodes) {
					int nodeIndex = Integer.parseInt(acs.getAttributes().getNamedItem(IndexedEndpoint.INDEX_ATTRIB_NAME).getNodeValue());
					if (nodeIndex == acsIndexInt){
						// return the location for the ACS with the requested index
						returnACS = acs;
						break;
					}
				}
			}
			// return the ACS information found based on the SP metadata
			if (returnACS == null){
				// the requested acs could not be found
				return null;
			}
			else{
				String location = returnACS.getAttributes().getNamedItem(AssertionConsumerService.LOCATION_ATTRIB_NAME).getNodeValue();
				String binding = returnACS.getAttributes().getNamedItem(AssertionConsumerService.BINDING_ATTRIB_NAME).getNodeValue();
				return new StringPair(location, binding);
			}
		}
		else{
			// check if the index is also available
			if(acsIndex != null){
				// location and index should be mutually-exclusive so the request is invalid
				return null;
			}
			
			// found ACS location in request, must also have a binding then
			Node acsBinding = authnRequestNode.getAttributes().getNamedItem(AuthnRequest.PROTOCOL_BINDING_ATTRIB_NAME);
			// return the ACS information found based on the request 
			return new StringPair(acsURL.getNodeValue(), acsBinding.getNodeValue());
		}
	}
}
