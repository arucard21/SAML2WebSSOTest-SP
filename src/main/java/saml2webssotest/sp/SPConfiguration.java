package saml2webssotest.sp;

import java.util.ArrayList;
import java.util.List;

import org.w3c.dom.Document;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import saml2webssotest.common.Interaction;
import saml2webssotest.common.StringPair;
import saml2webssotest.common.SAMLAttribute;
import saml2webssotest.common.standardNames.MD;

public class SPConfiguration {
	/**
	 * Contains the start page of the target SP. It should be the URL where SSO for the mock IdP is started
	 */
	private String startPage;
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
		NodeList allNodes = metadata.getElementsByTagNameNS(MD.NAMESPACE, tagName);
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
		NodeList allNodes = metadata.getElementsByTagNameNS(MD.NAMESPACE, tagName);
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
	 * Retrieve the location of the AssertionConsumerService for a specific
	 * binding for the SP that is being tested from the metadata.
	 * 
	 * @param binding specifies for which binding the location should be retrieved
	 * @return the location for the requested binding or null if no matching ACS could be found
	 */
	public String getMDACSLocation(String binding) {
		ArrayList<Node> acsNodes = (ArrayList<Node>) getMDNodes(MD.ASSERTIONCONSUMERSERVICE);
		// look for ACS with specified binding
		for (Node acs : acsNodes) {
			if (acs.getAttributes().getNamedItem(MD.BINDING)
					.getNodeValue().equalsIgnoreCase(binding))
				// return the location for the requested binding
				return acs.getAttributes().getNamedItem(MD.LOCATION)
						.getNodeValue();
		}
		// the requested binding could not be found
		return null;
	}
	
	/**
	 * Retrieve the location of the AssertionConsumerService with a specific index
	 * for the SP that is being tested from the metadata.
	 * 
	 * @param index specifies the index of the ACS for which the location should be retrieved
	 * @return the location of the ACS with the requested index or null if no matching ACS could be found
	 */
	public String getMDACSLocation(int index) {
		ArrayList<Node> acsNodes = (ArrayList<Node>) getMDNodes(MD.ASSERTIONCONSUMERSERVICE);
		// look for ACS with specified index
		for (Node acs : acsNodes) {
			int nodeIndex = Integer.parseInt(acs.getAttributes().getNamedItem(MD.INDEX).getNodeValue());
			if (nodeIndex == index)
				// return the location for the ACS with the requested index
				return acs.getAttributes().getNamedItem(MD.LOCATION).getNodeValue();
		}
		// the requested index could not be found
		return null;
	}
	
	/**
	 * Retrieve the binding of the AssertionConsumerService with a specific index
	 * for the SP that is being tested from the metadata.
	 * 
	 * @param index specifies the index of the ACS for which the binding should be retrieved
	 * @return the binding of the ACS with the requested index or null if no matching ACS could be found
	 */
	public String getMDACSBinding(int index) {
		ArrayList<Node> acsNodes = (ArrayList<Node>) getMDNodes(MD.ASSERTIONCONSUMERSERVICE);
		// look for ACS with specified index
		for (Node acs : acsNodes) {
			int nodeIndex = Integer.parseInt(acs.getAttributes().getNamedItem(MD.INDEX).getNodeValue());
			if (nodeIndex == index)
				// return the location for the ACS with the requested index
				return acs.getAttributes().getNamedItem(MD.BINDING).getNodeValue();
		}
		// the requested index could not be found
		return null;
	}

	/**
	 * Retrieve the location of the default AssertionConsumerService 
	 * (as defined by [SAMLMeta] 2.2.3). 
	 * 
	 * @return the location of the default AssertionConsumerService
	 */
	public String getDefaultMDACSLocation(){
		ArrayList<Node> acsNodes = (ArrayList<Node>) getMDNodes(MD.ASSERTIONCONSUMERSERVICE);
		
		String firstACSLocation = null;
		// check if one of the nodes is set as default and return its location
		for (Node acs : acsNodes) {
			if (acs.getAttributes().getNamedItem(MD.ISDEFAULT) != null) {
				if(acs.getAttributes().getNamedItem(MD.ISDEFAULT).getNodeValue().equalsIgnoreCase("true")){
					return acs.getAttributes().getNamedItem(MD.LOCATION).getNodeValue();
				}
			}
			else{
				if (firstACSLocation == null){
					// save the first ACS found without isDefault attribute so it can be returned later
					firstACSLocation = acs.getAttributes().getNamedItem(MD.LOCATION).getNodeValue();
				}
			}
		}
		// no ACS found with isDefault set to true, so return the first ACS without isDefault attribute
		return firstACSLocation;
	}
	
	/**
	 * Retrieve the binding of the default AssertionConsumerService 
	 * (as defined by [SAMLMeta] 2.2.3). 
	 * 
	 * @return the binding of the default AssertionConsumerService
	 */
	public String getDefaultMDACSBinding(){
		ArrayList<Node> acsNodes = (ArrayList<Node>) getMDNodes(MD.ASSERTIONCONSUMERSERVICE);
		
		String firstACSLocation = null;
		// check if one of the nodes is set as default and return its location
		for (Node acs : acsNodes) {
			if (acs.getAttributes().getNamedItem(MD.ISDEFAULT) != null) {
				if(acs.getAttributes().getNamedItem(MD.ISDEFAULT).getNodeValue().equalsIgnoreCase("true")){
					return acs.getAttributes().getNamedItem(MD.BINDING).getNodeValue();
				}
			}
			else{
				if (firstACSLocation == null){
					// save the first ACS found without isDefault attribute so it can be returned later
					firstACSLocation = acs.getAttributes().getNamedItem(MD.BINDING).getNodeValue();
				}
			}
		}
		// no ACS found with isDefault set to true, so return the first ACS without isDefault attribute
		return firstACSLocation;
	}
}
