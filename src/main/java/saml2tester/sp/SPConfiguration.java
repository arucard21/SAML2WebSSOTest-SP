package saml2tester.sp;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;

import org.w3c.dom.Document;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import saml2tester.common.SAMLAttribute;
import saml2tester.common.standardNames.Attribute;
import saml2tester.common.standardNames.MD;

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
	private HashMap<String, String> loginCookies = new HashMap<String, String>();
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
	 * Add a single cookie to the list
	 * 
	 * @param cookieName is the name of the cookie
	 * @param cookieValue is the value of the cookie
	 */
	public void addLoginCookie(String cookieName, String cookieValue) {
		this.loginCookies.put(cookieName, cookieValue);
	}
	
	/**
	 * Add a single attribute to the list
	 * 
	 * @param attributeName is the name of the attribute
	 * @param nameformat is the nameformat used in the attribute
	 * @param attributeValue is the value of the attribute
	 */
	public void addAttribute(String attributeName, String nameformat, String attributeValue) {
		SAMLAttribute attribute = new SAMLAttribute(attributeName, nameformat, attributeValue);
		this.attributes.add(attribute);
	}
	
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
	public HashMap<String, String> getLoginCookies() {
		return loginCookies;
	}
	public void setLoginCookies(HashMap<String, String> loginCookies) {
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
	
	/**
	 * Retrieve all nodes with the requested tag name from the metadata
	 * 
	 * @param tagName is the name of the requested nodes
	 * @return a list of nodes with the requested tag name
	 */
	public List<Node> getMDNodes(String tagName) {
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
		ArrayList<String> resultAttributes = new ArrayList<String>();
		NodeList allACS = metadata.getElementsByTagNameNS(MD.NAMESPACE, tagName);
		for (int i = 0; i < allACS.getLength(); i++){
			Node acs = allACS.item(i);
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
		List<String> allIDs = getMDAttributes(tagName, attrName);
		if(allIDs.size() == 1){
			return allIDs.get(0);
		}
		else {
			return null;
		}
	}
	
	/**
	 * Retrieve the location of the AssertionConsumerService for a specific
	 * binding for the SP that is being tested from the metadata
	 * 
	 * @param binding specifies for which binding the location should be retrieved
	 * @return the location for the requested binding or null if it is not found
	 */
	public String getMDACSLocation(String binding) {
		ArrayList<Node> acsNodes = (ArrayList<Node>) getMDNodes(MD.ASSERTIONCONSUMERSERVICE);
		// check all ACS nodes for the requested binding
		for (Node acs : acsNodes) {
			if (acs.getAttributes().getNamedItem(Attribute.BINDING)
					.getNodeValue().equalsIgnoreCase(binding))
				// return the location for the requested binding
				return acs.getAttributes().getNamedItem(Attribute.LOCATION)
						.getNodeValue();
		}
		// the requested binding could not be found
		return null;
	}
}
