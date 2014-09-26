package saml2tester.sp;

import java.io.IOException;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Properties;
import java.util.Set;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Document;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import saml2tester.common.FormInteraction;
import saml2tester.common.LinkInteraction;
import saml2tester.common.SAMLAttribute;
import saml2tester.common.SAMLUtil;
import saml2tester.common.standardNames.Attribute;
import saml2tester.common.standardNames.MD;

public class SPConfiguration {
	private final Logger logger = LoggerFactory.getLogger(SPConfiguration.class);
	/**
	 * Define the keys used in the SP configuration properties file
	 */
	private static final String configStartPage = "targetSP.startPage";
	private static final String configMetadata = "targetSP.metadata";
	private static final String configLoginStatuscode = "targetSP.login.httpstatuscode";
	private static final String configLoginURL = "targetSP.login.url";
	private static final String configLoginCookiePrefix = "targetSP.login.cookie";
	private static final String configLoginContent = "targetSP.login.content";
	private static final String configIdPAttributePrefix = "targetSP.idp.attribute";
	private static final String configInteractionPrefix = "targetSP.interaction";
	private static final String configInteractionForm = "form";
	private static final String configInteractionLink = "link";
	private static final String configInteractionLinkName = "name";
	private static final String configInteractionLinkText = "text";
	private static final String configInteractionLinkHref = "href";
	private static final String preloginPrefix = "prelogin";
	private static final String postResponsePrefix = "postresponse";
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
	 * Contains the interactions to be used before logging in
	 */
	private ArrayList<Object> preloginInteractions = new ArrayList<Object>();
	/**
	 * Contains the interactions to be used after receiving the response
	 */
	private ArrayList<Object> postresponseInteractions = new ArrayList<Object>();

	/**
	 * Load the configuration of the target SP, provided in JSON format
	 * 
	 * @param targetSPConfig is the path to the configuration file of the target SP in JSON format
	 */
	public SPConfiguration(String targetSPConfig){
		if(targetSPConfig != null && !targetSPConfig.isEmpty()){
			try {
				Properties propConfig = new Properties();
				propConfig.load(Files.newBufferedReader(Paths.get(targetSPConfig),Charset.defaultCharset()));
			
				Set<String> configKeys = propConfig.stringPropertyNames();
	
				for (String key : configKeys) {
					// add the properties to the config object appropriately
					if (key.equalsIgnoreCase(configStartPage)){
						this.setStartPage(propConfig.getProperty(configStartPage));
					}
					else if (key.equalsIgnoreCase(configMetadata)) {
						String mdVal = propConfig.getProperty(configMetadata);
						this.setMetadata(SAMLUtil.fromXML(mdVal));
					} 
					else if (key.equalsIgnoreCase(configLoginStatuscode)){
						String scProp = propConfig.getProperty(configLoginStatuscode);
						if(scProp != null && !scProp.isEmpty()){
							this.setLoginStatuscode(Integer.valueOf(scProp));
						}
					}
					else if (key.equalsIgnoreCase(configLoginContent)){
						this.setLoginContent(propConfig.getProperty(configLoginContent));
					}
					else if (key.equalsIgnoreCase(configLoginURL)){
						this.setLoginURL(propConfig.getProperty(configLoginURL));
					}
					else if (key.startsWith(configLoginCookiePrefix)) {
						String cookieProp = propConfig.getProperty(key);
						// make sure the properties file actually has a value for the cookie
						if (cookieProp != null && !cookieProp.isEmpty()){
							String[] cookie = cookieProp.split(",");
							
							if(cookie.length > 0 && cookie[0] != null){
								String name = cookie[0].trim();
								String value;
								if (cookie.length > 1 && cookie[1] != null){
									value = cookie[1].trim();
								}
								else{
									value = null;
								}
								this.addLoginCookie(name, value);
							}
						}
					}
					else if (key.startsWith(configIdPAttributePrefix)) {
						String[] attribute = propConfig.getProperty(key).split(",");
						String name = attribute[0].trim();
						String nameformat = attribute[1].trim();
						String value = attribute[2].trim();
						this.addAttribute(name, nameformat, value);
					}
					else if (key.startsWith(configInteractionPrefix)) {
						String interactionProp = propConfig.getProperty(key);
						// split the hierarchy of the property key into separate strings
						Object interaction;
						if(key.contains(configInteractionForm)){
							String[] formNames = interactionProp.split(",");
							FormInteraction formInter = new FormInteraction(formNames[0].trim(), formNames[1].trim());
							// add all input fields
							for(int i = 2; i < formNames.length; i++){
								//get the name of the input field
								String name = formNames[i];
								// get the corresponding value of the input field
								i++;
								String value = "";
								// make sure you can actually access the value of the input field
								if(i<formNames.length) value = formNames[i];
								// add the input to the FormInteraction object
								formInter.addInput(name, value);
							}
							// store the interaction in the object so it can be stored in the configuration
							interaction = formInter;
						}
						else if(key.contains(configInteractionLink)){
							String[] linkValues = interactionProp.split(",");
							// check how to look up the link and create the link interaction accordingly
							if(linkValues[0].contains(configInteractionLinkName))
								interaction = (LinkInteraction) new LinkInteraction(LinkInteraction.LookupType.NAME, linkValues[1].trim());
							else if(linkValues[0].contains(configInteractionLinkText))
								interaction = (LinkInteraction) new LinkInteraction(LinkInteraction.LookupType.TEXT, linkValues[1].trim());
							else if(linkValues[0].contains(configInteractionLinkHref))
								interaction = (LinkInteraction) new LinkInteraction(LinkInteraction.LookupType.HREF, linkValues[1].trim());
							else{
								logger.error("Unknown interaction link lookup type in target SP configuration file");
								interaction = null;
							}
						}
						else{
							logger.error("Unknown interaction type in target SP configuration file");
							interaction = null;
						}
						
						if(key.contains(preloginPrefix)){
							this.addPreloginInteractions(interaction);
						}
						else if(key.contains(postResponsePrefix)){
							this.addPreloginInteractions(interaction);
						}
						else{
							logger.error("Unknown interaction point in target SP configuration file");
						}
					}
					else {
						logger.error("Unknown property in target SP configuration file");
					}
				}
			} catch (IOException e) {
				logger.error("I/O error occurred while accessing the configuration file", e);
			}
		}		
	}
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
	/**
	 * @return the preloginInteractions
	 */
	public ArrayList<Object> getPreloginInteractions() {
		return preloginInteractions;
	}
	/**
	 * @param preloginInteraction is the interaction object that should be added to the preloginInteractions
	 */
	public void addPreloginInteractions(Object preloginInteraction) {
		this.preloginInteractions.add(preloginInteraction);
	}
	/**
	 * @return the postresponseInteractions
	 */
	public ArrayList<Object> getPostresponseInteractions() {
		return postresponseInteractions;
	}
	/**
	 * @param postresponseInteraction is the interaction object that should be added to the postresponseInteractions
	 */
	public void addPostresponseInteractions(Object postresponseInteraction) {
		this.postresponseInteractions.add(postresponseInteraction);
	}
}
