package saml2TestframeworkCommon;
/**
 * The Attribute class contains the values pertaining to a single attribute
 */
public class SAMLAttribute {

	private String attributeName;
	private String nameFormat;
	private String attributeValue;
	
	public SAMLAttribute(String name, String format, String value){
		attributeName = name;
		nameFormat = format;
		attributeValue = value;
	}
	
	public String getAttributeName() {
		return attributeName;
	}

	public String getNameFormat() {
		return nameFormat;
	}

	public String getAttributeValue() {
		return attributeValue;
	}
}