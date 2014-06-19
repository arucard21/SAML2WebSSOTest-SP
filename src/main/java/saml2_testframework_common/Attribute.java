package saml2_testframework_common;
/**
 * The Attribute class contains the values pertaining to a single attribute
 */
public class Attribute {

	private String attributeName;
	private String nameFormat;
	private String attributeValue;
	
	public Attribute(String name, String format, String value){
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