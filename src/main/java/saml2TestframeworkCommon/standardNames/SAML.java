package saml2TestframeworkCommon.standardNames;
/**
 * Class contains the tag names for the saml namespace
 * 
 * @author RiaasM
 *
 */
public class SAML {
	public static final String PREFIX = "saml";
	public static final String NAMESPACE = "urn:oasis:names:tc:SAML:2.0:assertion";
	public static final String ASSERTION = String.format("{%s}Assertion", NAMESPACE);
	public static final String BASEID = String.format("{%s}BaseID", NAMESPACE);
	public static final String NAMEID = String.format("{%s}NameID", NAMESPACE);
	public static final String ENCRYPTEDID = String.format("{%s}EncryptedID", NAMESPACE);
	public static final String ISSUER = String.format("{%s}Issuer", NAMESPACE);
	public static final String SUBJECT = String.format("{%s}Subject", NAMESPACE);
	public static final String SUBJECTCONFIRMATION = String.format("{%s}SubjectConfirmation", NAMESPACE);
	public static final String SUBJECTCONFIRMATIONDATA = String.format("{%s}SubjectConfirmationData", NAMESPACE);
	public static final String KEYINFOCONFIRMATIONDATA = String.format("{%s}KeyInfoConfirmationData", NAMESPACE);
	public static final String CONDITIONS = String.format("{%s}Conditions", NAMESPACE);
	public static final String CONDITION = String.format("{%s}Condition", NAMESPACE);
	public static final String AUDIENCERESTRICTION = String.format("{%s}AudienceRestriction", NAMESPACE);
	public static final String ONETIMEUSE = String.format("{%s}OneTimeUse", NAMESPACE);
	public static final String PROXYRESTRICTION = String.format("{%s}ProxyRestriction", NAMESPACE);
	public static final String AUDIENCE = String.format("{%s}Audience", NAMESPACE);
	public static final String ADVICE = String.format("{%s}Advice", NAMESPACE);
	public static final String ASSERTIONIDREF = String.format("{%s}AssertionIDRef", NAMESPACE);
	public static final String ASSERTIONURIREF = String.format("{%s}AssertionURIRef", NAMESPACE);
	public static final String ENCRYPTEDASSERTION = String.format("{%s}EncryptedAssertion", NAMESPACE);
	public static final String STATEMENT = String.format("{%s}Statement", NAMESPACE);
	public static final String AUTHNSTATEMENT = String.format("{%s}AuthnStatement", NAMESPACE);
	public static final String SUBJECTLOCALITY = String.format("{%s}SubjectLocality", NAMESPACE);
	public static final String AUTHNCONTEXT = String.format("{%s}AuthnContext", NAMESPACE);
	public static final String AUTHNCONTEXTCLASSREF = String.format("{%s}AuthnContextClassRef", NAMESPACE);
	public static final String AUTHNCONTEXTDECLREF = String.format("{%s}AuthnContextDeclRef", NAMESPACE);
	public static final String AUTHNCONTEXTDECL = String.format("{%s}AuthnContextDecl", NAMESPACE);
	public static final String AUTHENTICATINGAUTHORITY = String.format("{%s}AuthenticatingAuthority", NAMESPACE);
	public static final String AUTHZDECISIONSTATEMENT = String.format("{%s}AuthzDecisionStatement", NAMESPACE);
	public static final String ACTION = String.format("{%s}Action", NAMESPACE);
	public static final String EVIDENCE = String.format("{%s}Evidence", NAMESPACE);
	public static final String ATTRIBUTESTATEMENT = String.format("{%s}AttributeStatement", NAMESPACE);
	public static final String ATTRIBUTE = String.format("{%s}Attribute", NAMESPACE);
	public static final String ENCRYPTEDATTRIBUTE = String.format("{%s}EncryptedAttribute", NAMESPACE);
	public static final String ATTRIBUTEVALUE = String.format("{%s}AttributeValue", NAMESPACE);
}
