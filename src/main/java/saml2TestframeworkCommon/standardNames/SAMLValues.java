package saml2TestframeworkCommon.standardNames;
/**
 * Class contains common, standard values used in SAML that are not specific to any single namespace
 * 
 * @author RiaasM
 *
 */
public class SAMLValues {
	public static final String SAML20_PROTOCOL = "urn:oasis:names:tc:SAML:2.0:protocol";
	public static final String BINDING_SOAP = "urn:oasis:names:tc:SAML:2.0:bindings:SOAP";
	public static final String BINDING_PAOS = "urn:oasis:names:tc:SAML:2.0:bindings:PAOS";
	public static final String BINDING_HTTP_REDIRECT = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect";
	public static final String BINDING_HTTP_POST = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST";
	public static final String BINDING_HTTP_ARTIFACT = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact";
	public static final String BINDING_URI = "urn:oasis:names:tc:SAML:2.0:bindings:URI";
	public static final String STATUS_SUCCESS = "urn:oasis:names:tc:SAML:2.0:status:Success";
	public static final String STATUS_REQUESTER = "urn:oasis:names:tc:SAML:2.0:status:Requester";
	public static final String STATUS_RESPONDER = "urn:oasis:names:tc:SAML:2.0:status:Responder";
	public static final String STATUS_VERSIONMISMATCH = "urn:oasis:names:tc:SAML:2.0:status:VersionMismatch";
	public static final String DECISION_PERMIT = "Permit";
	public static final String DECISION_DENY = "Deny";
	public static final String DECISION_INDETERMINATE = "Indeterminate";
	public static final String NAMEID_FORMAT_ENTITY = "urn:oasis:names:tc:SAML:2.0:nameid-format:entity";
	public static final String NAMEID_FORMAT_UNSPECIFIED = "urn:oasis:names:tc:SAML:1.0:nameid-format:unspecified";
	public static final String AUTHNCONTEXT_PASSWORD = "urn:oasis:names:tc:SAML:2.0:ac:classes:Password";
	public static final String CONFIRMATION_METHOD_HOLDER = "urn:oasis:names:tc:SAML:2.0:cm:holder-of-key";
	public static final String CONFIRMATION_METHOD_SENDER = "urn:oasis:names:tc:SAML:2.0:cm:sender-vouches";
	public static final String CONFIRMATION_METHOD_BEARER = "urn:oasis:names:tc:SAML:2.0:cm:bearer";
	public static final String URLPARAM_SAMLREQUEST_REDIRECT = "SAMLRequest";
	public static final String URLPARAM_SAMLREQUEST_POST= "SAMLRequest";
	public static final String URLPARAM_SAMLRESPONSE_POST= "SAMLResponse";
	public static final String URLPARAM_SAMLARTIFACT = "SAMLArt";
}
