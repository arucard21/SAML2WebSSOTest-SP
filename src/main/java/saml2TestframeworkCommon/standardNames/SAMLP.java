package saml2TestframeworkCommon.standardNames;
/**
 * Class contains the tag names for the samlp namespace
 * 
 * @author RiaasM
 *
 */
public class SAMLP {
	public static final String PREFIX = "samlp";
	public static final String NAMESPACE = "urn:oasis:names:tc:SAML:2.0:protocol";
	public static final String EXTENSIONS = String.format("{%s}Extensions", NAMESPACE);
	public static final String STATUS = String.format("{%s}Status", NAMESPACE);
	public static final String STATUSCODE = String.format("{%s}StatusCode", NAMESPACE);
	public static final String RESPONSE = String.format("{%s}Response", NAMESPACE);
}
