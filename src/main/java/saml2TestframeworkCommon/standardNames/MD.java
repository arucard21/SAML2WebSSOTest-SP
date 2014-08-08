package saml2TestframeworkCommon.standardNames;
/**
 * Class contains the tag names for the md namespace
 * 
 * @author RiaasM
 *
 */
public class MD {
	public static final String PREFIX = "md";
	public static final String NAMESPACE = "urn:oasis:names:tc:SAML:2.0:metadata";
	public static final String ENTITIESDESCRIPTOR = String.format("{%s}EntitiesDescriptor", NAMESPACE);
	public static final String ENTITYDESCRIPTOR = String.format("{%s}EntityDescriptor", NAMESPACE);
	public static final String ADDITIONALMETADATALOCATION = String.format("{%s}AdditionalMetadataLocation", NAMESPACE);
	public static final String SPSSODESCRIPTOR = String.format("{%s}SPSSODescriptor", NAMESPACE);
	public static final String IDPSSODESCRIPTOR = String.format("{%s}IDPSSODescriptor", NAMESPACE);
	public static final String KEYDESCRIPTOR = String.format("{%s}KeyDescriptor", NAMESPACE);
	public static final String SINGLESIGNONSERVICE = String.format("{%s}SingleSignOnService", NAMESPACE);
	public static final String ARTIFACTRESOLUTIONSERVICE = String.format("{%s}ArtifactResolutionService", NAMESPACE);
	public static final String ASSERTIONCONSUMERSERVICE = String.format("{%s}AssertionConsumerService", NAMESPACE);
}
