package saml2TestframeworkSP.testsuites;

import java.io.IOException;
import java.io.StringReader;

import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;

import org.xml.sax.InputSource;
import org.xml.sax.SAXException;

import saml2TestframeworkCommon.TestStatus;


public class SAML2Int extends TestSuite {

	@Override
	public int getMockIdPPort() {
		return 8080;
	}

	@Override
	public String getMockIdPURL() {
		return "localhost";
	}

	@Override
	public String getmockIdPEntityID() {
		return "localhost";
	}

	@Override
	public String getIdPMetadata() {
		return null;
	}

	/**
	 *  Tests the following part of the SAML2Int Profile:
	 *  	Identity Providers and Service Providers MUST provide a SAML 2.0 Metadata document representing its entity. 
	 *  	How metadata is exchanged is out of scope of this specification.
	 *  
	 *  TODO The metadata is currently provided in the target SP configuration, but this 
	 *  test will be more useful when the test framework allows retrieving metadata from URL's
	 *   
	 * @author RiaasM
	 *
	 */
	public class MetadataAvailable implements MetadataTestCase {
		private String failedMessage;
		
		@Override
		public String getDescription() {
			return "Test if the Service Provider's metadata is available";
		}

		@Override
		public String getSuccessMessage() {
			return "The Service Provider's metadata is available";
		}

		@Override
		public String getFailedMessage() {
			return failedMessage;
		}

		@Override
		public TestStatus checkMetadata(String metadata) {
			if(metadata != null && !metadata.isEmpty()){
				// check if the metadata is correct XML by trying to parse it
				DocumentBuilderFactory dbuildfac = DocumentBuilderFactory.newInstance();
				dbuildfac.setValidating(false);
				dbuildfac.setNamespaceAware(true);
				try {
					dbuildfac.newDocumentBuilder().parse(new InputSource(new StringReader(metadata)));
					// if no exception has occurred, then the XML is well-formed
					return TestStatus.OK;
				} catch (ParserConfigurationException e) {
					System.err.println("The metadata parser was configured incorrectly");
					e.printStackTrace();
				} catch (SAXException e) {
					// The metadata could not be parsed
					failedMessage = "The Service Provider's metadata was not well-formed XML";
				} catch (IOException e) {
					System.err.println("The Service Provider's metadata could not be accessed");
					e.printStackTrace();
				}
			}
			else{
				failedMessage = "The Service Provider's metadata was not available";
			}
			// The test failed but you need to check if it failed due to specification or an error in the test case itself
			if (failedMessage != null && !failedMessage.isEmpty()){
				// The test failed because a specification check failed
				return TestStatus.ERROR;
			}
			else{
				// The test failed but the failedMessage was not set, so there was a problem with the test case itself.
				return TestStatus.CRITICAL;
			}
		}
		
	}

	/**
	 *  Tests the following part of the SAML2Int Profile:
	 *  	Metadata documents provided by a Service Provider MUST include an <md:SPSSODescriptor> element containing 
	 *  	all necessary <md:KeyDescriptor> and <md:AssertionConsumerService> elements.
	 * @author RiaasM
	 *
	 */
	public class MetadataElementsAvailable implements MetadataTestCase{
		private String failedMessage;

		@Override
		public String getDescription() {
			return "Test if the minimally required elements are available in the metadata";
		}

		@Override
		public String getSuccessMessage() {
			return "All minimally required elements are available in the metadata";
		}

		@Override
		public String getFailedMessage() {
			return failedMessage;
		}

		@Override
		public TestStatus checkMetadata(String metadata) {
			failedMessage = "NOT YET IMPLEMENTED";
			return TestStatus.CRITICAL;
		}
		
	}
}
