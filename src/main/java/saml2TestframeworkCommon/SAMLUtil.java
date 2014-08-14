package saml2TestframeworkCommon;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.StringReader;
import java.io.StringWriter;
import java.io.UnsupportedEncodingException;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLEncoder;
import java.util.zip.Deflater;
import java.util.zip.DeflaterOutputStream;
import java.util.zip.Inflater;
import java.util.zip.InflaterInputStream;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerConfigurationException;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.TransformerFactoryConfigurationError;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.apache.commons.codec.binary.StringUtils;
import org.opensaml.Configuration;
import org.opensaml.common.SAMLObject;
import org.opensaml.xml.io.Marshaller;
import org.opensaml.xml.io.MarshallingException;
import org.opensaml.xml.util.Base64;
import org.w3c.dom.Document;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;

/**
 * Utility class containing some convenience methods. 
 * 
 * The encode/decode methods are based on (basically copied from) the corresponding methods in OpenSAML. Unfortunately, those 
 * methods were not easily accessible so these methods can be used instead. They still use the Base64 implementation from OpenSAML.
 * @author RiaasM
 *
 */
public class SAMLUtil {
	
	/**
	 * Encodes the SAML Request or Response according to the Redirect binding.
	 * 
	 * @param message is the original SAML message as a string
	 * @return the encoded SAML message
	 */
	public static String encodeSamlMessageForRedirect(String message){
		try {
			ByteArrayOutputStream bytesOut = new ByteArrayOutputStream();
            Deflater deflater = new Deflater(Deflater.DEFLATED, true);
            DeflaterOutputStream deflaterStream = new DeflaterOutputStream(bytesOut, deflater);
            deflaterStream.write(message.getBytes("UTF-8"));
            deflaterStream.finish();

			String b64compressedRequest = Base64.encodeBytes(bytesOut.toByteArray(), Base64.DONT_BREAK_LINES);
			// url-encode
			return URLEncoder.encode(b64compressedRequest, "UTF-8");
		} catch (UnsupportedEncodingException e) {
			// url encoding failed because the encoding was not supported
			e.printStackTrace();
			return "";
		} catch (IOException e) {
			// problems writing to the deflated stream
			e.printStackTrace();
		}
		return null;
	}
	
	/**
	 * Encodes the SAML Request or Response according to the POST binding.
	 * 
	 * @param message is the original SAML message as a string
	 * @return the encoded SAML message
	 */
	public static String encodeSamlMessageForPost(String message) {
		return Base64.encodeBytes(StringUtils.getBytesUtf8(message));
	}

	/**
	 * Decodes the SAML Request or Response according to the Redirect binding.
	 * 
	 * Note that it does not perform the URL-decoding since this is often already done
	 * automatically. Make sure the provided string is already URL-decoded.
	 * 
	 * @param request is the encoded SAML message as a string
	 * @return the decoded SAML message
	 */
	public static String decodeSamlMessageForRedirect(String request) {
		try {
			// url-decoding was already done by the mock IdP so only do base64-decode and decompress
			ByteArrayInputStream bytesIn = new ByteArrayInputStream(Base64.decode(request));
            InflaterInputStream inflater = new InflaterInputStream(bytesIn, new Inflater(true));
            ByteArrayOutputStream bytesOut = new ByteArrayOutputStream();
            // read the decompressed data and write it to a string
            byte[] buffer = new byte[1024];
            int length = 0;
            while ((length = inflater.read(buffer)) >= 0) {
                bytesOut.write(buffer, 0, length);
            }
            return bytesOut.toString();
		} catch (UnsupportedEncodingException e) {
			// url decoding failed because the encoding was not supported
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		} 
		return null;
	}

	/**
	 * Decodes the SAML Request according to the binding.
	 * 
	 * Note that a SAML Request can only be used with the Redirect and POST bindings
	 * 
	 * @param request is the encoded SAML Request as a string
	 * @param binding is the binding for which it should be decoded
	 * @return the decoded SAML Request
	 */
	public static String decodeSamlMessageForPost(String request) {
		// base64-decode
		return StringUtils.newStringUtf8(Base64.decode(request));
	}
	
	/**
	 * 
	 * @param xmlString
	 * @return
	 */
	public static Document fromXML(String xmlString){
		if (xmlString != null && !xmlString.isEmpty()){
			try {
				DocumentBuilderFactory xmlDocBuilder = DocumentBuilderFactory.newInstance();
				xmlDocBuilder.setNamespaceAware(true);
				DocumentBuilder docbuilder = xmlDocBuilder.newDocumentBuilder();
				// check if the string contains a URL and retrieve the XML from there
				// otherwise just treat the string itself as XML 
				try{
					URL xmlLocation = new URL(xmlString);
					return docbuilder.parse(xmlLocation.toExternalForm());
				} catch(MalformedURLException noURL){
					return docbuilder.parse(new InputSource(new StringReader(xmlString)));
				}
			} catch (ParserConfigurationException e) {
				e.printStackTrace();
			} catch (SAXException e) {
				e.printStackTrace();
			} catch (IOException e) {
				e.printStackTrace();
			}
		}
		return null;
	}
	/**
	 * Convert a SAML Object to XML in a string
	 * 
	 * @param samlObj is the SAML object that should be converted
	 * @return the given SAML object as a string or an empty string if it could not be converted
	 */
	public static String toXML(SAMLObject samlObj){
		try {
			Marshaller marshall = Configuration.getMarshallerFactory().getMarshaller(samlObj.getElementQName());
			// Marshall the SAML object into an XML object
			Document xmlDoc = DocumentBuilderFactory.newInstance().newDocumentBuilder().newDocument();
			marshall.marshall(samlObj, xmlDoc);
			return toXML(xmlDoc);
		} catch (MarshallingException e) {
			System.err.println("Could not marshall the metadata into an Element");
			e.printStackTrace();
		} catch (ParserConfigurationException e) {
			e.printStackTrace();
		}
		return "";
	}
	
	/**
	 * Convert an org.w3c.dom.Document to XML in a string
	 * 
	 * @param doc is the Document that should be converted
	 * @return the given XML Document as a string or an empty string if it could not be converted
	 */
	public static String toXML(Document doc){
		try {
			// Convert the XML object to a string
			Transformer transformer = TransformerFactory.newInstance().newTransformer();
			StringWriter writer = new StringWriter();
			transformer.transform(new DOMSource(doc), new StreamResult(writer));
			return writer.toString();
		} catch (TransformerConfigurationException e) {
			e.printStackTrace();
		} catch (TransformerFactoryConfigurationError e) {
			e.printStackTrace();
		} catch (TransformerException e) {
			System.err.println("Could not convert the metadata object to a string");
			e.printStackTrace();
		}
		return "";
	}

}
