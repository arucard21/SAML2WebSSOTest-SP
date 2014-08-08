package saml2TestframeworkCommon;

import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.util.zip.DataFormatException;
import java.util.zip.Deflater;
import java.util.zip.Inflater;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.binary.StringUtils;

public class SAMLUtil {
	
	/**
	 * Encodes the SAML Request or Response according to the Redirect binding.
	 * 
	 * @param message is the original SAML message as a string
	 * @return the encoded SAML message
	 */
	public static String encodeSamlMessageForRedirect(String message){
		try {
			byte[] compressedBytes = new byte[1024];
			// create a GZIP compatible compressor 
			Deflater compressor = new Deflater(0, true);
			compressor.setInput(StringUtils.getBytesUtf8(message));
			compressor.finish();
		    compressor.deflate(compressedBytes);
		    compressor.end();
			
			// base64-encode
			byte[] b64encoded = Base64.encodeBase64(compressedBytes);
			String b64compressedRequest = StringUtils.newStringUtf8(b64encoded);
			
			// url-encode
			String urlencoded = URLEncoder.encode(b64compressedRequest, "UTF-8");
			
			return urlencoded;
			
		} catch (UnsupportedEncodingException e) {
			// url encoding failed because the encoding was not supported
			e.printStackTrace();
			return "";
		}
	}
	
	/**
	 * Encodes the SAML Request or Response according to the POST binding.
	 * 
	 * @param message is the original SAML message as a string
	 * @return the encoded SAML message
	 */
	public static String encodeSamlMessageForPost(String message) {
		return StringUtils.newStringUtf8(Base64.encodeBase64(StringUtils.getBytesUtf8(message)));
	}

	/**
	 * Decodes the SAML Request or Response according to the Redirect binding.
	 * 
	 * @param request is the encoded SAML message as a string
	 * @return the decoded SAML message
	 */
	public static String decodeSamlMessageForRedirect(String request, String binding) {
		try {
			// url-decode
			String urldecoded = URLDecoder.decode(request, "UTF-8");
			// base64-decode
			byte[] b64decoded = Base64.decodeBase64(urldecoded);
			// create a GZIP compatible decompressor 
			Inflater decompressor = new Inflater(true);
			// add a byte to the input for GZIP compatibility
			byte dummy = 0;
			b64decoded[b64decoded.length] = dummy;
			// decompress the data
			decompressor.setInput(b64decoded);
			byte[] decompressedBytes = new byte[1024];
			decompressor.inflate(decompressedBytes);
			decompressor.end();
			return StringUtils.newStringUtf8(decompressedBytes);
			
		} catch (UnsupportedEncodingException e) {
			// url decoding failed because the encoding was not supported
			e.printStackTrace();
			return "";
		} catch (DataFormatException e) {
			// inflate failed because the data was not valid
			e.printStackTrace();
			return "";
		}
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
		return StringUtils.newStringUtf8(Base64.decodeBase64(request));
	}
}
