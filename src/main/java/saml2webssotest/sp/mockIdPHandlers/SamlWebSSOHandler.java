package saml2webssotest.sp.mockIdPHandlers;

import java.io.IOException;
import java.net.URL;
import java.net.URLConnection;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Arrays;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLHandshakeException;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.eclipse.jetty.server.HttpChannel;
import org.eclipse.jetty.server.Request;
import org.eclipse.jetty.server.handler.AbstractHandler;
import org.opensaml.common.xml.SAMLConstants;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.Response;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import saml2webssotest.common.SAMLUtil;
import saml2webssotest.common.StandardNames;
import saml2webssotest.common.StringPair;
import saml2webssotest.sp.SPTestRunner;
import saml2webssotest.sp.testsuites.SPTestSuite;

public class SamlWebSSOHandler extends AbstractHandler{
	private String method;
	private String samlRequest;
	private String requestID;
	private StringPair applicableACS;
	private boolean returnArtifact;
	
	private final Logger logger = LoggerFactory.getLogger(SamlWebSSOHandler.class);
	/**
	 * Handle a received request.
	 * It should retrieve and decode the SAML Request and send it to the test runner. If the response should be sent over a synchronous 
	 * connection, it should also send that response.
	 * 
	 * @param target is the identifier for the resource that should handle the request, usually the URI from the HTTP Request
	 * @param baseRequest is the original unwrapped request
	 * @param request is the request that the handler received
	 * @param response is the response that will be sent
	 */
	@Override
	public void handle(String target, Request baseRequest, HttpServletRequest abstractRequest, HttpServletResponse response) throws IOException, ServletException {
		Request request = (abstractRequest instanceof Request) ? (Request) abstractRequest : HttpChannel.getCurrentHttpChannel().getRequest();
		method = request.getMethod();
		samlRequest = null;
		applicableACS = null;
		String relayState = "";
		String signature = "";

        if (method.equalsIgnoreCase("GET")) {
            // retrieve the SAML Request and binding
        	String reqParam = request.getParameter(StandardNames.URLPARAM_SAMLREQUEST_REDIRECT);
        	
            if (reqParam != null) {
            	SPTestRunner.getInstance().setSamlRequestBinding(SAMLConstants.SAML2_REDIRECT_BINDING_URI);
            	samlRequest = SAMLUtil.decodeSamlMessageForRedirect(reqParam);
                SPTestRunner.getInstance().setSamlRequest(samlRequest);
                applicableACS = SPTestRunner.getInstance().getSPConfig().getApplicableACS(SAMLUtil.fromXML(samlRequest));
                requestID = SAMLUtil.getSamlMessageID(samlRequest);
                
                // retrieve the RelayState, if provided (this will always be either a GET or POST variable called RelayState)
                relayState = request.getParameter(StandardNames.URLPARAM_RELAYSTATE);
                if(relayState != null && !relayState.isEmpty()){
                	signature = request.getParameter(StandardNames.URLPARAM_SIGNATURE);
                	// check if the signature was provided
                		if(signature == null){
                		logger.error("SAMLBind warning (Section 3.4.3, lines 545-547) - The target SP has provided a RelayState parameter, but has not provided a Signature that protects the integrity of the RelayState parameter");
                	}
                }

                logger.debug("SAML Request received through GET by the mock IdP");
            }
            else if (request.getParameter(StandardNames.URLPARAM_SAMLARTIFACT) != null){
            	SPTestRunner.getInstance().setSamlRequestBinding(SAMLConstants.SAML2_ARTIFACT_BINDING_URI);
            	returnArtifact = true;
                // TODO: implement for BINDING_HTTP_ARTIFACT
            }
            else{
            	applicableACS = SPTestRunner.getInstance().getSPConfig().getApplicableACS(SAMLUtil.fromXML(null));
            	logger.debug("Attempting IdP-initiated login");
            }
        }
        else if (method.equalsIgnoreCase("POST")) {
            // get the POST variables
        	String reqParam = request.getParameter(StandardNames.URLPARAM_SAMLREQUEST_POST);
            
            if (reqParam != null){
            	SPTestRunner.getInstance().setSamlRequestBinding(SAMLConstants.SAML2_POST_BINDING_URI);
            	samlRequest = SAMLUtil.decodeSamlMessageForPost(reqParam);
            	SPTestRunner.getInstance().setSamlRequest(samlRequest);
            	applicableACS = SPTestRunner.getInstance().getSPConfig().getApplicableACS(SAMLUtil.fromXML(samlRequest));
            	requestID = SAMLUtil.getSamlMessageID(samlRequest);
            	
            	 // retrieve the RelayState, if provided (this will always be either a GET or POST variable called RelayState)
                relayState = request.getParameter(StandardNames.URLPARAM_RELAYSTATE);

            	logger.debug("SAML Request received through POST by the mock IdP");
            		
            }
            else if (request.getParameter(StandardNames.URLPARAM_SAMLARTIFACT) != null){
            	SPTestRunner.getInstance().setSamlRequestBinding(SAMLConstants.SAML2_ARTIFACT_BINDING_URI);
            	returnArtifact = true;
                // TODO: implement for BINDING_HTTP_ARTIFACT
            }
            else{
            	logger.error("SAML Request sent using an unknown binding (with POST)");
            }
        }
        else{
        	logger.error("SAML Request sent using an unknown binding (with neither GET nor POST)");
        }
		if (applicableACS != null) {
			// connect to the base URL of the applicable ACS so we don't interfere with the login process
			URL acs = new URL(applicableACS.getName());
			URL baseACS = new URL(acs.getProtocol(), acs.getHost(), acs.getPort(), "");
			URLConnection acsURLConn =  baseACS.openConnection();
			logger.debug("Checking SSL certificate version with a second connection to the URL: " + baseACS.toString());
			// check if the connection is an HTTPS connection
			if (acsURLConn instanceof HttpsURLConnection){
				HttpsURLConnection acsConn = (HttpsURLConnection) acsURLConn;
				try{
					// try to connect to the root of the ACS URL, while verifying the SSL certificates
					acsConn.connect();
				} catch(SSLHandshakeException badSSL){
					// disconnect from the URL before reconfiguring the connecting to trust all SSL certificates
					acsConn.disconnect();
					// Create a trust manager that does not validate certificate chains since we are not
					// trying to test the certificate validity
					TrustManager[] trustAllCerts = new TrustManager[] {
							new X509TrustManager() {
								@Override
								public X509Certificate[] getAcceptedIssuers() {return new X509Certificate[0];}
								@Override
								public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {}
								@Override
								public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {}
							}
					};
					// Install the all-trusting trust manager on the HttpsURLConnection
					try {
					    SSLContext sc = SSLContext.getInstance("SSL"); 
					    sc.init(null, trustAllCerts, new java.security.SecureRandom()); 
					    acsConn.setSSLSocketFactory(sc.getSocketFactory());
					} catch (NoSuchAlgorithmException e) {
						logger.error("The SSL protocol was not supported in the SSLContext", e);
					} catch (KeyManagementException e){
						logger.error("Could not initialize the SSLContext", e);
					}
					// connect again, while trusting all certificates
					try{
						acsConn.connect();
					} catch (IOException e){
						logger.error("Could not connect to target SP, even without verifying SSL certificates", e);
					}
				}
    			Certificate[] certs = acsConn.getServerCertificates();
    			acsConn.disconnect();
    			for (Certificate cert : Arrays.asList(certs)) {
    				if (cert instanceof X509Certificate) {
    					X509Certificate x509cert = (X509Certificate) cert;
    					// check if the certificate is X.509 v3
    					if (x509cert.getVersion() != 3) {
    						logger.error("SAMLBind violation (Section 3.1.2.1, lines 237-238) - The target SP does not have an X.509 v3 SSL certificate on the ACS endpoint, instead it uses version "
    								+ x509cert.getVersion());
    						logger.error("SAMLConf violation (Section 5, lines 255-256) - The target SP does not have an X.509 v3 SSL certificate on the ACS endpoint, instead it uses version "
    								+ x509cert.getVersion());
    					}
    				}
    				else {
    					logger.error("SAMLBind violation (Section 3.1.2.1, lines 237-238) - The target SP has a non-X.509 SSL certificate on the ACS endpoint");
    					logger.error("SAMLConf violation (Section 5, lines 255-256) - The target SP has a non-X.509 SSL certificate on the ACS endpoint");
    				}
    			}
			}
		}
        if (returnArtifact){
    		/**
    		 * Artifact binding requested, which is not yet supported
    		 * TODO: add support for artifact binding
    		 */
    		// set page to return POST data
    		response.setContentType("text/html");
    		// make page redirect back to SP's ACS
    		response.setStatus(HttpServletResponse.SC_OK);
    		// log the response
    		logger.error("Can not send Response because it is requested with the unsupported Artifact binding");
    		// add the SAML Response as post data
    		String responsePage = "<html>"
    				+ "<body"
    				+ "SAML2WebSSOTest does not yet support the Artifact binding"
    				+ "</body>"
    				+ "</html>";
    		response.getWriter().print(responsePage);
    		// declare that we're done processing the request
    		request.setHandled(true);
        }
        else{
        	String relayStateFormInput = "";
        	if(relayState != null && !relayState.isEmpty()){
        		// create the form input element that will be used to return the RelayState to the target SP
        		relayStateFormInput = "<input type=\"hidden\" name=\""+StandardNames.URLPARAM_RELAYSTATE+"\" value=\""+relayState+"\"/>";
        		// Make sure the RelayState does not exceed 80 bytes in size
        		if (relayState.getBytes().length > 80 ){
        			logger.error("SAMLBind violation (Section 3.4.3, lines 545-547) - The target SP has provided a RelayState parameter which exceeds 80 bytes in size, its size (in bytes) is "+ relayState.getBytes().length);
        		}
        	}
        	// get the SAML Response that should be sent and replace any request variables (e.g. [[requestID]])  that have been placed in it
        	String samlResponse = replaceReqVars(SPTestRunner.getInstance().getSamlResponse());	
        	// set page to return POST data
        	response.setContentType("text/html");
        	// make page redirect back to SP's ACS
        	response.setStatus(HttpServletResponse.SC_OK);
        	// log the response
        	logger.debug("Sending a Response with the mock IdP");
        	logger.trace(samlResponse);
        	// add the SAML Response as post data, including possibly the RelayState parameter 
        	String responsePage = "<html>"
        			+ "<body onLoad=\"document.sendSAMLResponse.submit()\">"
        			+ "<form action=\""+applicableACS.getName()+"\" method=\"post\" name=\"sendSAMLResponse\">"
        			+ relayStateFormInput
        			+ "<input type=\"hidden\" name=\""+StandardNames.URLPARAM_SAMLRESPONSE_POST+"\" value=\""+SAMLUtil.encodeSamlMessageForPost(samlResponse)+"\"/>"
        			+ "</form>"
        			+ "</body>"
        			+ "</html>";
        	response.getWriter().print(responsePage);
        	// declare that we're done processing the request
        	request.setHandled(true);
        }
	}
	
	/**
	 * Replace the placeholders for values obtained from the AuthnRequest in the Response
	 * 
	 * This will replace placeholders in the string, like [[requestID]], with the appropriate
	 * value from the AuthnRequest that was received.
	 * 
	 * @param samlResponse is the SAML Response as received from the test runner
	 * @return a SAML Response with all placeholders replaced with the appropriate values
	 */
	private String replaceReqVars(String samlResponse) {
		// only update the SAML Response if it contains any placeholders
		if (samlResponse.contains(SPTestSuite.PLACEHOLDER_REQUESTID) || samlResponse.contains(SPTestSuite.PLACEHOLDER_ACSURL)){
    		// replace the placeholders with actual values
    		String fullResponse = samlResponse
    				.replace(SPTestSuite.PLACEHOLDER_REQUESTID, requestID)
    				.replace(SPTestSuite.PLACEHOLDER_ACSURL, applicableACS.getName());
    		
    		// re-sign the assertions and response that were previously signed so the signatures are valid again
    		Response resp = (Response) SAMLUtil.XMLObjectFromXML(fullResponse);
    		// check if the contained assertions have been signed
    		for (Assertion assertion: resp.getAssertions()){
    			// re-sign the assertion if it was already signed and updating the assertion signature is allowed
    			if (assertion.isSigned() && SPTestRunner.getInstance().isSigUpdateAssertionAllowed()){
    				SAMLUtil.sign(assertion, SPTestRunner.getInstance().getMockedX509Credentials(null));
    			}
    		}
    		// re-sign the response if it was already signed and updating the response signature is allowed
    		if (resp.isSigned() && SPTestRunner.getInstance().isSigUpdateResponseAllowed()){
    			// remove existing signatures
    			SAMLUtil.sign(resp, SPTestRunner.getInstance().getMockedX509Credentials(null));
    		}
    		return SAMLUtil.toXML(resp);
		}
		else{
			return samlResponse;
		}
	}
}