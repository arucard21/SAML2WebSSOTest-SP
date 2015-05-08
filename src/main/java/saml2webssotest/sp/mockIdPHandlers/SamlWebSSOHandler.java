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
import org.opensaml.saml2.core.AuthnRequest;
import org.opensaml.saml2.core.Response;
import org.opensaml.xml.signature.Signature;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

import saml2webssotest.common.SAMLUtil;
import saml2webssotest.common.StandardNames;
import saml2webssotest.common.StringPair;
import saml2webssotest.common.TestResult;
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

		// retrieve the RelayState, if provided (this will always be either a GET or POST variable called RelayState)
        relayState = request.getParameter(StandardNames.URLPARAM_RELAYSTATE);
        // check if cache-control header is set correctly
        String cachecontrol = request.getHeader(StandardNames.HEADER_CACHECONTROL);
        if(cachecontrol != null && !cachecontrol.isEmpty()){
        	// check if cache-control header has correct value
        	if (!cachecontrol.equalsIgnoreCase(StandardNames.HEADER_CACHECONTROL_VALUE)){
        		logger.error("SAMLBind warning (Section 3.4.5.1+3.5.5.1+3.6.5.1, lines 654+835+1146) - The Cache-Control header was not set to the correct value");
            	SPTestRunner.getInstance().addTestResult("SAMLBind", new TestResult(false, "The Cache-Control header was not set to the correct value", false, "HeaderCacheControl", "The Cache-Control header field should be set to the corrrect value"));
        	}
        	else{
            	SPTestRunner.getInstance().addTestResult("SAMLBind", new TestResult(true, "The Cache-Control header was set to the correct value", false, "HeaderCacheControl", "The Cache-Control header field should be set to the corrrect value"));
        	}
        }
        else{
        	logger.error("SAMLBind warning (Section 3.4.5.1+3.5.5.1+3.6.5.1, lines 654+835+1146) - The Cache-Control header was not set");
        	SPTestRunner.getInstance().addTestResult("SAMLBind", new TestResult(false, "The Cache-Control header was not set", false, "HeaderCacheControl", "The Cache-Control header field should be set to the corrrect value"));
        }
        // check if pragma header is set correctly
        String pragma = request.getHeader(StandardNames.HEADER_PRAGMA);
        if(pragma != null && !pragma.isEmpty()){
        	// check if cache-control header has correct value
        	if (!pragma.equalsIgnoreCase(StandardNames.HEADER_PRAGMA_VALUE)){
        		logger.error("SAMLBind warning (Section 3.4.5.1+3.5.5.1+3.6.5.1, lines 655+836+1147) - The Pragma header was not set to the correct value");
        		SPTestRunner.getInstance().addTestResult("SAMLBind", new TestResult(false, "The Pragma header was not set to the correct value", false, "HeaderPragma", "The Pragma header field should be set to the corrrect value"));
        	}
        	else{
        		SPTestRunner.getInstance().addTestResult("SAMLBind", new TestResult(true, "The Pragma header was set to the correct value", false, "HeaderPragma", "The Pragma header field should be set to the corrrect value"));
        	}
        }
        else{
        	logger.error("SAMLBind warning (Section 3.4.5.1+3.5.5.1+3.6.5.1, lines 655+836+1147) - The Pragma header was not set");
        	SPTestRunner.getInstance().addTestResult("SAMLBind", new TestResult(false, "The Pragma header was not set", false, "HeaderPragma", "The Pragma header field should be set to the corrrect value"));
        }
        
        if (method.equalsIgnoreCase("GET")) {
        	// get the signature
        	signature = request.getParameter(StandardNames.URLPARAM_SIGNATURE);
            // retrieve the SAML Request and binding
        	String reqParam = request.getParameter(StandardNames.URLPARAM_SAMLREQUEST_REDIRECT);
        	
            if (reqParam != null) {
            	SPTestRunner.getInstance().setSamlRequestBinding(SAMLConstants.SAML2_REDIRECT_BINDING_URI);
            	samlRequest = SAMLUtil.decodeSamlMessageForRedirect(reqParam);
            	// check if the decoded SAML message is in fact a valid SAML object
            	AuthnRequest samlObj = null;
            	try{
            		samlObj = (AuthnRequest) SAMLUtil.XMLObjectFromXML(samlRequest);
            	}
            	catch (ClassCastException e){
            		// the decoded string could not be turned into a valid XMLObject (which is the parent of all SAMLObjects)
            		logger.error("SAMLBind violation (Section 3.4.4, lines 571-572) - The SAML Request could not be cast to an AuthnRequest, it was most likely not encoded properly with the DEFLATE encoding");
            		SPTestRunner.getInstance().addTestResult("SAMLBind", new TestResult(false, "The SAML Request could not be cast to an AuthnRequest using the DEFLATE encoding", true, "RedirectDEFLATE", "The DEFLATE encoding must be supported when using the Redirect binding"));
            	}
            	if(samlObj == null){
            		// the decoded string could not be turned into a valid XMLObject (which is the parent of all SAMLObjects)
            		logger.error("SAMLBind violation (Section 3.4.4, lines 571-572) - The SAML Request could not be decoded into a proper AuthnRequest, it was most likely not encoded properly with the DEFLATE encoding");
            		SPTestRunner.getInstance().addTestResult("SAMLBind", new TestResult(false, "The SAML Request could not be decoded into a proper AuthnRequest using the DEFLATE encoding", true, "RedirectDEFLATE", "The DEFLATE encoding must be supported when using the Redirect binding"));
            	}
            	else{
            		SPTestRunner.getInstance().addTestResult("SAMLBind", new TestResult(true, "The SAML Request could be correctly decoded using the DEFLATE encoding", true, "RedirectDEFLATE", "The DEFLATE encoding must be supported when using the Redirect binding"));
            		Element msgDOM = samlObj.getDOM();
            		NodeList signatures = msgDOM.getElementsByTagNameNS(Signature.DEFAULT_ELEMENT_NAME.getNamespaceURI(), Signature.DEFAULT_ELEMENT_NAME.getLocalPart());
            		if (signatures.getLength() > 0){
            			for(int i = 0; i < signatures.getLength(); i++){
            				if (signatures.item(i).getParentNode().isSameNode(msgDOM)){
            					logger.error("SAMLBind violation (Section 3.4.4.1, lines 578-579 - The SAML message contains a Signature element which should be removed for the DEFLATE encoding but a query string parameter called Signature can be used in the URL instead");  
            					SPTestRunner.getInstance().addTestResult("SAMLBind", new TestResult(false, "The SAML message contains a Signature element which should be removed for the DEFLATE encoding", true, "SignaturesRedirect", "The SAML message should not contain signatures when using the Redirect binding"));         					
            				}
            				else{
            					logger.error("SAMLBind warning (Section 3.4.4.1, lines 579-582 - The SAML message contains a Signature element which can not be removed for the DEFLATE encoding so a different encoding (and possibly binding) should be used or the Signature element should be removed");
            					SPTestRunner.getInstance().addTestResult("SAMLBind", new TestResult(false, "The SAML message contains a Signature element which can not be removed for the DEFLATE encoding", false, "SignaturesRedirect", "The SAML message should not contain signatures when using the Redirect binding"));
            				}
            			}
            		}
            		else{
            			SPTestRunner.getInstance().addTestResult("SAMLBind", new TestResult(true, "The SAML message does not contain any Signature elements using the DEFLATE encoding", false, "SignaturesRedirect", "The SAML message should not contain signatures when using the Redirect binding"));
            		}
            		// make sure the Destination attribute is set when the message is signed
            		if(signature != null && !signature.isEmpty()){
            			URL destination = new URL(samlObj.getDestination());
            			URL mockserverLocation = SPTestRunner.getInstance().getMainTestSuite().getMockServerURL();
            			if(!destination.equals(mockserverLocation)){
            				logger.error("SAMLBind violation (Section 3.4.5.2, lines 661-664) - The Destination attribute in the SAML Request doesn't match the URL of the mock IdP");
            				SPTestRunner.getInstance().addTestResult("SAMLBind", new TestResult(false, "The Destination attribute in the SAML Request does not match the URL of the mock IdP", true, "RedirectDestinationWhenSigned", "The Destination attribute on a signed AuthnRequest must contain the URL to which the message was sent"));
            			}
            			else{
            				SPTestRunner.getInstance().addTestResult("SAMLBind", new TestResult(true, "The Destination attribute in the SAML Request matches the URL of the mock IdP", true, "RedirectDestinationWhenSigned", "The Destination attribute on a signed AuthnRequest must contain the URL to which the message was sent"));
            			}
            		}
            	}
                SPTestRunner.getInstance().setSamlRequest(samlRequest);
                applicableACS = SPTestRunner.getInstance().getSPConfig().getApplicableACS(SAMLUtil.fromXML(samlRequest));
                requestID = SAMLUtil.getSamlMessageID(samlRequest);
                
                // verify that a signature is provided when when using relaystate parameter
                if(relayState != null && !relayState.isEmpty()){
                	// check if the signature was provided
                	if(signature == null || signature.isEmpty()){
                		logger.error("SAMLBind warning (Section 3.4.3, lines 545-547) - The target SP has provided a RelayState parameter, but has not provided a Signature that protects the integrity of the RelayState parameter");
                		SPTestRunner.getInstance().addTestResult("SAMLBind", new TestResult(false, "The target SP does not provide a Signature to protect the integrity of the RelayState parameter", false, "RelayStateSignature", "The RelayState parameter should be integrity-protected"));
                	}
                	else{
                		SPTestRunner.getInstance().addTestResult("SAMLBind", new TestResult(true, "The target SP provides a Signature to protect the integrity of the RelayState parameter", false, "RelayStateSignature", "The RelayState parameter should be integrity-protected"));
                	}
                }
                
                // retrieve the SAMLEncoding, if provided, and make sure it's set to DEFLATE (the only one supported by the test framework and the one required to be supported by all endpoints)
                String samlencoding = request.getParameter(StandardNames.URLPARAM_SAMLENCODING);
                if(samlencoding != null && !samlencoding.isEmpty()){
                	if(!samlencoding.equals(StandardNames.SAMLENCODING_DEFLATE)){
                		logger.error("SAMLBind warning (Section 3.4.4, lines 568-570) - The target SP has provided a SAMLEncoding parameter, but it is not set to "+ StandardNames.SAMLENCODING_DEFLATE +" so it is not supported by this test framework");
                		SPTestRunner.getInstance().addTestResult("SAMLBind", new TestResult(false, "The SAMLEncoding provided was not DEFLATE", false, "SAMLEncodingDEFLATE", "The SAMLEncoding should be set to DEFLATE (other encodings are not supported in this test framework)"));
                	}
                	else{
                		SPTestRunner.getInstance().addTestResult("SAMLBind", new TestResult(true, "The SAMLEncoding provided was DEFLATE", false, "SAMLEncodingDEFLATE", "The SAMLEncoding should be set to DEFLATE (other encodings are not supported in this test framework)"));
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
            	// check if the decoded SAML message is in fact a valid SAML object
            	AuthnRequest samlObj = null;
            	try{
            		samlObj = (AuthnRequest) SAMLUtil.XMLObjectFromXML(samlRequest);
            	}
            	catch(ClassCastException e){
            		// the decoded string could not be turned into a valid XMLObject (which is the parent of all SAMLObjects)
            		logger.error("SAMLBind violation (Section 3.5.4, lines 790-791) - The SAML Request could not be cast to an AuthnRequest, it was most likely not encoded properly with base-64 encoding");
            		SPTestRunner.getInstance().addTestResult("SAMLBind", new TestResult(false, "The SAML message was not properly encoded", false, "POSTEncoding", "The SAML message should be properly encoded"));
            	}
            	if(samlObj == null){
            		// the decoded string could not be turned into a valid XMLObject (which is the parent of all SAMLObjects)
            		logger.error("SAMLBind violation (Section 3.5.4, lines 790-791) - The SAML Request could not be decoded into a proper AuthnRequest, it was most likely not encoded properly with base-64 encoding");
            		SPTestRunner.getInstance().addTestResult("SAMLBind", new TestResult(false, "The SAML message was not properly encoded", false, "POSTEncoding", "The SAML message should be properly encoded"));
            	}
            	else{
            		SPTestRunner.getInstance().addTestResult("SAMLBind", new TestResult(true, "The SAML message was properly encoded", false, "POSTEncoding", "The SAML message should be properly encoded"));
            		// make sure the Destination attribute is set when the message is signed
            		if(samlObj.isSigned()){
            			URL destination = new URL(samlObj.getDestination());
            			URL mockserverLocation = SPTestRunner.getInstance().getMainTestSuite().getMockServerURL();
            			if(!destination.equals(mockserverLocation)){
            				logger.error("SAMLBind violation (Section 3.5.5.2, lines 843-846) - The Destination attribute in the SAML Request doesn't match the URL of the mock IdP");
            				SPTestRunner.getInstance().addTestResult("SAMLBind", new TestResult(false, "The Destination attribute in the SAML Request doesn't match the URL of the mock IdP", true, "POSTDestinationWhenSigned", "The Destination attribute on a signed AuthnRequest must contain the URL to which the message was sent"));
            			}
            			else{
            				SPTestRunner.getInstance().addTestResult("SAMLBind", new TestResult(true, "The Destination attribute in the SAML Request matches the URL of the mock IdP", true, "POSTDestinationWhenSigned", "The Destination attribute on a signed AuthnRequest must contain the URL to which the message was sent"));
            			}
            		}
            	}
            	SPTestRunner.getInstance().setSamlRequest(samlRequest);
            	applicableACS = SPTestRunner.getInstance().getSPConfig().getApplicableACS(SAMLUtil.fromXML(samlRequest));
            	requestID = SAMLUtil.getSamlMessageID(samlRequest);
            	
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
				// the target SP's ACS uses HTTPS
				SPTestRunner.getInstance().addTestResult("SAMLBind", new TestResult(true, "The target SP uses SSL/TLS on the ACS endpoint", true, "HTTPSonACS", "The target SP should use SSL/TLS on the ACS endpoint"));
				
				HttpsURLConnection acsConn = (HttpsURLConnection) acsURLConn;
				try{
					// try to connect to the root of the ACS URL, while verifying the SSL certificates
					acsConn.connect();
				} catch(SSLHandshakeException badSSL){
					// TODO check if the https connection actually uses ssl 3.0 or tls 1.0 or higher.
					
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
    						SPTestRunner.getInstance().addTestResult("SAMLBind", new TestResult(false, "The target SP does not use an X.509 v3 SSL certificate on the ACS endpoint", true, "X.509v3Certs", "The target SP should use an X.509 v3 SSL certificate on the ACS endpoint"));
    						SPTestRunner.getInstance().addTestResult("SAMLConf", new TestResult(false, "The target SP does not use an X.509 v3 SSL certificate on the ACS endpoint", true, "X.509v3Certs", "The target SP should use an X.509 v3 SSL certificate on the ACS endpoint"));
    					}
    					else{
    						SPTestRunner.getInstance().addTestResult("SAMLBind", new TestResult(true, "The target SP uses an X.509 v3 SSL certificate on the ACS endpoint", true, "X.509v3Certs", "The target SP should use an X.509 v3 SSL certificate on the ACS endpoint"));
    						SPTestRunner.getInstance().addTestResult("SAMLConf", new TestResult(true, "The target SP uses an X.509 v3 SSL certificate on the ACS endpoint", true, "X.509v3Certs", "The target SP should use an X.509 v3 SSL certificate on the ACS endpoint"));
    					}
    				}
    				else {
    					logger.error("SAMLBind violation (Section 3.1.2.1, lines 237-238) - The target SP has a non-X.509 SSL certificate on the ACS endpoint");
    					logger.error("SAMLConf violation (Section 5, lines 255-256) - The target SP has a non-X.509 SSL certificate on the ACS endpoint");
    					SPTestRunner.getInstance().addTestResult("SAMLBind", new TestResult(false, "The target SP does not use an X.509 SSL certificate on the ACS endpoint", true, "X.509v3Certs", "The target SP should use an X.509 v3 SSL certificate on the ACS endpoint"));
						SPTestRunner.getInstance().addTestResult("SAMLConf", new TestResult(false, "The target SP does not use an X.509 SSL certificate on the ACS endpoint", true, "X.509v3Certs", "The target SP should use an X.509 v3 SSL certificate on the ACS endpoint"));
    				}
    			}
			}
			else{
				// the target SP's ACS doesn't use HTTPS
				logger.error("SAMLBind warning (Section 3.4.5.2+3.5.5.2+3.6.5.2, lines 667-669+849-851+1157-1158) - The target SP has an AssertionConsumerService that doesn't use HTTPS");
				SPTestRunner.getInstance().addTestResult("SAMLBind", new TestResult(false, "The target SP does not use SSL/TLS on the ACS endpoint", true, "HTTPSonACS", "The target SP should use SSL/TLS on the ACS endpoint"));
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
        			SPTestRunner.getInstance().addTestResult("SAMLBind", new TestResult(false, "The target SP has provided a RelayState parameter which exceeds 80 bytes in size", true, "RelayStateSize", "The target SP's RelayState size should not exceed 80 bytes"));
        		}
        		else{
        			SPTestRunner.getInstance().addTestResult("SAMLBind", new TestResult(true, "The target SP has provided a RelayState parameter which does not exceed 80 bytes in size", true, "RelayStateSize", "The target SP's RelayState size should not exceed 80 bytes"));
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