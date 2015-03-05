package saml2webssotest.sp.mockIdPHandlers;

import java.io.IOException;

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

        if (method.equalsIgnoreCase("GET")) {
            // retrieve the SAML Request and binding
        	String reqParam = request.getParameter(StandardNames.URLPARAM_SAMLREQUEST_REDIRECT);
        	
            if (reqParam != null) {
            	SPTestRunner.getInstance().setSamlRequestBinding(SAMLConstants.SAML2_REDIRECT_BINDING_URI);
            	samlRequest = SAMLUtil.decodeSamlMessageForRedirect(reqParam);
                SPTestRunner.getInstance().setSamlRequest(samlRequest);
                applicableACS = SPTestRunner.getInstance().getSPConfig().getApplicableACS(SAMLUtil.fromXML(samlRequest));
                requestID = SAMLUtil.getSamlMessageID(samlRequest);

                logger.debug("SAML Request received through GET by the mock IdP");
            }
            else if (request.getParameter(StandardNames.URLPARAM_SAMLARTIFACT) != null){
            	SPTestRunner.getInstance().setSamlRequestBinding(SAMLConstants.SAML2_ARTIFACT_BINDING_URI);
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

            	logger.debug("SAML Request received through POST by the mock IdP");
            		
            }
            else if (request.getParameter(StandardNames.URLPARAM_SAMLARTIFACT) != null){
            	SPTestRunner.getInstance().setSamlRequestBinding(SAMLConstants.SAML2_ARTIFACT_BINDING_URI);
                // TODO: implement for BINDING_HTTP_ARTIFACT
            }
            else{
            	logger.error("SAML Request sent using an unknown binding (with POST)");
            }
        }
        else{
        	logger.error("SAML Request sent using an unknown binding (with neither GET nor POST)");
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
		// add the SAML Response as post data
		String responsePage = "<html>"
				+ "<body onLoad=\"document.sendSAMLResponse.submit()\">"
						+ "<form action=\""+applicableACS.getName()+"\" method=\"post\" name=\"sendSAMLResponse\">"
								+ "<input type=\"hidden\" name=\""+StandardNames.URLPARAM_SAMLRESPONSE_POST+"\" value=\""+SAMLUtil.encodeSamlMessageForPost(samlResponse)+"\"/>"
						+ "</form>"
				+ "</body>"
				+ "</html>";
		response.getWriter().print(responsePage);
		// declare that we're done processing the request
		request.setHandled(true);
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