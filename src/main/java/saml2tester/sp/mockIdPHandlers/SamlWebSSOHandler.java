package saml2tester.sp.mockIdPHandlers;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.eclipse.jetty.server.HttpChannel;
import org.eclipse.jetty.server.Request;
import org.eclipse.jetty.server.handler.AbstractHandler;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import saml2tester.common.SAMLUtil;
import saml2tester.common.standardNames.SAMLmisc;
import saml2tester.sp.SPTestRunner;

public class SamlWebSSOHandler extends AbstractHandler{
	
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
		String method = request.getMethod();
		String samlRequest;

        if (method.equalsIgnoreCase("GET")) {
            // retrieve the SAML Request and binding
        	String reqParam = request.getParameter(SAMLmisc.URLPARAM_SAMLREQUEST_REDIRECT);
        	
            if (reqParam != null) {
            	SPTestRunner.setSamlRequestBinding(SAMLmisc.BINDING_HTTP_REDIRECT);
            	samlRequest = SAMLUtil.decodeSamlMessageForRedirect(reqParam);
                SPTestRunner.setSamlRequest(samlRequest);

                logger.debug("SAML Request received through GET by the mock IdP");
            }
            else if (request.getParameter(SAMLmisc.URLPARAM_SAMLARTIFACT) != null){
            	SPTestRunner.setSamlRequestBinding(SAMLmisc.BINDING_HTTP_ARTIFACT);
            	samlRequest = "";
                // TODO: implement for BINDING_HTTP_ARTIFACT
            }
            else{
            	samlRequest = "";
            	logger.error("SAML Request sent using an unknown binding (with GET)");
            }
        }
        else if (method.equalsIgnoreCase("POST")) {
            // get the POST variables
        	String reqParam = request.getParameter(SAMLmisc.URLPARAM_SAMLREQUEST_POST);
            
            if (reqParam != null){
            	SPTestRunner.setSamlRequestBinding(SAMLmisc.BINDING_HTTP_POST);
            	samlRequest = SAMLUtil.decodeSamlMessageForPost(reqParam);
            	SPTestRunner.setSamlRequest(samlRequest);

            	logger.debug("SAML Request received through POST by the mock IdP");
            		
            }
            else if (request.getParameter(SAMLmisc.URLPARAM_SAMLARTIFACT) != null){
            	SPTestRunner.setSamlRequestBinding(SAMLmisc.BINDING_HTTP_ARTIFACT);
            	samlRequest = "";
                // TODO: implement for BINDING_HTTP_ARTIFACT
            }
            else{
            	samlRequest = "";
            	logger.error("SAML Request sent using an unknown binding (with POST)");
            }
        }
        else{
        	samlRequest = "";
        	logger.error("SAML Request sent using an unknown binding (with neither GET nor POST)");
        }
        
        // Show a simple page as response
    	response.setContentType("text/html");
		response.setStatus(HttpServletResponse.SC_OK);
		response.getWriter().println("<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.01 Transitional//EN\" \"http://www.w3.org/TR/html4/loose.dtd\"><html><head><title>SAML2Tester Mock IdP</title></head><body><p>The request has been handled and the following SAML Request was received:</p><br><br>"+samlRequest+"</body></html>");
		request.setHandled(true);
	}
}