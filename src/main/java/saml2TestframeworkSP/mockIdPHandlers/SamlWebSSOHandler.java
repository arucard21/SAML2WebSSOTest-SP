package saml2TestframeworkSP.mockIdPHandlers;

import java.io.IOException;
import java.util.List;
import java.util.HashMap;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.eclipse.jetty.http.HttpHeader;
import org.eclipse.jetty.server.HttpChannel;
import org.eclipse.jetty.server.Request;
import org.eclipse.jetty.server.handler.AbstractHandler;
import org.eclipse.jetty.util.MultiMap;

import saml2TestframeworkCommon.SAMLUtil;
import saml2TestframeworkCommon.standardNames.SAMLValues;
import saml2TestframeworkSP.SPTestRunner;

public class SamlWebSSOHandler extends AbstractHandler{
	
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
		MultiMap<String> urlArguments = request.getQueryParameters();

        if (method.equalsIgnoreCase("GET")) {
            // retrieve the SAML Request and binding
            if (urlArguments.containsKey(SAMLValues.URLPARAM_SAMLREQUEST_REDIRECT)) {
            	SPTestRunner.setSamlRequestBinding(SAMLValues.BINDING_HTTP_REDIRECT);
                SPTestRunner.setSamlRequest(SAMLUtil.decodeSamlMessageForRedirect(urlArguments.getString("SAMLRequest"), SAMLValues.BINDING_HTTP_REDIRECT));
                System.out.println("Retrieved SAML Request");
            }
            else if (urlArguments.containsKey(SAMLValues.URLPARAM_SAMLARTIFACT)){
            	SPTestRunner.setSamlRequestBinding(SAMLValues.BINDING_HTTP_ARTIFACT);
                // TODO: implement for BINDING_HTTP_ARTIFACT
            }
        }
        else if (method.equalsIgnoreCase("POST")) {
            // get the POST variables
        	HashMap<String, String[]> postVars = (HashMap<String, String[]>) request.getParameterMap();
            
            if (postVars.containsKey(SAMLValues.URLPARAM_SAMLREQUEST_POST)){
            	SPTestRunner.setSamlRequestBinding(SAMLValues.BINDING_HTTP_POST);
            	String[] samlRequestArray = postVars.get(SAMLValues.URLPARAM_SAMLREQUEST_POST);
            	// there should be only one samlrequest parameter
            	if (samlRequestArray.length == 1){
            		SPTestRunner.setSamlRequest(SAMLUtil.decodeSamlMessageForRedirect(samlRequestArray[0], SAMLValues.BINDING_HTTP_POST));
            	}
            		
            }
            else if (postVars.containsKey(SAMLValues.URLPARAM_SAMLARTIFACT)){
            	SPTestRunner.setSamlRequestBinding(SAMLValues.BINDING_HTTP_ARTIFACT);
                // TODO: implement for BINDING_HTTP_ARTIFACT
            }
        }
        
        // check if you need to send a response
        String samlResponse = SPTestRunner.getSamlResponse();
        if (samlResponse != null && !samlResponse.isEmpty()){
        	List<String> samlBindings = SPTestRunner.getSamlSPBindings();
        	
        	if (samlBindings.contains(SAMLValues.BINDING_HTTP_POST)){
        		System.out.println("Using HTTP POST binding to send SAML Response");
        		response.setContentType("text/plain");
        		response.setStatus(HttpServletResponse.SC_OK);
        		response.getWriter().println("<p>HTTP POST binding should be used. This is done by the user agent in the test runner itself.");
        		request.setHandled(true);
        	}
        	else if (samlBindings.contains(SAMLValues.BINDING_HTTP_ARTIFACT)){
        		//TODO: implement artifact binding
        		System.err.println("Artifact Resolution not yet implemented");
        		/**
        		 * Configure the response for the artifact binding
        		 */
        		// respond with a 302 redirect
        		response.setStatus(HttpServletResponse.SC_FOUND);
        		// return to the ACS location, but without a response
        		response.setHeader(HttpHeader.LOCATION.asString(), SPTestRunner.getACSLocation(SAMLValues.BINDING_HTTP_POST));
        		// TODO the response should redirect to the location specified by the IdP's Artifact Resolution protocol
        		//String artifactID = "NotYetImplemented";
        		//response.setHeader(HttpHeader.LOCATION.asString(), "mockid url for artifact resolution"+"?SamlArt="+artifactID);
        		request.setHandled(true);
        	}
        	else{
        		System.err.println("Binding not supported by the Web SSO profile");
        		response.setContentType("text/plain");
        		response.setStatus(HttpServletResponse.SC_OK);
        		response.getWriter().println("<p>Binding not supported by the Web SSO profile");
        		request.setHandled(true);
        	}
        	
        }
        else{
            // send a simple, standard page as response
        	response.setContentType("text/plain");
    		response.setStatus(HttpServletResponse.SC_OK);
    		response.getWriter().println("<p>The request has been handled, but no response needed to be sent</p>");
    		request.setHandled(true);
        }
	}


}