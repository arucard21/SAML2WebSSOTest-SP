package saml2tester.sp;
/**
 * The LoginAttempt interface can be used to create classes that define a login attempt at an SP
 * 
 * You must define the Response message that should be sent to the SP to see how the SP handles this. This
 * should be done in the getResponse() method where you can make use of the Authentication Request that was
 * sent. Note that the request will be null when the login attempt is not SP-initiated
 *  
 */
public interface LoginAttempt {
	/**
	 * Determine whether the login attempt should be SP-initiated. If SP-initiated, the login attempt should start at the SP and
	 * the SP should send an authentication request before the mock IdP should send a Response (which can be retrieved with the
	 * getResponse() method).
	 * 
	 * Note that when SP-initiated login is used, you must set the request (and possibly binding) appropriately before retrieving
	 * the Response message.
	 *  
	 * @return true if the login attempt should be SP-initiated, false otherwise, i.e. when the login should be IdP-initiated
	 */
	public boolean isSPInitiated();

	/**
	 * Get the Response message that should be sent to the SP
	 * 
	 * @param request is the SAML Request that was sent by the 
	 * 		SP, or null if the login attempt was not SP-initiated
	 * @return the response message that should be sent to the SP
	 */
	public String getResponse(String request);
}