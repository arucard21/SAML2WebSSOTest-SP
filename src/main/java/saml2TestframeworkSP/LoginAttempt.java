package saml2TestframeworkSP;
/**
 * The LoginAttempt object can be used to define a login attempt at an SP
 * 
 * You must define the Response message that should be sent to the SP to see how the SP handles this.
 */
public class LoginAttempt {

	private boolean spInitiated;
	private String response;
	
	/**
	 * Create the LoginAttempt object.
	 * 
	 * @param spInitiated specifies if the login attempt should be SP-initiated
	 * @param response is the SAML Response message that the mock IdP should send to the SP 
	 */
	public LoginAttempt(boolean spInitiated, String response){
		this.spInitiated = spInitiated;
		this.response = response;
	}
	
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
	public boolean isSPInitiated(){
		return this.spInitiated;
	}

	/**
	 * Get the Response message that should be sent to the SP
	 * 
	 * @return the response message that should be sent to the SP
	 */
	public String getResponse(){
		return this.response;
	}

}