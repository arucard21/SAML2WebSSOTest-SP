package saml2TestframeworkCommon;

import java.util.List;

/**
 * This module contains the variables that represent the different status levels that a test can return. 
 * The meaning of each status level is described below.
 * 
 * UNKNOWN:		This status level is used as fallback. This status should never be shown and indicates that something is wrong.
 * INFORMATION:	This status level is used when nothing can be said about the status of the test. It allows you to return a 
 * 				neutral status, which might sometimes be required.
 * OK:			This status level is used when the test is successful.
 * WARNING:		This status level is used when a test failed, but the failure does not mean incompliance with the specification. 
 * 				This occurs when testing the recommendations of a specification instead of its requirements.
 * ERROR:		This status level is used when a test failed and its failure indicates incompliance with the specification.
 * CRITICAL:	This status level is used when the test itself failed. This is done whenever possible,  but the test could still 
 * 				throw an exception when something goes wrong and not show any status at all.
 * 
 * The STATUSCODE variable can be used to translate the status variable integers into a string that can be shown in the test results.
 * 
 * @author RiaasM
 *
 */
public enum TestStatus {
	UNKNOWN, INFORMATION, OK, WARNING, ERROR, CRITICAL;
	
	public static TestStatus getWorst(List<TestStatus> statusList){
		if (statusList.contains(TestStatus.CRITICAL))
			return TestStatus.CRITICAL;
		else if (statusList.contains(TestStatus.ERROR))
			return TestStatus.ERROR;
		else if (statusList.contains(TestStatus.WARNING))
			return TestStatus.WARNING;
		else if (statusList.contains(TestStatus.OK))
			return TestStatus.OK;
		else if (statusList.contains(TestStatus.INFORMATION))
			return TestStatus.INFORMATION;
		else
			return TestStatus.UNKNOWN;
	}
}
