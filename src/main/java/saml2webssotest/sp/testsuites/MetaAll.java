package saml2webssotest.sp.testsuites;

import java.util.ArrayList;
import java.util.List;
import saml2webssotest.common.TestSuite;

/**
 * This is a test suite that runs all other test suites. It is mainly added for convenience.
 * 
 * @author RiaasM
 *
 */
public class MetaAll extends SPTestSuite {
	@Override
	public List<TestSuite> getDependencies() {
		ArrayList<TestSuite> dependencies = new ArrayList<TestSuite>();
		dependencies.add(new SAML2Int());
		dependencies.add(new SAMLProf_WebSSO());
		dependencies.add(new SAMLBind());
		return dependencies;
	}
}
