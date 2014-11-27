package saml2webssotest.sp;

import java.lang.reflect.Type;

import org.w3c.dom.Document;

import saml2webssotest.common.SAMLUtil;

import com.google.gson.JsonDeserializationContext;
import com.google.gson.JsonDeserializer;
import com.google.gson.JsonElement;
import com.google.gson.JsonParseException;

public class DocumentDeserializer implements JsonDeserializer<Document> {

	@Override
	public Document deserialize(JsonElement json, Type typeOfT, JsonDeserializationContext context) throws JsonParseException {
		return SAMLUtil.fromXML(json.getAsString());
	}

}
