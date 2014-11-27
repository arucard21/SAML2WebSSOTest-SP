package saml2webssotest.sp;

import java.lang.reflect.Type;
import java.util.ArrayList;

import saml2webssotest.common.FormInteraction;
import saml2webssotest.common.Interaction;
import saml2webssotest.common.LinkInteraction;
import saml2webssotest.common.StringPair;

import com.google.gson.JsonArray;
import com.google.gson.JsonDeserializationContext;
import com.google.gson.JsonDeserializer;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParseException;

public class InteractionDeserializer implements JsonDeserializer<Interaction> {

	@Override
	public Interaction deserialize(JsonElement json, Type typeOfT, JsonDeserializationContext context) throws JsonParseException {
		JsonObject interactionJSON = json.getAsJsonObject();
		String type = interactionJSON.get("interactionType").getAsString();
		if (type.equalsIgnoreCase("link")){
			LinkInteraction interaction = new LinkInteraction(
					interactionJSON.get("lookupAttribute").getAsString(), 
					interactionJSON.get("lookupValue").getAsString());
			return interaction;
		}
		else if (type.equalsIgnoreCase("form")){
			FormInteraction interaction = (FormInteraction) new FormInteraction(
					interactionJSON.get("lookupAttribute").getAsString(), 
					interactionJSON.get("lookupValue").getAsString());
			interaction.setSubmitName(interactionJSON.get("submitName").getAsString());
			JsonArray inputsJSON = interactionJSON.get("inputs").getAsJsonArray();
			ArrayList<StringPair> inputs = new ArrayList<StringPair>();
			for (JsonElement inputJSON : inputsJSON){
				StringPair input = new StringPair(
						inputJSON.getAsJsonObject().get("name").getAsString(), 
						inputJSON.getAsJsonObject().get("value").getAsString());
				inputs.add(input);
			}
			interaction.setInputs(inputs);
			return interaction;
		}
		else{
			Interaction interaction = new Interaction(
					interactionJSON.get("lookupAttribute").getAsString(), 
					interactionJSON.get("lookupValue").getAsString());
			return interaction;
		}
	}
}
