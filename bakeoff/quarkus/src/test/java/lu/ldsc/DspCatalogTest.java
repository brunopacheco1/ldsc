// SPDX-FileCopyrightText: LDSC contributors
//
// SPDX-License-Identifier: Apache-2.0

package lu.ldsc;

import static io.restassured.RestAssured.given;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.networknt.schema.JsonSchema;
import com.networknt.schema.JsonSchemaFactory;
import com.networknt.schema.SchemaId;
import com.networknt.schema.SpecVersion;
import com.networknt.schema.ValidationMessage;
import io.quarkus.test.junit.QuarkusTest;
import io.quarkus.test.junit.QuarkusTestProfile;
import io.quarkus.test.junit.TestProfile;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.Test;

/** Checks responses against the official DSP 2025-1 JSON Schemas (same as the Rust tests). */
@QuarkusTest
@TestProfile(DspCatalogTest.Profile.class)
class DspCatalogTest {
    public static class Profile implements QuarkusTestProfile {
        @Override
        public Map<String, String> getConfigOverrides() {
            return Map.of("ldsc.datasets", "CAT0101,CAT0102");
        }
    }

    static final ObjectMapper M = new ObjectMapper();
    static final JsonSchemaFactory F = JsonSchemaFactory.getInstance(SpecVersion.VersionFlag.V201909,
            b -> b.schemaMappers(m -> m.mapPrefix("https://w3id.org/dspace/2025/1/common/", "classpath:schemas/")
                    .mapPrefix("https://w3id.org/dspace/2025/1/catalog/", "classpath:schemas/")
                    .mapPrefix("https://w3id.org/dspace/2025/1/negotiation/", "classpath:schemas/")));

    static Set<ValidationMessage> validate(String schema, String body) throws Exception {
        JsonSchema s = F.getSchema(SchemaId.class.getClassLoader().getResourceAsStream("schemas/" + schema));
        return s.validate(M.readTree(body));
    }

    static final String REQ = "{\"@context\":[\"https://w3id.org/dspace/2025/1/context.jsonld\"],\"@type\":\"CatalogRequestMessage\",\"filter\":[]}";

    @Test
    void met_01_01_version() throws Exception {
        String body = given().get("/.well-known/dspace-version").then().statusCode(200).extract().asString();
        assertEquals(Set.of(), validate("protocol-version-schema.json", body));
        assertEquals("2025-1", M.readTree(body).at("/protocolVersions/0/version").asText());
    }

    @Test
    void cat_01_01_catalog() throws Exception {
        String body = given().contentType("application/json").body(REQ).post("/dsp/2025-1/catalog/request")
                .then().statusCode(200).extract().asString();
        assertEquals(Set.of(), validate("catalog-schema.json", body));
        boolean found = false;
        for (JsonNode d : M.readTree(body).get("dataset")) {
            found |= d.get("@id").asText().equals("CAT0101");
        }
        assertTrue(found);
    }

    @Test
    void cat_01_02_dataset() throws Exception {
        String body = given().get("/dsp/2025-1/catalog/datasets/CAT0102").then().statusCode(200).extract().asString();
        assertEquals(Set.of(), validate("dataset-schema.json", body));
    }

    @Test
    void cat_01_03_not_found() throws Exception {
        String body = given().get("/dsp/2025-1/catalog/datasets/nope").then().statusCode(404).extract().asString();
        assertEquals(Set.of(), validate("catalog-error-schema.json", body));
    }

    @Test
    void bad_requests() throws Exception {
        for (String msg : new String[] {
            "{\"@context\":[\"https://w3id.org/dspace/2025/1/context.jsonld\"],\"@type\":\"Catalog\"}",
            "{\"@context\":[\"https://w3id.org/dspace/2025/1/context.jsonld\"],\"@type\":\"CatalogRequestMessage\",\"filter\":[{\"x\":1}]}",
            "{\"@type\":\"CatalogRequestMessage\"}"}) {
            String body = given().contentType("application/json").body(msg).post("/dsp/2025-1/catalog/request")
                    .then().statusCode(400).extract().asString();
            assertEquals(Set.of(), validate("catalog-error-schema.json", body), msg);
        }
    }

    @Test
    void schema_check_is_not_vacuous() throws Exception {
        String bad = "{\"@context\":[\"https://w3id.org/dspace/2025/1/context.jsonld\"],\"@id\":\"c\",\"@type\":\"Catalog\",\"participantId\":\"p\","
                + "\"dataset\":[{\"@id\":\"d\",\"distribution\":[{\"format\":\"f\",\"accessService\":\"s\"}]}]}";
        assertFalse(validate("catalog-schema.json", bad).isEmpty());
    }
}
