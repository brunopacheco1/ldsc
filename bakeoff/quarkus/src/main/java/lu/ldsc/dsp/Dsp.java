// SPDX-FileCopyrightText: LDSC contributors
//
// SPDX-License-Identifier: Apache-2.0

package lu.ldsc.dsp;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import io.quarkus.runtime.annotations.RegisterForReflection;
import java.util.List;
import java.util.Objects;

/** DSP 2025-1 message types, processed as plain JSON (allowed by the spec). */
public final class Dsp {
    public static final String CONTEXT = "https://w3id.org/dspace/2025/1/context.jsonld";
    public static final String VERSION = "2025-1";

    private Dsp() {}

    static void requireType(String actual, String expected) {
        if (!expected.equals(actual)) {
            throw new IllegalArgumentException("expected @type " + expected + ", got " + actual);
        }
    }

    static List<String> requireContext(List<String> context) {
        if (context == null || !context.contains(CONTEXT)) {
            throw new IllegalArgumentException("@context must contain " + CONTEXT);
        }
        return context;
    }

    @RegisterForReflection
    @JsonInclude(JsonInclude.Include.NON_NULL)
    public record ProtocolVersion(String version, String path, String binding, String serviceId, String identifierType) {}

    @RegisterForReflection
    public record VersionResponse(List<ProtocolVersion> protocolVersions) {}

    @RegisterForReflection
    public record CatalogRequestMessage(
            @JsonProperty("@context") List<String> context,
            @JsonProperty("@type") String type,
            List<Object> filter) {
        public CatalogRequestMessage {
            requireContext(context);
            requireType(type, "CatalogRequestMessage");
        }
    }

    @RegisterForReflection
    @JsonInclude(JsonInclude.Include.NON_EMPTY)
    public record Rule(String action, List<Object> constraint) {}

    @RegisterForReflection
    @JsonInclude(JsonInclude.Include.NON_EMPTY)
    public record Offer(@JsonProperty("@id") String id, @JsonProperty("@type") String type, List<Rule> permission) {}

    @RegisterForReflection
    public record Distribution(@JsonProperty("@type") String type, String format, String accessService) {}

    @RegisterForReflection
    @JsonInclude(JsonInclude.Include.NON_NULL)
    public record Dataset(
            @JsonProperty("@context") List<String> context,
            @JsonProperty("@id") String id,
            @JsonProperty("@type") String type,
            List<Offer> hasPolicy,
            List<Distribution> distribution) {
        public Dataset withContext() {
            return new Dataset(List.of(CONTEXT), id, type, hasPolicy, distribution);
        }
    }

    @RegisterForReflection
    public record DataService(
            @JsonProperty("@id") String id, @JsonProperty("@type") String type,
            @JsonProperty("endpointURL") String endpointUrl) {}

    @RegisterForReflection
    public record Catalog(
            @JsonProperty("@context") List<String> context,
            @JsonProperty("@id") String id,
            @JsonProperty("@type") String type,
            String participantId,
            List<DataService> service,
            List<Dataset> dataset) {}

    @RegisterForReflection
    public record CatalogError(
            @JsonProperty("@context") List<String> context,
            @JsonProperty("@type") String type,
            String code,
            List<String> reason) {
        public static CatalogError of(String code, String reason) {
            return new CatalogError(List.of(CONTEXT), "CatalogError", code, List.of(Objects.requireNonNull(reason)));
        }
    }
}
