// SPDX-FileCopyrightText: LDSC contributors
//
// SPDX-License-Identifier: Apache-2.0

package lu.ldsc.http;

import jakarta.enterprise.context.ApplicationScoped;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.PathParam;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import lu.ldsc.dsp.CatalogService;
import lu.ldsc.dsp.CatalogService.Outcome;
import lu.ldsc.dsp.Dsp;
import lu.ldsc.dsp.Dsp.CatalogError;
import lu.ldsc.dsp.Dsp.CatalogRequestMessage;
import lu.ldsc.dsp.Dsp.Dataset;
import lu.ldsc.dsp.Dsp.Distribution;
import lu.ldsc.dsp.Dsp.Offer;
import lu.ldsc.dsp.Dsp.Rule;
import org.eclipse.microprofile.config.inject.ConfigProperty;

/** HTTPS binding adapter. */
@Path("/")
@ApplicationScoped
@Produces(MediaType.APPLICATION_JSON)
public class DspResource {
    private static final com.fasterxml.jackson.databind.ObjectMapper MAPPER = new com.fasterxml.jackson.databind.ObjectMapper()
            .configure(com.fasterxml.jackson.databind.DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
    private final CatalogService catalog;
    private final Dsp.VersionResponse versions;

    public DspResource(
            @ConfigProperty(name = "ldsc.participant-id", defaultValue = "did:web:localhost%3A8080") String participantId,
            @ConfigProperty(name = "ldsc.public-url", defaultValue = "http://localhost:8080") String publicUrl,
            @ConfigProperty(name = "ldsc.datasets", defaultValue = "dataset-1") String datasets) {
        String serviceId = "urn:ldsc:service:" + UUID.randomUUID();
        Map<String, Dataset> byId = new LinkedHashMap<>();
        for (String id : Arrays.stream(datasets.split(",")).map(String::trim).filter(s -> !s.isEmpty()).toList()) {
            byId.put(id, new Dataset(null, id, "Dataset",
                    List.of(new Offer(id + ":offer:use", "Offer", List.of(new Rule("use", List.of())))),
                    List.of(new Distribution("Distribution", "HttpData-PULL", serviceId))));
        }
        CatalogService.DatasetStore store = new CatalogService.DatasetStore() {
            @Override
            public List<Dataset> all() {
                return List.copyOf(byId.values());
            }

            @Override
            public Optional<Dataset> get(String id) {
                return Optional.ofNullable(byId.get(id));
            }
        };
        this.catalog = new CatalogService(store, "urn:ldsc:catalog:" + UUID.randomUUID(), participantId, serviceId,
                publicUrl + "/dsp/2025-1");
        this.versions = new Dsp.VersionResponse(List.of(
                new Dsp.ProtocolVersion(Dsp.VERSION, "/dsp/2025-1", "HTTPS", serviceId, "did:web")));
    }

    @GET
    @Path(".well-known/dspace-version")
    public Dsp.VersionResponse version() {
        return versions;
    }

    @GET
    @Path("health")
    @Produces(MediaType.TEXT_PLAIN)
    public String health() {
        return "ok";
    }

    @POST
    @Path("dsp/2025-1/catalog/request")
    public Response catalogRequest(String body) {
        CatalogRequestMessage msg;
        try {
            msg = MAPPER.readValue(body, CatalogRequestMessage.class);
        } catch (java.io.IOException | IllegalArgumentException e) {
            return Response.status(400).entity(CatalogError.of("400", "invalid message")).build();
        }
        return respond(catalog.request(msg));
    }

    @GET
    @Path("dsp/2025-1/catalog/datasets/{id}")
    public Response dataset(@PathParam("id") String id) {
        return respond(catalog.dataset(id));
    }

    private static <T> Response respond(Outcome<T> outcome) {
        return switch (outcome) {
            case Outcome.Ok<T> ok -> Response.ok(ok.body()).build();
            case Outcome.BadRequest<T> bad -> Response.status(400).entity(bad.error()).build();
            case Outcome.NotFound<T> nf -> Response.status(404).entity(nf.error()).build();
        };
    }

}
