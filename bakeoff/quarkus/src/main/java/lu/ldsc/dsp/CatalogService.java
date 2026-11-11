// SPDX-FileCopyrightText: LDSC contributors
//
// SPDX-License-Identifier: Apache-2.0

package lu.ldsc.dsp;

import java.util.List;
import java.util.Optional;
import lu.ldsc.dsp.Dsp.Catalog;
import lu.ldsc.dsp.Dsp.CatalogError;
import lu.ldsc.dsp.Dsp.CatalogRequestMessage;
import lu.ldsc.dsp.Dsp.DataService;
import lu.ldsc.dsp.Dsp.Dataset;

/** Catalog protocol (domain). Datasets come through the {@link DatasetStore} port. */
public final class CatalogService {

    /** Port: where the provider's datasets come from. */
    public interface DatasetStore {
        List<Dataset> all();

        Optional<Dataset> get(String id);
    }

    /** Outcome of a catalog operation, independent of transport. */
    public sealed interface Outcome<T> {
        record Ok<T>(T body) implements Outcome<T> {}

        record BadRequest<T>(CatalogError error) implements Outcome<T> {}

        record NotFound<T>(CatalogError error) implements Outcome<T> {}
    }

    private final DatasetStore store;
    private final String catalogId;
    private final String participantId;
    private final DataService service;

    public CatalogService(DatasetStore store, String catalogId, String participantId, String serviceId, String endpointUrl) {
        this.store = store;
        this.catalogId = catalogId;
        this.participantId = participantId;
        this.service = new DataService(serviceId, "DataService", endpointUrl);
    }

    public Outcome<Catalog> request(CatalogRequestMessage msg) {
        if (msg.filter() != null && !msg.filter().isEmpty()) {
            return new Outcome.BadRequest<>(CatalogError.of("400", "filter expressions are not supported"));
        }
        return new Outcome.Ok<>(new Catalog(List.of(Dsp.CONTEXT), catalogId, "Catalog", participantId, List.of(service), store.all()));
    }

    public Outcome<Dataset> dataset(String id) {
        return store.get(id)
                .<Outcome<Dataset>>map(d -> new Outcome.Ok<>(d.withContext()))
                .orElseGet(() -> new Outcome.NotFound<>(CatalogError.of("404", "dataset not found")));
    }
}
