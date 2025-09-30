package sh.libre.scim.core;

import java.util.HashMap;
import java.util.Map;

import jakarta.persistence.EntityManager;
import jakarta.persistence.NoResultException;
import jakarta.ws.rs.ProcessingException;

import de.captaingoldfish.scim.sdk.client.ScimClientConfig;
import de.captaingoldfish.scim.sdk.client.ScimRequestBuilder;
import de.captaingoldfish.scim.sdk.client.http.BasicAuth;
import de.captaingoldfish.scim.sdk.client.response.ServerResponse;
import de.captaingoldfish.scim.sdk.common.exceptions.ResponseException;
import de.captaingoldfish.scim.sdk.common.resources.ResourceNode;
import de.captaingoldfish.scim.sdk.common.response.ListResponse;

import org.jboss.logging.Logger;
import org.keycloak.component.ComponentModel;
import org.keycloak.connections.jpa.JpaConnectionProvider;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RoleMapperModel;
import org.keycloak.storage.user.SynchronizationResult;

import com.google.common.net.HttpHeaders;

import io.github.resilience4j.core.IntervalFunction;
import io.github.resilience4j.retry.RetryConfig;
import io.github.resilience4j.retry.RetryRegistry;


public class ScimClient {
    final protected Logger LOGGER = Logger.getLogger(ScimClient.class);
    final protected ScimRequestBuilder scimRequestBuilder;
    final protected RetryRegistry registry;
    final protected KeycloakSession session;
    final protected String contentType;
    final protected ComponentModel model;
    final protected String scimApplicationBaseUrl;
    final protected Map<String, String> defaultHeaders;
    final protected Map<String, String> expectedResponseHeaders;

    public ScimClient(ComponentModel model, KeycloakSession session) {
        this.model = model;
        this.contentType = model.get("content-type");
        this.session = session;
        this.scimApplicationBaseUrl = model.get("endpoint");
        this.defaultHeaders = new HashMap<>();
        this.expectedResponseHeaders = new HashMap<>();

        switch (model.get("auth-mode")) {
            case "BEARER":
                defaultHeaders.put(HttpHeaders.AUTHORIZATION,
                    BearerAuthentication(model.get("auth-bearer-scheme"),
                                         model.get("auth-pass")));
                break;
            case "BASIC_AUTH":
                defaultHeaders.put(HttpHeaders.AUTHORIZATION,
                    BasicAuthentication(model.get("auth-user"),
                                        model.get("auth-pass")));
                break;
        }

        defaultHeaders.put(HttpHeaders.CONTENT_TYPE, contentType);

        scimRequestBuilder = new ScimRequestBuilder(scimApplicationBaseUrl, genScimClientConfig());

        RetryConfig retryConfig = RetryConfig.custom()
            .maxAttempts(10)
            .intervalFunction(IntervalFunction.ofExponentialBackoff())
            .retryExceptions(ProcessingException.class)
            .build();

        registry = RetryRegistry.of(retryConfig);
    }

    protected String BasicAuthentication(String username, String password) {
        return  BasicAuth.builder()
        .username(model.get(username))
        .password(model.get(password))
        .build()
        .getAuthorizationHeaderValue();
    }

    protected ScimClientConfig genScimClientConfig() {
        return ScimClientConfig.builder()
        .httpHeaders(defaultHeaders)
        .connectTimeout(5)
        .requestTimeout(5)
        .socketTimeout(5)
        .expectedHttpResponseHeaders(expectedResponseHeaders)
        .hostnameVerifier((s, sslSession) -> true)
        .build();
    }

    protected String BearerAuthentication(String prefix, String token) {
        return prefix + " " + token ;
    }

    protected String genScimUrl(String scimEndpoint, String resourcePath) {
        return "%s/%s/%s".formatted(scimApplicationBaseUrl,
                scimEndpoint,
                resourcePath);
    }

    /**
     * Custom success check that accepts both 200 and 201 as successful responses
     * This handles SCIM servers that return 200 instead of 201 for resource creation
     */
    protected <S extends ResourceNode> boolean isSuccessfulResponse(ServerResponse<S> response) {
        int statusCode = response.getHttpStatus();
        // Accept both 200 OK and 201 Created as successful responses
        return response.isSuccess() || statusCode == 200;
    }


    protected EntityManager getEM() {
        return session.getProvider(JpaConnectionProvider.class).getEntityManager();
    }

    protected String getRealmId() {
        return session.getContext().getRealm().getId();
    }

    protected <M extends RoleMapperModel, S extends ResourceNode, A extends Adapter<M, S>> A getAdapter(
            Class<A> aClass) {
        try {
            return aClass.getDeclaredConstructor(KeycloakSession.class, String.class)
                    .newInstance(session, this.model.getId());
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public <M extends RoleMapperModel, S extends ResourceNode, A extends Adapter<M, S>> void create(Class<A> aClass,
            M kcModel) {
        var adapter = getAdapter(aClass);
        adapter.apply(kcModel);
        if (adapter.skip) {
            return;
        }
        // If mapping exist then it was created by import so skip.
        if (!adapter.query("findById", adapter.getId()).getResultList().isEmpty()) {
            LOGGER.infof("[create] %s with ID %s already exists on the target, skipping", adapter.getType(), adapter.getId());
            return;
        }

        var retry = registry.retry("create-" + adapter.getId());
        var response = retry.executeSupplier(() -> {
            return scimRequestBuilder
            .create(adapter.getResourceClass(), ("/" + adapter.getSCIMEndpoint()).formatted())
            .setResource(adapter.toSCIM(false))
            .sendRequest();
        });

        // Custom success check - accept both 200 and 201 as successful responses
        if (!isSuccessfulResponse(response)){
            LOGGER.errorf("[create] Failed to create %s with ID %s and external ID %s. Received response (%s): %s", adapter.getType(), adapter.getId(), adapter.getExternalId(), response.getHttpStatus(), response.getResponseBody());
            return;
        }

        adapter.apply(response.getResource(adapter.getResourceClass()));
        var mapping = adapter.saveMapping();
        LOGGER.infof("[create] Created %s with ID %s and external ID %s", mapping.getType(), mapping.getId(), mapping.getExternalId());
    };

    public <M extends RoleMapperModel, S extends ResourceNode, A extends Adapter<M, S>> void replace(Class<A> aClass,
            M kcModel) {
        var adapter = getAdapter(aClass);
        try {
            adapter.apply(kcModel);
            if (adapter.skip) {
                return;
            }
            var resource = adapter.query("findById", adapter.getId()).getSingleResult();
            adapter.apply(resource);
            String url = genScimUrl(adapter.getSCIMEndpoint(), adapter.getExternalId());
            var retry = registry.retry("replace-" + adapter.getId());
            ServerResponse<S> response = retry.executeSupplier(() -> {
                try {
                    LOGGER.info(adapter.getType());
                    if ((adapter.getType() == "Group" && this.model.get("group-patchOp", false))
                         || (adapter.getType() == "User" && this.model.get("user-patchOp", false))) {
                        return adapter.toPatchBuilder(scimRequestBuilder, url)
                                      .sendRequest();
                    }
                    else {
                        return scimRequestBuilder
                            .update(url, adapter.getResourceClass())
                            .setResource(adapter.toSCIM(false))
                            .sendRequest();
                    }
                } catch (ResponseException e) {
                    throw new RuntimeException(e);
                }
            });
            if (!isSuccessfulResponse(response)){
                LOGGER.warnf("[replace] Failed to update %s with ID %s. Received response (%s): %s", adapter.getType(), adapter.getId(), response.getHttpStatus(), response.getResponseBody());
            } else {
                LOGGER.infof("[replace] Updated %s with ID %s and external ID %s", adapter.getType(), adapter.getId(), adapter.getExternalId());
            }
        } catch (NoResultException e) {
            LOGGER.warnf("failed to replace resource %s, scim mapping not found", adapter.getId());
        } catch (Exception e) {
            LOGGER.error(e);
        }
    }

    public <M extends RoleMapperModel, S extends ResourceNode, A extends Adapter<M, S>> void delete(Class<A> aClass,
            String id) {
        var adapter = getAdapter(aClass);
        adapter.setId(id);

        try {
            var resource = adapter.query("findById", adapter.getId()).getSingleResult();
            adapter.apply(resource);

            var retry = registry.retry("delete-" + id);

            ServerResponse<S> response = retry.executeSupplier(() -> {
                try {
                    return scimRequestBuilder.delete(genScimUrl(adapter.getSCIMEndpoint(), adapter.getExternalId()),
                                                                adapter.getResourceClass())
                                             .sendRequest();
                } catch (ResponseException e) {
                    throw new RuntimeException(e);
                }
            });

            if (!isSuccessfulResponse(response)){
                LOGGER.warnf("[delete] Failed to delete %s with ID %s. Received response (%s): %s", adapter.getType(), adapter.getId(), response.getHttpStatus(), response.getResponseBody());
            } else {
                LOGGER.infof("[delete] Deleted %s with ID %s", adapter.getType(), adapter.getId());
            }

            getEM().remove(resource);

        } catch (NoResultException e) {
            LOGGER.warnf("Failed to delete resource %s, scim mapping not found", id);
        }
    }

    public <M extends RoleMapperModel, S extends ResourceNode, A extends Adapter<M, S>> void refreshResources(
            Class<A> aClass,
            SynchronizationResult syncRes) {
        LOGGER.info("Refresh resources");
        getAdapter(aClass).getResourceStream().forEach(resource -> {
            var adapter = getAdapter(aClass);
            adapter.apply(resource);
            LOGGER.infof("Reconciling local resource %s", adapter.getId());
            if (!adapter.skipRefresh()) {
                var mapping = adapter.getMapping();
                if (mapping == null) {
                    LOGGER.info("Creating it");
                    this.create(aClass, resource);
                } else {
                    LOGGER.info("Replacing it");
                    this.replace(aClass, resource);
                }
                syncRes.increaseUpdated();
            }
        });

    }

    public <M extends RoleMapperModel, S extends ResourceNode, A extends Adapter<M, S>> void importResources(
            Class<A> aClass, SynchronizationResult syncRes) {
        LOGGER.info("Import");
        try {
            var adapter = getAdapter(aClass);
            ServerResponse<ListResponse<S>> response  = scimRequestBuilder.list("url", adapter.getResourceClass()).get().sendRequest();
            ListResponse<S> resourceTypeListResponse = response.getResource();

            for (var resource : resourceTypeListResponse.getListedResources()) {
                try {
                    LOGGER.infof("Reconciling remote resource %s", resource);
                    adapter = getAdapter(aClass);
                    adapter.apply(resource);

                    var mapping = adapter.getMapping();
                    if (mapping != null) {
                        adapter.apply(mapping);
                        if (adapter.entityExists()) {
                            LOGGER.info("Valid mapping found, skipping");
                            continue;
                        } else {
                            LOGGER.info("Delete a dangling mapping");
                            adapter.deleteMapping();
                        }
                    }

                    var mapped = adapter.tryToMap();
                    if (mapped) {
                        LOGGER.info("Matched");
                        adapter.saveMapping();
                    } else {
                        switch (this.model.get("sync-import-action")) {
                            case "CREATE_LOCAL":
                                LOGGER.info("Create local resource");
                                try {
                                    adapter.createEntity();
                                    adapter.saveMapping();
                                    syncRes.increaseAdded();
                                } catch (Exception e) {
                                    LOGGER.error(e);
                                }
                                break;
                            case "DELETE_REMOTE":
                                LOGGER.info("Delete remote resource");
                                scimRequestBuilder
                                    .delete(genScimUrl(adapter.getSCIMEndpoint(),
                                                       resource.getId().get()),
                                                       adapter.getResourceClass())
                                    .sendRequest();
                                syncRes.increaseRemoved();
                                break;
                        }
                    }
                } catch (Exception e) {
                    LOGGER.error(e);
                    e.printStackTrace();
                    syncRes.increaseFailed();
                }
            }
        } catch (ResponseException e) {
            throw new RuntimeException(e);
        }
    }

    public <M extends RoleMapperModel, S extends ResourceNode, A extends Adapter<M, S>> void sync(Class<A> aClass,
            SynchronizationResult syncRes) {
        if (this.model.get("sync-import", false)) {
            this.importResources(aClass, syncRes);
        }
        if (this.model.get("sync-refresh", false)) {
            this.refreshResources(aClass, syncRes);
        }
    }

    public void close() {
        scimRequestBuilder.close();
    }
}
