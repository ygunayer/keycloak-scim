package sh.libre.scim.core;

import java.util.stream.Stream;

import jakarta.persistence.EntityManager;
import jakarta.persistence.NoResultException;
import jakarta.persistence.TypedQuery;
import jakarta.ws.rs.NotFoundException;

import org.jboss.logging.Logger;
import org.keycloak.connections.jpa.JpaConnectionProvider;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.RoleMapperModel;
import sh.libre.scim.jpa.ScimResource;
import de.captaingoldfish.scim.sdk.client.ScimRequestBuilder;
import de.captaingoldfish.scim.sdk.client.builder.PatchBuilder;
import de.captaingoldfish.scim.sdk.common.resources.ResourceNode;

public abstract class Adapter<M extends RoleMapperModel, S extends ResourceNode> {

    protected final Logger LOGGER;
    protected final String realmId;
    protected final RealmModel realm;
    protected final String type;
    protected final String componentId;
    protected final EntityManager em;
    protected final KeycloakSession session;

    protected String id;
    protected String externalId;
    protected Boolean skip = false;

    public Adapter(KeycloakSession session, String componentId, String type, Logger logger) {
        this.session = session;
        this.realm = session.getContext().getRealm();
        this.realmId = session.getContext().getRealm().getId();
        this.componentId = componentId;
        this.em = session.getProvider(JpaConnectionProvider.class).getEntityManager();
        this.type = type;
        this.LOGGER = logger;
    }

    public String getType() {
        return type;
    }

    public String getId() {
        return id;
    }

    public void setId(String id) {
        if (this.id == null) {
            this.id = id;
        }
    }

    public String getExternalId() {
        return externalId;
    }

    public void setExternalId(String externalId) {
        if (this.externalId == null) {
            this.externalId = externalId;
        }
    }

    public String getSCIMEndpoint() {
        return type + "s";
    }

    public ScimResource toMapping() {
        var entity = new ScimResource();
        entity.setType(type);
        entity.setId(id);
        entity.setExternalId(externalId);
        entity.setComponentId(componentId);
        entity.setRealmId(realmId);
        return entity;
    }

    public TypedQuery<ScimResource> query(String query, String id) {
        return query(query, id, type);
    }

    public TypedQuery<ScimResource> query(String query, String id, String type) {
        return this.em
                .createNamedQuery(query, ScimResource.class)
                .setParameter("type", type)
                .setParameter("realmId", realmId)
                .setParameter("componentId", componentId)
                .setParameter("id", id);
    }

    public ScimResource getMapping() {
        try {
            if (this.id != null) {
                return this.query("findById", id).getSingleResult();
            }
            if (this.externalId != null) {
                return this.query("findByExternalId", externalId).getSingleResult();
            }
        } catch (NotFoundException e) {
        } catch (NoResultException e) {
        } catch (Exception e) {
            LOGGER.error(e);
        }

        return null;
    }

    public ScimResource saveMapping() {
        var mapping = toMapping();
        this.em.persist(mapping);
        return mapping;
    }

    public void deleteMapping() {
        var mapping = this.em.merge(toMapping());
        this.em.remove(mapping);
    }

    public void apply(ScimResource mapping) {
        setId(mapping.getId());
        setExternalId(mapping.getExternalId());
    }

    public abstract void apply(M model);

    public abstract void apply(S resource);

    public abstract Class<S> getResourceClass();

    public abstract S toSCIM(Boolean addMeta);

    public abstract PatchBuilder<S> toPatchBuilder(ScimRequestBuilder scimRequestBuilder, String url);

    public abstract Boolean entityExists();

    public abstract Boolean tryToMap();

    public abstract void createEntity() throws Exception;

    public abstract Stream<M> getResourceStream();

    public abstract Boolean skipRefresh();
}
