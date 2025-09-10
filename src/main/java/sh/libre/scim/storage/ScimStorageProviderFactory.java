package sh.libre.scim.storage;

import java.util.Date;
import java.util.List;

import jakarta.ws.rs.core.MediaType;

import org.jboss.logging.Logger;
import org.keycloak.component.ComponentModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.models.KeycloakSessionTask;
import org.keycloak.models.utils.KeycloakModelUtils;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.provider.ProviderConfigurationBuilder;
import org.keycloak.storage.UserStorageProviderFactory;
import org.keycloak.storage.UserStorageProviderModel;
import org.keycloak.storage.user.ImportSynchronization;
import org.keycloak.storage.user.SynchronizationResult;

import sh.libre.scim.core.GroupAdapter;
import sh.libre.scim.core.ScimDispatcher;
import sh.libre.scim.core.UserAdapter;

import de.captaingoldfish.scim.sdk.common.constants.HttpHeader;

public class ScimStorageProviderFactory
        implements UserStorageProviderFactory<ScimStorageProvider>, ImportSynchronization {
    final private Logger LOGGER = Logger.getLogger(ScimStorageProviderFactory.class);
    public final static String ID = "scim";
    protected static final List<ProviderConfigProperty> configMetadata;
    static {
        configMetadata = ProviderConfigurationBuilder.create()
                .property()
                .name("endpoint")
                .type(ProviderConfigProperty.STRING_TYPE)
                .label("SCIM 2.0 endpoint")
                .helpText("""
                        External SCIM 2.0 base \
                        URL (/ServiceProviderConfig  /Schemas and /ResourcesTypes should be accessible)\
                        """)
                .add()
                .property()
                .name("content-type")
                .type(ProviderConfigProperty.LIST_TYPE)
                .label("Endpoint content type")
                .helpText("Only used when endpoint doesn't support application/scim+json")
                .options(MediaType.APPLICATION_JSON.toString(), HttpHeader.SCIM_CONTENT_TYPE)
                .defaultValue(HttpHeader.SCIM_CONTENT_TYPE)
                .add()
                .property()
                .name("auth-mode")
                .type(ProviderConfigProperty.LIST_TYPE)
                .label("Auth mode")
                .helpText("Select the authorization mode")
                .options("NONE", "BASIC_AUTH", "BEARER")
                .defaultValue("NONE")
                .add()
                .property()
                .name("auth-bearer-scheme")
                .type(ProviderConfigProperty.STRING_TYPE)
                .label("Bearer Authentication Scheme")
                .helpText("The scheme to use when Bearer authentication is used (e.g. \"Bearer\")")
                .defaultValue("Bearer")
                .add()
                .property()
                .name("auth-user")
                .type(ProviderConfigProperty.STRING_TYPE)
                .label("Auth username")
                .helpText("Required for basic authentification.")
                .add()
                .property()
                .name("auth-pass")
                .type(ProviderConfigProperty.PASSWORD)
                .label("Auth password/token")
                .helpText("Password or token required for basic or bearer authentification.")
                .add()
                .property()
                .name("propagation-user")
                .type(ProviderConfigProperty.BOOLEAN_TYPE)
                .label("Enable user propagation")
                .defaultValue("true")
                .add()
                .property()
                .name("propagation-group")
                .type(ProviderConfigProperty.BOOLEAN_TYPE)
                .label("Enable group propagation")
                .defaultValue("true")
                .add()
                .property()
                .name("sync-import")
                .type(ProviderConfigProperty.BOOLEAN_TYPE)
                .label("Enable import during sync")
                .add()
                .property()
                .name("sync-import-action")
                .type(ProviderConfigProperty.LIST_TYPE)
                .label("Import action")
                .helpText("What to do when the user don\'t exists in Keycloak.")
                .options("NOTHING", "CREATE_LOCAL", "DELETE_REMOTE")
                .defaultValue("CREATE_LOCAL")
                .add()
                .property()
                .name("sync-refresh")
                .type(ProviderConfigProperty.BOOLEAN_TYPE)
                .label("Enable refresh during sync")
                .add()
                .property()
                .name("group-patchOp")
                .type(ProviderConfigProperty.BOOLEAN_TYPE)
                .label("Use patchOp for groups")
                .helpText("Only used when endpoint doesn't support putGroup API operation (full replace)")
                .defaultValue(false)
                .add()
                .property()
                .name("user-patchOp")
                .type(ProviderConfigProperty.BOOLEAN_TYPE)
                .label("Use patchOp for users")
                .helpText("Only used when endpoint doesn't support putUser API operation (full replace)")
                .defaultValue(false)
                .add()
                .build();
    }

    @Override
    public ScimStorageProvider create(KeycloakSession session, ComponentModel model) {
        LOGGER.info("create");
        return new ScimStorageProvider();
    }

    @Override
    public String getId() {
        return ID;
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return configMetadata;
    }

    @Override
    public SynchronizationResult sync(KeycloakSessionFactory sessionFactory, String realmId,
            UserStorageProviderModel model) {
        LOGGER.info("sync");
        var result = new SynchronizationResult();
        KeycloakModelUtils.runJobInTransaction(sessionFactory, new KeycloakSessionTask() {

            @Override
            public void run(KeycloakSession session) {
                var realm = session.realms().getRealm(realmId);
                session.getContext().setRealm(realm);
                var dispatcher = new ScimDispatcher(session);
                if ("true".equals(model.get("propagation-user"))) {
                    dispatcher.runOne(model, client -> client.sync(UserAdapter.class, result));
                }
                if ("true".equals(model.get("propagation-group"))) {
                    dispatcher.runOne(model, client -> client.sync(GroupAdapter.class, result));
                }
            }

        });

        return result;

    }

    @Override
    public SynchronizationResult syncSince(Date lastSync, KeycloakSessionFactory sessionFactory, String realmId,
            UserStorageProviderModel model) {
        return this.sync(sessionFactory, realmId, model);
    }

}
