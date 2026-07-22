package grails.plugin.springsecurity.acl

import grails.core.GrailsApplication
import grails.testing.mixin.integration.Integration
import spock.lang.Specification

import javax.sql.DataSource

/**
 * Pins the behavior of grails.plugin.springsecurity.acl.useDefaultDomainDefinitions:
 * the four Default* ACL domain classes are provided by the plugin descriptor
 * (providedArtefacts) only when the key is unset or true.
 *
 * With the default suite configuration this verifies the default path. Run with
 * the key set to false in application.groovy to verify the opt-out path: the
 * Default* domains must not be registered as artefacts, not be GORM-mapped and
 * none of the four acl_* tables may be created (this app defines no custom ACL
 * domains, so the tables can only come from the defaults).
 */
@Integration
class UseDefaultDomainDefinitionsSpec extends Specification {

    private static final List<String> DEFAULT_DOMAIN_CLASS_NAMES = [
        DefaultAclClass, DefaultAclSid, DefaultAclObjectIdentity, DefaultAclEntry
    ]*.name

    private static final List<String> DEFAULT_TABLE_NAMES = [
        'acl_class', 'acl_sid', 'acl_object_identity', 'acl_entry'
    ].asImmutable()

    GrailsApplication grailsApplication
    DataSource dataSource

    void 'Default* ACL domains are registered, mapped and have tables iff useDefaultDomainDefinitions'() {
        given:
        boolean useDefaults = grailsApplication.config.getProperty(
            'grails.plugin.springsecurity.acl.useDefaultDomainDefinitions', Boolean, true)
        List<String> domainArtefacts = grailsApplication.getArtefacts('Domain')*.clazz*.name
        List<String> mappedEntities = grailsApplication.mappingContext.persistentEntities*.name
        List<String> tables = []
        dataSource.connection.withCloseable { connection ->
            def rs = connection.metaData.getTables(null, null, '%', ['TABLE'] as String[])
            while (rs.next()) {
                tables << rs.getString('TABLE_NAME').toLowerCase()
            }
        }

        expect:
        DEFAULT_DOMAIN_CLASS_NAMES.every { String className ->
            domainArtefacts.contains(className) == useDefaults
        }
        DEFAULT_DOMAIN_CLASS_NAMES.every { String className ->
            mappedEntities.contains(className) == useDefaults
        }
        DEFAULT_TABLE_NAMES.every { String tableName ->
            tables.contains(tableName) == useDefaults
        }
    }
}
