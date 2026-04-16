package grails.plugin.springsecurity.acl

import grails.gorm.transactions.Rollback
import grails.testing.mixin.integration.Integration
import spock.lang.Specification

@Integration
@Rollback
class AclObjectIdentityEqualsSpec extends Specification {

    void 'two AclObjectIdentity with same objectId but different aclClass are not equal'() {
        given:
        def aclClass1 = new AclClass(className: 'com.example.Report').save(failOnError: true)
        def aclClass2 = new AclClass(className: 'com.example.Document').save(failOnError: true)
        def sid = new AclSid(sid: 'admin', principal: true).save(failOnError: true)

        when:
        def oid1 = new AclObjectIdentity(
            aclClass: aclClass1, objectId: 42L, owner: sid, entriesInheriting: true
        ).save(failOnError: true)
        def oid2 = new AclObjectIdentity(
            aclClass: aclClass2, objectId: 42L, owner: sid, entriesInheriting: true
        ).save(failOnError: true)

        then:
        oid1 != oid2
        oid1.hashCode() != oid2.hashCode()
    }

    void 'two AclObjectIdentity with same objectId and same aclClass are equal'() {
        given:
        def aclClass = new AclClass(className: 'com.example.Report').save(failOnError: true)
        def sid = new AclSid(sid: 'admin', principal: true).save(failOnError: true)

        when:
        def oid1 = new AclObjectIdentity(
            aclClass: aclClass, objectId: 42L, owner: sid, entriesInheriting: true
        ).save(failOnError: true)

        then: 'same instance equals itself'
        oid1 == oid1

        when: 'fresh load from DB'
        AclObjectIdentity.withSession { it.flush(); it.clear() }
        def oid1Reloaded = AclObjectIdentity.get(oid1.id)

        then:
        oid1 == oid1Reloaded
        oid1.hashCode() == oid1Reloaded.hashCode()
    }
}
