package grails.plugin.springsecurity.acl

import grails.gorm.transactions.Rollback
import grails.testing.mixin.integration.Integration
import spock.lang.Specification

@Integration
@Rollback
class AclObjectIdentityGormServiceSpec extends Specification {

    AclObjectIdentityGormService aclObjectIdentityGormService

    void 'findAllByParentObjectIdAndParentAclClassName returns children of a given parent'() {
        given:
        def sid = new DefaultAclSid(sid: 'admin', principal: true).save(failOnError: true)
        def aclClass = new DefaultAclClass(className: 'com.example.Report').save(failOnError: true)
        def aclClass2 = new DefaultAclClass(className: 'com.example.Document').save(failOnError: true)

        def parent = new DefaultAclObjectIdentity(
            aclClass: aclClass, objectId: 100L, owner: sid, entriesInheriting: true
        ).save(failOnError: true)

        def child1 = new DefaultAclObjectIdentity(
            aclClass: aclClass, objectId: 101L, owner: sid, entriesInheriting: true, parent: parent
        ).save(failOnError: true)

        def child2 = new DefaultAclObjectIdentity(
            aclClass: aclClass, objectId: 102L, owner: sid, entriesInheriting: true, parent: parent
        ).save(failOnError: true)

        // unrelated — different parent class
        def unrelatedParent = new DefaultAclObjectIdentity(
            aclClass: aclClass2, objectId: 200L, owner: sid, entriesInheriting: true
        ).save(failOnError: true)

        def unrelatedChild = new DefaultAclObjectIdentity(
            aclClass: aclClass2, objectId: 201L, owner: sid, entriesInheriting: true, parent: unrelatedParent
        ).save(failOnError: true)

        DefaultAclObjectIdentity.withSession { it.flush(); it.clear() }

        when:
        List<DefaultAclObjectIdentity> result = aclObjectIdentityGormService
            .findAllByParentObjectIdAndParentAclClassName(100L, 'com.example.Report')

        then:
        result.size() == 2
        result*.objectId.sort() == [101L, 102L]
    }

    void 'findAllByParentObjectIdAndParentAclClassName returns empty list when no children'() {
        given:
        def sid = new DefaultAclSid(sid: 'admin', principal: true).save(failOnError: true)
        def aclClass = new DefaultAclClass(className: 'com.example.Report').save(failOnError: true)

        new DefaultAclObjectIdentity(
            aclClass: aclClass, objectId: 100L, owner: sid, entriesInheriting: true
        ).save(failOnError: true)

        DefaultAclObjectIdentity.withSession { it.flush(); it.clear() }

        when:
        List<DefaultAclObjectIdentity> result = aclObjectIdentityGormService
            .findAllByParentObjectIdAndParentAclClassName(100L, 'com.example.Report')

        then:
        result.isEmpty()
    }
}
