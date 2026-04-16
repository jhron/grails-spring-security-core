package grails.plugin.springsecurity.acl

import grails.plugin.springsecurity.acl.trait.AclClassTrait
import grails.plugin.springsecurity.acl.trait.AclSidTrait
import grails.testing.mixin.integration.Integration
import spock.lang.Specification

@Integration
class AclDomainClassResolverSpec extends Specification {

    AclDomainClassResolver aclDomainClassResolver

    void 'resolver is initialized with default domain classes'() {
        expect:
        aclDomainClassResolver.aclClassDomainClass == DefaultAclClass
        aclDomainClassResolver.aclSidDomainClass == DefaultAclSid
        aclDomainClassResolver.aclObjectIdentityDomainClass == DefaultAclObjectIdentity
        aclDomainClassResolver.aclEntryDomainClass == DefaultAclEntry
    }

    void 'factory methods return instances implementing traits'() {
        when:
        def aclClass = aclDomainClassResolver.newAclClassInstance(className: 'com.example.Foo')
        def aclSid = aclDomainClassResolver.newAclSidInstance(sid: 'admin', principal: true)

        then:
        aclClass instanceof AclClassTrait
        aclClass.className == 'com.example.Foo'
        aclSid instanceof AclSidTrait
        aclSid.sid == 'admin'
        aclSid.principal == true
    }

    void 'criteria builders return functional criteria'() {
        expect:
        aclDomainClassResolver.createAclClassCriteria() != null
        aclDomainClassResolver.createAclSidCriteria() != null
        aclDomainClassResolver.createAclObjectIdentityCriteria() != null
        aclDomainClassResolver.createAclEntryCriteria() != null
    }
}
