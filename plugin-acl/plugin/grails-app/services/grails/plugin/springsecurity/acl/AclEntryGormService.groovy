package grails.plugin.springsecurity.acl

import grails.gorm.transactions.ReadOnly
import grails.plugin.springsecurity.acl.trait.AclEntryTrait
import grails.plugin.springsecurity.acl.trait.AclObjectIdentityTrait

class AclEntryGormService {

    AclDomainClassResolver aclDomainClassResolver

    @ReadOnly
    List<AclEntryTrait> findAllByAclObjectIdentity(AclObjectIdentityTrait aclObjectIdentity) {
        aclDomainClassResolver.createAclEntryCriteria().build {
            eq 'aclObjectIdentity', aclObjectIdentity
        }.list() as List<AclEntryTrait>
    }

    @ReadOnly
    List<Serializable> findAllIdByAclObjectIdentity(AclObjectIdentityTrait oid) {
        aclDomainClassResolver.createAclEntryCriteria().build {
            eq 'aclObjectIdentity', oid
        }.id().list() as List<Serializable>
    }
}
