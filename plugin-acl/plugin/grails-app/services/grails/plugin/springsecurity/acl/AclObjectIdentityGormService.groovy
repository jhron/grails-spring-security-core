package grails.plugin.springsecurity.acl

import grails.gorm.transactions.ReadOnly
import grails.plugin.springsecurity.acl.trait.AclObjectIdentityTrait
import org.springframework.security.acls.model.ObjectIdentity

class AclObjectIdentityGormService {

    AclDomainClassResolver aclDomainClassResolver

    @ReadOnly
    List<AclObjectIdentityTrait> findAll() {
        aclDomainClassResolver.createAclObjectIdentityCriteria().list() as List<AclObjectIdentityTrait>
    }

    @ReadOnly
    AclObjectIdentityTrait findById(Serializable id) {
        aclDomainClassResolver.getAclObjectIdentityById(id) as AclObjectIdentityTrait
    }

    @ReadOnly
    List<AclObjectIdentityTrait> findAllByParentObjectIdAndParentAclClassName(Long objectId, String aclClassName) {
        aclDomainClassResolver.createAclObjectIdentityCriteria().build {
            parent {
                eq 'objectId', objectId
                aclClass {
                    eq 'className', aclClassName
                }
            }
        }.list() as List<AclObjectIdentityTrait>
    }

    @ReadOnly
    List<AclObjectIdentityTrait> findAllByObjectIdAndAclClassName(Serializable objectId, String aclClassName) {
        aclDomainClassResolver.createAclObjectIdentityCriteria().build {
            eq 'objectId', objectId
            aclClass {
                eq 'className', aclClassName
            }
        }.list() as List<AclObjectIdentityTrait>
    }

    @ReadOnly
    AclObjectIdentityTrait findByObjectIdentity(ObjectIdentity oid) {
        aclDomainClassResolver.createAclObjectIdentityCriteria().build {
            eq 'objectId', oid.identifier
            aclClass {
                eq 'className', oid.type
            }
        }.get() as AclObjectIdentityTrait
    }

    @ReadOnly
    AclObjectIdentityTrait findByObjectIdAndAclClassName(Serializable objectId, String aclClassName) {
        aclDomainClassResolver.createAclObjectIdentityCriteria().build {
            eq 'objectId', objectId
            aclClass {
                eq 'className', aclClassName
            }
        }.get() as AclObjectIdentityTrait
    }
}
