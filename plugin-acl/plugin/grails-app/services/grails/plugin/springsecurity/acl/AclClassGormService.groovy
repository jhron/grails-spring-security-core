package grails.plugin.springsecurity.acl

import grails.gorm.transactions.ReadOnly
import grails.plugin.springsecurity.acl.trait.AclClassTrait

class AclClassGormService {

    AclDomainClassResolver aclDomainClassResolver

    @ReadOnly
    AclClassTrait findByClassName(String classNameParam) {
        aclDomainClassResolver.createAclClassCriteria()
            .eq('className', classNameParam)
            .get() as AclClassTrait
    }
}
