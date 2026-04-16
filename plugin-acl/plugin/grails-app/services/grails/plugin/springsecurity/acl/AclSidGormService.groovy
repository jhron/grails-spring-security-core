package grails.plugin.springsecurity.acl

import grails.gorm.transactions.ReadOnly
import grails.gorm.transactions.Transactional
import grails.plugin.springsecurity.acl.trait.AclSidTrait
import groovy.util.logging.Slf4j
import org.springframework.context.MessageSource

@Slf4j
class AclSidGormService implements WarnErros {

    AclDomainClassResolver aclDomainClassResolver
    MessageSource messageSource

    @ReadOnly
    AclSidTrait findBySidAndPrincipal(String sidName, boolean principal) {
        aclDomainClassResolver.createAclSidCriteria()
            .eq('sid', sidName)
            .eq('principal', principal)
            .get() as AclSidTrait
    }

    @Transactional
    AclSidTrait saveBySidNameAndPrincipal(String sidName, boolean principal) {
        def aclSidInstance = aclDomainClassResolver.newAclSidInstance(
            sid: sidName, principal: principal)
        if (!aclSidInstance.save()) {
            log.error '{}', errorsBeanBeingSaved(messageSource, aclSidInstance)
        }
        aclSidInstance as AclSidTrait
    }
}
