package grails.plugin.springsecurity.acl

import grails.core.GrailsApplication
import grails.gorm.DetachedCriteria
import grails.plugin.springsecurity.SpringSecurityUtils
import grails.plugin.springsecurity.acl.trait.AclClassTrait
import grails.plugin.springsecurity.acl.trait.AclEntryTrait
import grails.plugin.springsecurity.acl.trait.AclObjectIdentityTrait
import grails.plugin.springsecurity.acl.trait.AclSidTrait
import groovy.util.logging.Slf4j

/**
 * Resolves and creates ACL domain class instances from configuration.
 * Allows users to configure custom domain classes that implement ACL traits.
 *
 * Registered as Spring bean 'aclDomainClassResolver' in
 * {@link SpringSecurityAclGrailsPlugin#doWithSpring}.
 */
@Slf4j
class AclDomainClassResolver {

    GrailsApplication grailsApplication

    private Class<? extends AclClassTrait> aclClassDomainClass
    private Class<? extends AclSidTrait> aclSidDomainClass
    private Class<? extends AclObjectIdentityTrait> aclObjectIdentityDomainClass
    private Class<? extends AclEntryTrait> aclEntryDomainClass

    /**
     * Initialize the resolver by loading configured domain classes.
     * Called from {@link SpringSecurityAclGrailsPlugin#doWithApplicationContext}.
     */
    void initialize() {
        def conf = SpringSecurityUtils.securityConfig

        String aclClassClassName = conf.acl.aclClass.className ?:
            'grails.plugin.springsecurity.acl.DefaultAclClass'
        String aclSidClassName = conf.acl.aclSid.className ?:
            'grails.plugin.springsecurity.acl.DefaultAclSid'
        String aclOiClassName = conf.acl.aclObjectIdentity.className ?:
            'grails.plugin.springsecurity.acl.DefaultAclObjectIdentity'
        String aclEntryClassName = conf.acl.aclEntry.className ?:
            'grails.plugin.springsecurity.acl.DefaultAclEntry'

        aclClassDomainClass = loadAndValidate(aclClassClassName, AclClassTrait)
        aclSidDomainClass = loadAndValidate(aclSidClassName, AclSidTrait)
        aclObjectIdentityDomainClass = loadAndValidate(aclOiClassName, AclObjectIdentityTrait)
        aclEntryDomainClass = loadAndValidate(aclEntryClassName, AclEntryTrait)

        log.debug 'AclDomainClassResolver initialized: AclClass={}, AclSid={}, ' +
            'AclObjectIdentity={}, AclEntry={}',
            aclClassDomainClass.name, aclSidDomainClass.name,
            aclObjectIdentityDomainClass.name, aclEntryDomainClass.name
    }

    private Class loadAndValidate(String className, Class requiredTrait) {
        Class clazz = Class.forName(className, true, grailsApplication.classLoader)
        if (!requiredTrait.isAssignableFrom(clazz)) {
            throw new IllegalArgumentException(
                "Configured ACL domain class '${className}' does not implement ${requiredTrait.name}")
        }
        clazz
    }

    // ========== Class getters ==========

    Class<? extends AclClassTrait> getAclClassDomainClass() { aclClassDomainClass }
    Class<? extends AclSidTrait> getAclSidDomainClass() { aclSidDomainClass }
    Class<? extends AclObjectIdentityTrait> getAclObjectIdentityDomainClass() { aclObjectIdentityDomainClass }
    Class<? extends AclEntryTrait> getAclEntryDomainClass() { aclEntryDomainClass }

    // ========== Factory methods ==========

    Object newAclClassInstance(Map props = [:]) {
        createInstance(aclClassDomainClass, props)
    }

    Object newAclSidInstance(Map props = [:]) {
        createInstance(aclSidDomainClass, props)
    }

    Object newAclObjectIdentityInstance(Map props = [:]) {
        createInstance(aclObjectIdentityDomainClass, props)
    }

    Object newAclEntryInstance(Map props = [:]) {
        createInstance(aclEntryDomainClass, props)
    }

    private Object createInstance(Class clazz, Map props) {
        def instance = clazz.getDeclaredConstructor().newInstance()
        props.each { k, v -> instance.setProperty(k as String, unproxy(v)) }
        instance
    }

    // ========== DetachedCriteria builders ==========

    DetachedCriteria createAclClassCriteria() {
        new DetachedCriteria(aclClassDomainClass)
    }

    DetachedCriteria createAclSidCriteria() {
        new DetachedCriteria(aclSidDomainClass)
    }

    DetachedCriteria createAclObjectIdentityCriteria() {
        new DetachedCriteria(aclObjectIdentityDomainClass)
    }

    DetachedCriteria createAclEntryCriteria() {
        new DetachedCriteria(aclEntryDomainClass)
    }

    // ========== GORM utility methods ==========

    Object getAclObjectIdentityById(Serializable id) {
        aclObjectIdentityDomainClass.invokeMethod('get', id)
    }

    Object loadAclObjectIdentityById(Serializable id) {
        aclObjectIdentityDomainClass.invokeMethod('load', id)
    }

    Object loadAclEntryById(Serializable id) {
        aclEntryDomainClass.invokeMethod('load', id)
    }

    void withAclEntrySession(Closure closure) {
        aclEntryDomainClass.invokeMethod('withSession', closure)
    }

    void withAclObjectIdentitySession(Closure closure) {
        aclObjectIdentityDomainClass.invokeMethod('withSession', closure)
    }

    // ========== Proxy unwrapping ==========

    Object unproxy(Object possibleProxy) {
        if (possibleProxy == null) return null

        try {
            def utilClass = Class.forName(
                'org.grails.orm.hibernate.cfg.GrailsHibernateUtil', true, grailsApplication.classLoader)
            def unwrapped = utilClass.invokeMethod('unwrapIfProxy', possibleProxy)
            if (unwrapped != null && unwrapped.getClass() != possibleProxy.getClass()) {
                return unwrapped
            }
        } catch (Exception ignored) {}

        try {
            def hibernateClass = Class.forName(
                'org.hibernate.Hibernate', true, grailsApplication.classLoader)
            return hibernateClass.invokeMethod('unproxy', possibleProxy)
        } catch (Exception ignored) {}

        try {
            def handlerClass = Class.forName(
                'org.grails.orm.hibernate.proxy.HibernateProxyHandler', true, grailsApplication.classLoader)
            def handler = handlerClass.getDeclaredConstructor().newInstance()
            return handler.invokeMethod('unwrapIfProxy', possibleProxy)
        } catch (Exception ignored) {}

        possibleProxy
    }
}
