package grails.plugin.springsecurity.acl.trait

/**
 * Contract trait for AclClass domain class.
 * Implement this trait in your custom domain class to use with the ACL plugin.
 *
 * Required properties in implementing class:
 * - String className
 */
trait AclClassTrait implements Serializable {

    abstract String getClassName()
}
