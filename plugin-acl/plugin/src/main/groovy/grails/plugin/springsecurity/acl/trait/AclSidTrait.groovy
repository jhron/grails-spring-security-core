package grails.plugin.springsecurity.acl.trait

/**
 * Contract trait for AclSid (Security Identity) domain class.
 * Implement this trait in your custom domain class to use with the ACL plugin.
 *
 * Required properties in implementing class:
 * - String sid
 * - boolean principal
 */
trait AclSidTrait implements Serializable {

    abstract String getSid()

    abstract boolean getPrincipal()
}
