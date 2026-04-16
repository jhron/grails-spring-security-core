package grails.plugin.springsecurity.acl.trait

/**
 * Contract trait for AclObjectIdentity domain class.
 * Implement this trait in your custom domain class to use with the ACL plugin.
 *
 * Required properties in implementing class:
 * - Serializable objectId
 * - boolean entriesInheriting
 * - Object aclClass (reference to AclClassTrait implementation)
 * - Object parent (nullable, reference to AclObjectIdentityTrait implementation)
 * - Object owner (nullable, reference to AclSidTrait implementation)
 */
trait AclObjectIdentityTrait implements Serializable {

    abstract Serializable getObjectId()

    abstract boolean getEntriesInheriting()

    abstract Object getAclClass()

    abstract Object getParent()

    abstract Object getOwner()
}
