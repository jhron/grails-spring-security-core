package grails.plugin.springsecurity.acl.trait

/**
 * Contract trait for AclEntry domain class.
 * Implement this trait in your custom domain class to use with the ACL plugin.
 *
 * Required properties in implementing class:
 * - int aceOrder
 * - int mask
 * - boolean granting
 * - boolean auditSuccess
 * - boolean auditFailure
 * - Object aclObjectIdentity (reference to AclObjectIdentityTrait implementation)
 * - Object sid (reference to AclSidTrait implementation)
 */
trait AclEntryTrait implements Serializable {

    abstract int getAceOrder()

    abstract int getMask()

    abstract boolean getGranting()

    abstract boolean getAuditSuccess()

    abstract boolean getAuditFailure()

    abstract Object getAclObjectIdentity()

    abstract Object getSid()
}
