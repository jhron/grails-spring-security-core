package grails.plugin.springsecurity.acl

import grails.gorm.dirty.checking.DirtyCheck
import grails.plugin.springsecurity.acl.trait.AclObjectIdentityTrait
import groovy.transform.EqualsAndHashCode
import groovy.transform.ToString

@DirtyCheck
@EqualsAndHashCode(includes=['aclClass', 'objectId'], callSuper=false)
@ToString(includeNames=true)
class DefaultAclObjectIdentity implements AclObjectIdentityTrait {

    private static final long serialVersionUID = 1

    DefaultAclClass aclClass
    DefaultAclObjectIdentity parent
    DefaultAclSid owner
    boolean entriesInheriting
    Long objectId

    static mapping = {
        version false
        aclClass column: 'object_id_class'
        owner column: 'owner_sid'
        parent column: 'parent_object'
        objectId column: 'object_id_identity'
    }

    static constraints = {
        objectId unique: 'aclClass'
        parent nullable: true
        owner nullable: true
    }
}
