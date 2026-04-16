package grails.plugin.springsecurity.acl

import grails.plugin.springsecurity.acl.trait.AclEntryTrait
import groovy.transform.EqualsAndHashCode
import groovy.transform.ToString

@EqualsAndHashCode(includes=['aclObjectIdentity', 'aceOrder', 'sid', 'mask',
                             'granting', 'auditSuccess', 'auditFailure'])
@ToString(excludes='version', includeNames=true)
class AclEntry implements AclEntryTrait {

    private static final long serialVersionUID = 1

    AclObjectIdentity aclObjectIdentity
    int aceOrder
    AclSid sid
    int mask
    boolean granting
    boolean auditSuccess
    boolean auditFailure

    static mapping = {
        version false
        sid column: 'sid'
        aclObjectIdentity column: 'acl_object_identity'
    }

    static constraints = {
        aceOrder unique: 'aclObjectIdentity'
    }
}
