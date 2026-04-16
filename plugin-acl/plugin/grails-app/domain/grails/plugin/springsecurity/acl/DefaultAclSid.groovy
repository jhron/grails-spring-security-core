package grails.plugin.springsecurity.acl

import grails.plugin.springsecurity.acl.trait.AclSidTrait
import groovy.transform.EqualsAndHashCode
import groovy.transform.ToString

@EqualsAndHashCode(includes=['sid', 'principal'])
@ToString(excludes='version', includeNames=true)
class DefaultAclSid implements AclSidTrait {

    private static final long serialVersionUID = 1

    String sid
    boolean principal

    static mapping = {
        version false
    }

    static constraints = {
        principal unique: 'sid'
        sid blank: false, size: 1..255
    }
}
