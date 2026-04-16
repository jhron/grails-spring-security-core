package grails.plugin.springsecurity.acl

import grails.plugin.springsecurity.acl.trait.AclClassTrait
import groovy.transform.EqualsAndHashCode
import groovy.transform.ToString

@EqualsAndHashCode(includes='className')
@ToString(excludes='version', includeNames=true)
class AclClass implements AclClassTrait {

    private static final long serialVersionUID = 1

    String className

    static mapping = {
        className column: 'class'
        version false
    }

    static constraints = {
        className unique: true, blank: false
    }
}
