package grails.plugin.springsecurity.acl.jdbc

import grails.plugin.springsecurity.acl.AclDomainClassResolver
import grails.plugin.springsecurity.acl.model.StubAclParent
import org.springframework.security.acls.domain.AccessControlEntryImpl
import org.springframework.security.acls.domain.AclAuthorizationStrategy
import org.springframework.security.acls.domain.AclImpl
import org.springframework.security.acls.domain.GrantedAuthoritySid
import org.springframework.security.acls.domain.ObjectIdentityImpl
import org.springframework.security.acls.domain.PermissionFactory
import org.springframework.security.acls.domain.PrincipalSid
import org.springframework.security.acls.jdbc.LookupStrategy
import org.springframework.security.acls.model.Acl
import org.springframework.security.acls.model.AclCache
import org.springframework.security.acls.model.MutableAcl
import org.springframework.security.acls.model.ObjectIdentity
import org.springframework.security.acls.model.Permission
import org.springframework.security.acls.model.PermissionGrantingStrategy
import org.springframework.security.acls.model.Sid
import org.springframework.util.Assert
import org.springframework.util.ReflectionUtils

import java.lang.reflect.Field

/**
 * GORM implementation of {@link LookupStrategy}. Ported from <code>BasicLookupStrategy</code>.
 *
 * @author <a href='mailto:burt@burtbeckwith.com'>Burt Beckwith</a>
 */
class GormAclLookupStrategy implements LookupStrategy {

    protected Field aceAclField

    /** Dependency injection for aclDomainClassResolver. */
    AclDomainClassResolver aclDomainClassResolver

    /** Dependency injection for aclAuthorizationStrategy. */
    AclAuthorizationStrategy aclAuthorizationStrategy

    /** Dependency injection for aclCache. */
    AclCache aclCache

    /** Dependency injection for permissionFactory. */
    PermissionFactory permissionFactory

    /** Dependency injection for permissionGrantingStrategy. */
    PermissionGrantingStrategy permissionGrantingStrategy

    int batchSize = 50

    GormAclLookupStrategy() {
        findAceAclField()
    }

    Map<ObjectIdentity, Acl> readAclsById(List<ObjectIdentity> objects, List<Sid> sids) {
        Map<ObjectIdentity, Acl> result = [:]
        Set<ObjectIdentity> currentBatchToLoad = []

        for (int i = 0; i < objects.size(); i++) {
            ObjectIdentity object = objects.get(i)
            boolean aclFound = result.containsKey(object)

            if (!aclFound) {
                Acl acl = aclCache.getFromCache(object)
                if (acl) {
                    Assert.state(acl.isSidLoaded(sids),
                        'Error: SID-filtered element detected when implementation does not perform SID filtering ' +
                        '- have you added something to the cache manually?')
                    result[acl.objectIdentity] = acl
                    aclFound = true
                }
            }

            if (!aclFound) {
                currentBatchToLoad << object
            }

            if (currentBatchToLoad.size() == batchSize || (i + 1) == objects.size()) {
                if (currentBatchToLoad) {
                    Map<ObjectIdentity, Acl> loadedBatch = lookupObjectIdentities(currentBatchToLoad, sids)
                    result.putAll loadedBatch
                    loadedBatch.values().each { aclCache.putInCache it }
                    currentBatchToLoad.clear()
                }
            }
        }

        result
    }

    protected Map<ObjectIdentity, Acl> lookupObjectIdentities(Collection<ObjectIdentity> objectIdentities, List<Sid> sids) {
        Assert.notEmpty objectIdentities, 'Must provide identities to lookup'

        Map<Serializable, Acl> acls = [:]

        Class aclOiClass = aclDomainClassResolver.aclObjectIdentityDomainClass
        List aclObjectIdentities = aclOiClass.withCriteria {
            createAlias 'aclClass', 'ac'
            or {
                for (ObjectIdentity objectIdentity in objectIdentities) {
                    and {
                        eq 'objectId', objectIdentity.identifier
                        eq 'ac.className', objectIdentity.type
                    }
                }
            }
            order 'objectId', 'asc'
        }

        unwrapProxies aclObjectIdentities

        Map aclObjectIdentityMap = findAcls(aclObjectIdentities)

        List parents = convertEntries(aclObjectIdentityMap, acls, sids)
        if (parents) {
            lookupParents acls, parents, sids
        }

        Map<ObjectIdentity, Acl> result = [:]
        for (Acl inputAcl in acls.values()) {
            Acl converted = convert(acls, inputAcl.id)
            result[converted.objectIdentity] = converted
        }

        result
    }

    protected void unwrapProxies(List aclObjectIdentities) {
        for (ListIterator iter = aclObjectIdentities.listIterator(); iter.hasNext();) {
            iter.set aclDomainClassResolver.unproxy(iter.next())
        }
    }

    protected Map findAcls(List aclObjectIdentities) {
        List entries
        if (aclObjectIdentities) {
            Class aclEntryClass = aclDomainClassResolver.aclEntryDomainClass
            entries = aclEntryClass.withCriteria {
                'in'('aclObjectIdentity', aclObjectIdentities)
                order 'aceOrder', 'asc'
            }
        }

        def map = [:]
        for (aclObjectIdentity in aclObjectIdentities) {
            map[aclObjectIdentity] = []
        }
        for (entry in entries) {
            map[entry.aclObjectIdentity] << entry
        }
        map
    }

    protected AclImpl convert(Map<Serializable, Acl> inputMap, Serializable currentIdentity) {
        Assert.notEmpty inputMap, 'InputMap required'
        Assert.notNull currentIdentity, 'CurrentIdentity required'

        Acl inputAcl = inputMap[currentIdentity]
        Assert.isInstanceOf AclImpl, inputAcl, 'The inputMap contained a non-AclImpl'

        Acl parent = inputAcl.parentAcl
        if (parent instanceof StubAclParent) {
            parent = convert(inputMap, parent.id)
        }

        AclImpl result = new AclImpl(inputAcl.objectIdentity, inputAcl.id,
            aclAuthorizationStrategy, permissionGrantingStrategy, parent, null,
            inputAcl.isEntriesInheriting(), inputAcl.owner)

        List acesNew = []
        for (AccessControlEntryImpl ace in inputAcl.@aces) {
            ReflectionUtils.setField aceAclField, ace, result
            acesNew << ace
        }
        result.@aces.clear()
        result.@aces.addAll acesNew

        result
    }

    protected List convertEntries(Map aclObjectIdentityMap, Map<Serializable, Acl> acls, List<Sid> sids) {
        List parents = []

        aclObjectIdentityMap.each { aclObjectIdentity, aclEntries ->
            createAcl acls, aclObjectIdentity, aclEntries

            if (!aclObjectIdentity.parent) return

            Serializable parentId = aclObjectIdentity.parent.id
            if (acls.containsKey(parentId)) return

            MutableAcl cached = aclCache.getFromCache(parentId)
            if (!cached || !cached.isSidLoaded(sids)) {
                parents << aclObjectIdentity.parent
            } else {
                acls[cached.id] = cached
            }
        }

        parents
    }

    protected void createAcl(Map<Serializable, Acl> acls, aclObjectIdentity, List entries) {
        Serializable id = aclObjectIdentity.id

        AclImpl acl = acls[id]
        if (!acl) {
            ObjectIdentity objectIdentity = new ObjectIdentityImpl(
                lookupClass(aclObjectIdentity.aclClass.className),
                aclObjectIdentity.objectId)
            Acl parentAcl
            if (aclObjectIdentity.parent) {
                parentAcl = new StubAclParent(aclObjectIdentity.parent.id)
            }

            def ownerSid = aclDomainClassResolver.unproxy(aclObjectIdentity.owner)
            Sid owner = ownerSid.principal ?
                new PrincipalSid(ownerSid.sid) :
                new GrantedAuthoritySid(ownerSid.sid)

            acl = new AclImpl(objectIdentity, id, aclAuthorizationStrategy, permissionGrantingStrategy,
                parentAcl, null, aclObjectIdentity.entriesInheriting, owner)
            acls[id] = acl
        }

        List aces = acl.@aces
        for (entry in entries) {
            def entrySid = aclDomainClassResolver.unproxy(entry.sid)
            String aceSid = entrySid?.sid
            if (aceSid) {
                Sid recipient = entrySid.principal ? new PrincipalSid(aceSid) : new GrantedAuthoritySid(aceSid)
                Permission permission = permissionFactory.buildFromMask(entry.mask)
                AccessControlEntryImpl ace = new AccessControlEntryImpl(entry.id, acl, recipient, permission,
                    entry.granting, entry.auditSuccess, entry.auditFailure)
                if (!aces.contains(ace)) {
                    aces << ace
                }
            }
        }
    }

    protected Class<?> lookupClass(String className) {
        Class.forName className, true, Thread.currentThread().contextClassLoader
    }

    protected void lookupParents(Map<Serializable, Acl> acls, Collection findNow, List<Sid> sids) {
        Assert.notNull acls, 'ACLs are required'
        Assert.notEmpty findNow, 'Items to find now required'

        Map aclObjectIdentityMap = findAcls(findNow as List)
        List parents = convertEntries(aclObjectIdentityMap, acls, sids)
        if (parents) {
            lookupParents acls, parents, sids
        }
    }

    protected void findAceAclField() {
        aceAclField = ReflectionUtils.findField(AccessControlEntryImpl, 'acl')
        aceAclField.accessible = true
    }
}
