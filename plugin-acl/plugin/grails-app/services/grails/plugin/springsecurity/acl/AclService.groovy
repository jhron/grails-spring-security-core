package grails.plugin.springsecurity.acl

import grails.gorm.transactions.ReadOnly
import grails.gorm.transactions.Transactional
import grails.plugin.springsecurity.acl.trait.AclClassTrait
import grails.plugin.springsecurity.acl.trait.AclObjectIdentityTrait
import grails.plugin.springsecurity.acl.trait.AclSidTrait
import groovy.util.logging.Slf4j
import org.springframework.context.MessageSource
import org.springframework.security.acls.domain.AccessControlEntryImpl
import org.springframework.security.acls.domain.GrantedAuthoritySid
import org.springframework.security.acls.domain.ObjectIdentityImpl
import org.springframework.security.acls.domain.PrincipalSid
import org.springframework.security.acls.jdbc.LookupStrategy
import org.springframework.security.acls.model.AccessControlEntry
import org.springframework.security.acls.model.Acl
import org.springframework.security.acls.model.AclCache
import org.springframework.security.acls.model.AlreadyExistsException
import org.springframework.security.acls.model.AuditableAccessControlEntry
import org.springframework.security.acls.model.ChildrenExistException
import org.springframework.security.acls.model.MutableAcl
import org.springframework.security.acls.model.MutableAclService
import org.springframework.security.acls.model.NotFoundException
import org.springframework.security.acls.model.ObjectIdentity
import org.springframework.security.acls.model.Sid
import org.springframework.security.core.context.SecurityContextHolder
import org.springframework.util.Assert

/**
 * GORM implementation of {@link org.springframework.security.acls.model.AclService} and {@link MutableAclService}.
 * Ported from <code>JdbcAclService</code> and <code>JdbcMutableAclService</code>.
 *
 * Individual methods are @Transactional since NotFoundException
 * is a runtime exception and will cause an unwanted transaction rollback
 *
 * @author <a href='mailto:burt@burtbeckwith.com'>Burt Beckwith</a>
 */
@Slf4j
class AclService implements MutableAclService, WarnErros {

    AclDomainClassResolver aclDomainClassResolver
    AclSidGormService aclSidGormService
    AclEntryGormService aclEntryGormService
    AclClassGormService aclClassGormService
    AclObjectIdentityGormService aclObjectIdentityGormService

    /** Dependency injection for aclLookupStrategy. */
    LookupStrategy aclLookupStrategy

    /** Dependency injection for aclCache. */
    AclCache aclCache

    /** Dependency injection for messageSource. */
    MessageSource messageSource

    @Transactional
    MutableAcl createAcl(ObjectIdentity objectIdentity) throws AlreadyExistsException {
        Assert.notNull objectIdentity, 'Object Identity required'

        if (aclObjectIdentityGormService.findByObjectIdentity(objectIdentity)) {
            throw new AlreadyExistsException("Object identity '$objectIdentity' already exists")
        }

        PrincipalSid sid = new PrincipalSid(SecurityContextHolder.context.authentication)
        createObjectIdentity objectIdentity, sid
        readAclById(objectIdentity) as MutableAcl
    }

    @Transactional
    protected def createObjectIdentity(ObjectIdentity object, Sid owner) {
        def ownerSid = createOrRetrieveSid(owner, true)
        def aclClass = createOrRetrieveClass(object.type, true)
        def aclObjectIdentity = aclDomainClassResolver.newAclObjectIdentityInstance(
                aclClass: aclClass,
                objectId: object.identifier as Long,
                owner: ownerSid,
                entriesInheriting: true)
        save(aclObjectIdentity)
    }

    @Transactional
    protected def createOrRetrieveSid(Sid sid, boolean allowCreate) {
        Assert.notNull sid, 'Sid required'

        String sidName
        boolean principal
        if (sid instanceof PrincipalSid) {
            sidName = sid.principal
            principal = true
        }
        else if (sid instanceof GrantedAuthoritySid) {
            sidName = sid.grantedAuthority
            principal = false
        }
        else {
            throw new IllegalArgumentException('Unsupported implementation of Sid')
        }

        def aclSid = aclSidGormService.findBySidAndPrincipal(sidName, principal)
        if (!aclSid && allowCreate) {
            aclSid = aclDomainClassResolver.newAclSidInstance(sid: sidName, principal: principal)
            save(aclSid)
        }
        aclSid
    }

    @Transactional
    protected def createOrRetrieveClass(String className, boolean allowCreate) {
        def aclClass = aclClassGormService.findByClassName(className)
        if (!aclClass && allowCreate) {
            aclClass = aclDomainClassResolver.newAclClassInstance(className: className)
            save(aclClass)
        }
        aclClass
    }

    @Transactional
    void deleteAcl(ObjectIdentity objectIdentity, boolean deleteChildren) throws ChildrenExistException {

        Assert.notNull objectIdentity, 'Object Identity required'
        Assert.notNull objectIdentity.identifier, "Object Identity doesn't provide an identifier"

        if (deleteChildren) {
            List<ObjectIdentity> children = findChildren(objectIdentity)
            if (children != null) {
                for (ObjectIdentity child : children) {
                    deleteAcl(child, true)
                }
            }
        }

        def oid = aclObjectIdentityGormService.findByObjectIdentity(objectIdentity)
        if (oid) {
            deleteEntries oid
            oid.delete(failOnError: true)
            aclDomainClassResolver.withAclEntrySession { it.flush() }
        }

        aclCache.evictFromCache objectIdentity
    }

    @Transactional
    protected void deleteEntries(AclObjectIdentityTrait oid) {
        if (oid) {
            List<Serializable> aclEntryIdList = aclEntryGormService.findAllIdByAclObjectIdentity(oid)
            List entries = aclEntryIdList.collect { Serializable id ->
                aclDomainClassResolver.loadAclEntryById(id)
            }
            deleteEntries(entries)
        }
    }

    @Transactional
    protected void deleteEntries(List entries) {
        log.debug 'Deleting entries: {}', entries
        if (entries) {
            for (entry in entries) {
                entry.delete(failOnError: true)
            }
            aclDomainClassResolver.withAclEntrySession { it.flush() }
        }
    }

    @Transactional
    MutableAcl updateAcl(MutableAcl acl) throws NotFoundException {
        Assert.notNull acl.id, "Object Identity doesn't provide an identifier"

        def aclObjectIdentity = aclObjectIdentityGormService.findByObjectIdentity(acl.objectIdentity)

        List existingAces = aclEntryGormService.findAllByAclObjectIdentity(aclObjectIdentity)

        List toDelete = existingAces.findAll { ace ->
            !acl.entries.find { AccessControlEntry entry ->
                entryEqual(ace, entry)
            }
        }

        List<AccessControlEntry> toCreate = acl.entries.findAll { AccessControlEntry entry ->
            !existingAces.find { ace ->
                entryEqual(ace, entry)
            }
        }

        Integer maxAceOrder = existingAces.max { it.aceOrder }?.aceOrder

        deleteEntries toDelete
        createEntries(acl, maxAceOrder, toCreate as List<AuditableAccessControlEntry>)
        updateObjectIdentity acl
        clearCacheIncludingChildren acl.objectIdentity

        readAclById(acl.objectIdentity) as MutableAcl
    }

    @Transactional
    protected void createEntries(MutableAcl acl, Integer maxOrder, List<AuditableAccessControlEntry> entries) {
        int i = maxOrder != null ? maxOrder + 1 : 0
        for (AuditableAccessControlEntry entry in entries) {
            Assert.isInstanceOf AccessControlEntryImpl, entry, 'Unknown ACE class'
            def aclEntryInstance = aclDomainClassResolver.newAclEntryInstance(
                    aclObjectIdentity: aclDomainClassResolver.loadAclObjectIdentityById(acl.id),
                    aceOrder: i++,
                    sid: createOrRetrieveSid(entry.sid, true),
                    mask: entry.permission.mask,
                    granting: entry.isGranting(),
                    auditSuccess: entry.isAuditSuccess(),
                    auditFailure: entry.isAuditFailure())
            save(aclEntryInstance)
        }
    }

    @Transactional
    protected void updateObjectIdentity(MutableAcl acl) {
        Assert.notNull acl.owner, "Owner is required in this implementation"

        def aclObjectIdentity = aclObjectIdentityGormService.findById(acl.id)

        def parent = null
        if (acl.parentAcl) {
            ObjectIdentity oii = acl.parentAcl.objectIdentity
            Assert.isInstanceOf ObjectIdentityImpl, oii, 'Implementation only supports ObjectIdentityImpl'
            parent = aclObjectIdentityGormService.findByObjectIdentity(oii)
        }
        aclObjectIdentity.parent = parent
        aclObjectIdentity.owner = createOrRetrieveSid(acl.owner, true)
        aclObjectIdentity.entriesInheriting = acl.isEntriesInheriting()
        save(aclObjectIdentity)
        aclDomainClassResolver.withAclObjectIdentitySession { it.flush() }
    }

    protected void clearCacheIncludingChildren(ObjectIdentity objectIdentity) {
        Assert.notNull objectIdentity, 'ObjectIdentity required'

        List<ObjectIdentity> children = findChildren(objectIdentity)
        for (ObjectIdentity child in children) {
            clearCacheIncludingChildren child
        }
        aclCache.evictFromCache objectIdentity
    }

    @ReadOnly
    List<ObjectIdentity> findChildren(ObjectIdentity parentOid) {
        List children = aclObjectIdentityGormService
            .findAllByParentObjectIdAndParentAclClassName(parentOid?.identifier as Long, parentOid.type)

        if (!children) {
            return []
        }

        children.collect { aoi ->
            new ObjectIdentityImpl(lookupClass(aoi.aclClass.className), aoi.objectId)
        }
    }

    protected Class<?> lookupClass(String className) {
        Class.forName className, true, Thread.currentThread().contextClassLoader
    }

    @ReadOnly(noRollbackFor = [NotFoundException])
    Acl readAclById(ObjectIdentity object) throws NotFoundException {
        readAclById object, null
    }

    @ReadOnly(noRollbackFor = [NotFoundException])
    Acl readAclById(ObjectIdentity object, List<Sid> sids) throws NotFoundException {
        Map<ObjectIdentity, Acl> map = readAclsById([object], sids)
        Assert.isTrue map.containsKey(object),
                "There should have been an Acl entry for ObjectIdentity $object"
        map[object]
    }

    @ReadOnly(noRollbackFor = [NotFoundException])
    Map<ObjectIdentity, Acl> readAclsById(List<ObjectIdentity> objects) throws NotFoundException {
        readAclsById objects, null
    }

    @ReadOnly(noRollbackFor = [NotFoundException])
    Map<ObjectIdentity, Acl> readAclsById(List<ObjectIdentity> objects, List<Sid> sids) throws NotFoundException {
        Map<ObjectIdentity, Acl> result = aclLookupStrategy.readAclsById(objects, sids)
        for (ObjectIdentity object in objects) {
            if (!result.containsKey(object)) {
                throw new NotFoundException("Unable to find ACL information for object identity '$object'")
            }
        }
        return result
    }

    @Transactional
    protected def save(bean) {
        if (!bean.save()) {
            log.warn errorsBeanBeingSaved(messageSource, bean)
        }
        bean
    }

    private static boolean entryEqual(ace, AccessControlEntry entry) {
        Sid sid = ace.sid.principal ? new PrincipalSid(ace.sid.sid) : new GrantedAuthoritySid(ace.sid.sid)
        return entry.permission.mask == ace.mask && entry.sid == sid && entry.granting == ace.granting
    }
}
