/*
 *  Licensed to the Apache Software Foundation (ASF) under one
 *  or more contributor license agreements.  See the NOTICE file
 *  distributed with this work for additional information
 *  regarding copyright ownership.  The ASF licenses this file
 *  to you under the Apache License, Version 2.0 (the
 *  "License"); you may not use this file except in compliance
 *  with the License.  You may obtain a copy of the License at
 *
 *    https://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing,
 *  software distributed under the License is distributed on an
 *  "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *  KIND, either express or implied.  See the License for the
 *  specific language governing permissions and limitations
 *  under the License.
 */

/**
 * Copies the plugin's ACL domain classes to the project and updates
 * the security configuration with domain class names.
 * An optional package argument can be specified.
 *
 * @author <a href='mailto:burt@burtbeckwith.com'>Burt Beckwith</a>
 */

description 'Copies ACL domain classes to the project and updates security config', {
    usage 'grails s2-create-acl-domains [package]'
}

String packageName = args ? args[0] : 'grails.plugin.springsecurity.acl'
String packagePath = packageName.replace('.', '/')

['AclClass', 'AclEntry', 'AclObjectIdentity', 'AclSid'].each { String name ->
    render template: template('_' + name + '.groovy'),
           destination: file("grails-app/domain/${packagePath}/${name}.groovy"),
           overwrite: false
}

// Update application.groovy with domain class config
File configFile = file('grails-app/conf/application.groovy') as File
if (configFile.exists()) {
    String configText = configFile.text
    if (!configText.contains('acl.aclClass.className')) {
        configFile.withWriterAppend { writer ->
            writer.newLine()
            writer.writeLine '// Added by the Spring Security ACL plugin:'
            writer.writeLine "grails.plugin.springsecurity.acl.aclClass.className = '${packageName}.AclClass'"
            writer.writeLine "grails.plugin.springsecurity.acl.aclSid.className = '${packageName}.AclSid'"
            writer.writeLine "grails.plugin.springsecurity.acl.aclObjectIdentity.className = '${packageName}.AclObjectIdentity'"
            writer.writeLine "grails.plugin.springsecurity.acl.aclEntry.className = '${packageName}.AclEntry'"
        }
        println "Updated application.groovy with ACL domain class configuration"
    }
}

println "ACL domain classes generated in ${packagePath}/"
println "You can now customize them (e.g., add MultiTenant trait for multi-tenancy support)"
