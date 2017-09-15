/*
 * Copyright © 2017 VMware, Inc.  All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the ?~@~\License?~@~]); you may not
 * use this file except in compliance with the License.  You may obtain a copy
 * of the License at http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an ?~@~\AS IS?~@~] BASIS, without
 * warranties or conditions of any kind, EITHER EXPRESS OR IMPLIED.  See the
 * License for the specific language governing permissions and limitations
 * under the License.
 */

#include "includes.h"

/*
    Connects to the LDAP server with the login and creates the folder structure
    for the policies if they don't already exit
    Folder Structure:
        Domain
            |--->System
                    |---->Policies
*/
DWORD
DirCliGPGroupPolicyInit(
    PCSTR pszLogin,
    PCSTR pszPassword,
    PCSTR pszHostname,
    PCSTR pszDomain,
    LDAP **ppLd)
{
    DWORD dwError = 0;
    PSTR pszDomainDN = NULL;
    PSTR pszSystemContainerDN = NULL;
    PSTR pszPoliciesContainerDN = NULL;
    BOOLEAN bExists = FALSE;
    LDAP *pLd = NULL;

    if (!ppLd)
    {
        dwError = ERROR_INVALID_PARAMETER;
        BAIL_ON_VMAFD_ERROR(dwError);
    }

    if (IsNullOrEmptyString(pszLogin)    |
        IsNullOrEmptyString(pszPassword) |
        IsNullOrEmptyString(pszHostname) |
        IsNullOrEmptyString(pszDomain)
        )
    {
        dwError = ERROR_INVALID_PARAMETER;
        BAIL_ON_VMAFD_ERROR(dwError);
    }

    dwError = DirCliLdapConnect(
                pszHostname,
                pszLogin,
                pszDomain,
                pszPassword,
                &pLd);
    BAIL_ON_VMAFD_ERROR(dwError);

    dwError = DirCliGetDomainDN(pszDomain, &pszDomainDN);
    BAIL_ON_VMAFD_ERROR(dwError);

    if(IsNullOrEmptyString(pszDomainDN))
    {
        dwError = ERROR_INVALID_PARAMETER;
        BAIL_ON_VMAFD_ERROR(dwError);
    }

    dwError = VmAfdAllocateStringPrintf(
                  &pszSystemContainerDN,
                  "cn=System,%s",
                  pszDomainDN);
    BAIL_ON_VMAFD_ERROR(dwError);

    // Check if the system folder already exists
    dwError = DirCliGPCheckContainer(
                pLd,
                pszSystemContainerDN,
                TRUE,
                &bExists);
    BAIL_ON_VMAFD_ERROR(dwError);

    if (!bExists)
    {
        dwError = DirCliGPCreateContainer(pLd, pszSystemContainerDN);
        BAIL_ON_VMAFD_ERROR(dwError);
    }

    if(IsNullOrEmptyString(pszSystemContainerDN))
    {
        dwError = ERROR_INVALID_PARAMETER;
        BAIL_ON_VMAFD_ERROR(dwError);
    }

    dwError = VmAfdAllocateStringPrintf(
                  &pszPoliciesContainerDN,
                  "cn=Policies,%s",
                  pszSystemContainerDN);
    BAIL_ON_VMAFD_ERROR(dwError);

    // Check if the policies folder already exists
    dwError = DirCliGPCheckContainer(
                  pLd,
                  pszPoliciesContainerDN,
                  FALSE,
                  &bExists);
    BAIL_ON_VMAFD_ERROR(dwError);

    if (!bExists)
    {
        dwError = DirCliGPCreateContainer(pLd, pszPoliciesContainerDN);
        BAIL_ON_VMAFD_ERROR(dwError);
    }

    *ppLd = pLd;

cleanup:
    VMAFD_SAFE_FREE_MEMORY(pszSystemContainerDN);
    VMAFD_SAFE_FREE_MEMORY(pszPoliciesContainerDN);
    VMAFD_SAFE_FREE_MEMORY(pszDomainDN);
    return dwError;

error:
    if (ppLd)
    {
        *ppLd = NULL;
    }
    if (pLd)
    {
        DirCliLdapClose(pLd);
    }
    goto cleanup;
}

/*
    Commits the new in-memory policy object to the server.
*/

DWORD
DirCliGPAddPolicyObject(
    LDAP *pLd,
    const DIR_GROUP_POLICY_OBJECT *pPolicyObject
    )
{
    DWORD dwError = 0;
    BOOLEAN bExists = FALSE;
    PSTR pszPoliciesContainerDN = NULL;
    PSTR pszPolicyDN = NULL;
    PSTR pszDomain = NULL;
    PSTR pszversionNumber = NULL;

    PSTR ppszObjectClassValues[] = {OBJECT_CLASS_GROUP_POLICY_CONTAINER, NULL};
    PDIR_GROUP_POLICY_OBJECT pPolicyObjectExisting = NULL;

    if (!pLd                                            ||
        !pPolicyObject                                  ||
        IsNullOrEmptyString(pPolicyObject->pszDomainDN) ||
        IsNullOrEmptyString(pPolicyObject->pszPolicyCN)
        )
    {
        dwError = ERROR_INVALID_PARAMETER;
        BAIL_ON_VMAFD_ERROR(dwError);
    }

    dwError = VmAfdAllocateStringPrintf(
                  &pszPoliciesContainerDN,
                  "cn=Policies,cn=System,%s",
                  pPolicyObject->pszDomainDN);
    BAIL_ON_VMAFD_ERROR(dwError);

    // Check if the policies container already exists
    dwError = DirCliGPCheckContainer(
                  pLd,
                  pszPoliciesContainerDN,
                  FALSE,
                  &bExists);
    BAIL_ON_VMAFD_ERROR(dwError);

    if (!bExists)
    {
        dwError = LDAP_NO_SUCH_OBJECT;
        BAIL_ON_VMAFD_ERROR(dwError);
    }

    dwError = DirCliLdapGetDomainFromDomainDN(pPolicyObject->pszDomainDN, &pszDomain);
    BAIL_ON_VMAFD_ERROR(dwError);

    // Check for duplicates in the policy names and reject duplicate entries
    dwError = DirCliGPFindPolicyByName(
                  pLd,
                  pPolicyObject->pszPolicyName,
                  pszDomain,
                  &pPolicyObjectExisting);
    if(dwError == ERROR_GP_NO_SUCH_POLICY)
    {
        dwError = 0;
    }
    BAIL_ON_VMAFD_ERROR(dwError);

    if (pPolicyObjectExisting)
    {
        dwError = ERROR_GP_DUPLICATE_POLICY_NAME;
        BAIL_ON_VMAFD_ERROR(dwError);
    }

//TODO: verify params in the beginning
    dwError = VmAfdAllocateStringPrintf(
                  &pszPolicyDN,
                  "cn=%s,cn=Policies,cn=System,%s",
                  pPolicyObject->pszPolicyCN,
                  pPolicyObject->pszDomainDN);
    BAIL_ON_VMAFD_ERROR(dwError);

    // Print the version number to a string
    dwError = VmAfdAllocateStringPrintf(
                 &pszversionNumber,
                 "%u",
                 pPolicyObject->dwVersion);
    BAIL_ON_VMAFD_ERROR(dwError);

    PSTR modv_displayName[] = {pPolicyObject->pszPolicyName, NULL};
    PSTR modv_gPCMachineExtensions[] = {pPolicyObject->pszPolicyJson, NULL};
    PSTR modv_cn[] = {pPolicyObject->pszPolicyCN, NULL};
    PSTR modv_versionNumber[] = {pszversionNumber, NULL};

    LDAPMod mod_object = {0};
    LDAPMod mod_cn = {0};
    LDAPMod mod_displayName = {0};
    LDAPMod mod_version = {0};
    LDAPMod mod_gPCMachineExtensionNames = {0};
    LDAPMod *mods[] = {
               &mod_object,
               &mod_cn,
               &mod_displayName,
               &mod_version,
               &mod_gPCMachineExtensionNames,
               NULL};

    mod_version.mod_op = LDAP_MOD_ADD;
    mod_version.mod_type = ATTR_NAME_VERSION_NUMBER;
    mod_version.mod_values = modv_versionNumber;

    mod_cn.mod_op = LDAP_MOD_ADD;
    mod_cn.mod_type = ATTR_NAME_CN;
    mod_cn.mod_values = modv_cn;

    mod_object.mod_op = LDAP_MOD_ADD;
    mod_object.mod_type = ATTR_NAME_OBJECTCLASS;
    mod_object.mod_values = ppszObjectClassValues;

    mod_displayName.mod_op = LDAP_MOD_ADD;
    mod_displayName.mod_type = ATTR_NAME_DISPLAYNAME;
    mod_displayName.mod_values = modv_displayName;

    mod_gPCMachineExtensionNames.mod_op = LDAP_MOD_ADD;
    mod_gPCMachineExtensionNames.mod_type = ATTR_NAME_GPCMACHINEEXTENSIONS;
    mod_gPCMachineExtensionNames.mod_values = modv_gPCMachineExtensions;

    dwError = ldap_add_ext_s(pLd, (PSTR)pszPolicyDN, mods, NULL, NULL);
    BAIL_ON_VMAFD_ERROR(dwError);

cleanup:
    VMAFD_SAFE_FREE_MEMORY(pszversionNumber);
    VMAFD_SAFE_FREE_MEMORY(pszPoliciesContainerDN);
    VMAFD_SAFE_FREE_MEMORY(pszPolicyDN);
    VMAFD_SAFE_FREE_MEMORY(pszDomain);

    if (pPolicyObjectExisting)
    {
        DirCliGPFreePolicyObject(pPolicyObjectExisting);
    }
    return dwError;

error:
    goto cleanup;
}

/*
    Commits the modified in-memory policy object to the server.
*/

DWORD
DirCliGPUpdatePolicyObject(
    LDAP *pLd,
    const PDIR_GROUP_POLICY_OBJECT pPolicyObject
    )
{
    DWORD dwError = 0;
    BOOLEAN bExists = FALSE;
    PSTR pszPoliciesContainerDN = NULL;
    PSTR pszPolicyDN = NULL;
    PSTR pszversionNumber = NULL;

    if (!pLd                                            ||
        !pPolicyObject                                  ||
        IsNullOrEmptyString(pPolicyObject->pszDomainDN) ||
        IsNullOrEmptyString(pPolicyObject->pszPolicyCN))
    {
        dwError = ERROR_INVALID_PARAMETER;
        BAIL_ON_VMAFD_ERROR(dwError);
    }

    dwError = VmAfdAllocateStringPrintf(
                  &pszPoliciesContainerDN,
                  "cn=Policies,cn=System,%s",
                  pPolicyObject->pszDomainDN);
    BAIL_ON_VMAFD_ERROR(dwError);

    // Check if the policies container exists
    dwError = DirCliGPCheckContainer(
                  pLd,
                  pszPoliciesContainerDN,
                  FALSE,
                  &bExists);
    BAIL_ON_VMAFD_ERROR(dwError);

    if (!bExists)
    {
        dwError = LDAP_NO_SUCH_OBJECT;
        BAIL_ON_VMAFD_ERROR(dwError);
    }

    dwError = VmAfdAllocateStringPrintf(
                 &pszPolicyDN,
                 "cn=%s,cn=Policies,cn=System,%s",
                 pPolicyObject->pszPolicyCN,
                 pPolicyObject->pszDomainDN);
    BAIL_ON_VMAFD_ERROR(dwError);

    fprintf(stdout, "Updating the policy object %s \n", pszPolicyDN);

    // Print the version number to a string
    dwError = VmAfdAllocateStringPrintf(
                  &pszversionNumber,
                  "%u",
                  pPolicyObject->dwVersion);
    BAIL_ON_VMAFD_ERROR(dwError);

    PSTR modv_displayName[] = {pPolicyObject->pszPolicyName, NULL};
    PSTR modv_gPCMachineExtensions[] = {pPolicyObject->pszPolicyJson, NULL};
    PSTR modv_versionNumber[] = {pszversionNumber, NULL};

    LDAPMod mod_displayName = {0};
    LDAPMod mod_gPCMachineExtensionNames = {0};
    LDAPMod mod_version = {0};
    LDAPMod *mods[] = {
             &mod_displayName,
             &mod_gPCMachineExtensionNames,
             &mod_version,
             NULL};

    mod_displayName.mod_op = LDAP_MOD_REPLACE;
    mod_displayName.mod_type = ATTR_NAME_DISPLAYNAME;
    mod_displayName.mod_values = modv_displayName;

    mod_gPCMachineExtensionNames.mod_op = LDAP_MOD_REPLACE;
    mod_gPCMachineExtensionNames.mod_type = ATTR_NAME_GPCMACHINEEXTENSIONS;
    mod_gPCMachineExtensionNames.mod_values = modv_gPCMachineExtensions;

    mod_version.mod_op = LDAP_MOD_REPLACE;
    mod_version.mod_type = ATTR_NAME_VERSION_NUMBER;
    mod_version.mod_values = modv_versionNumber;

    dwError = ldap_modify_ext_s(pLd, (PSTR)pszPolicyDN, mods, NULL, NULL);
    BAIL_ON_VMAFD_ERROR(dwError);

cleanup:
    VMAFD_SAFE_FREE_MEMORY(pszPoliciesContainerDN);
    VMAFD_SAFE_FREE_MEMORY(pszPolicyDN);
    VMAFD_SAFE_FREE_MEMORY(pszversionNumber);
    return dwError;

error:
    ldap_perror(pLd, NULL);
    fprintf(stderr, "Updating policy failed \n");
    goto cleanup;
}
/*
    Finds all the policies with the name and gives an in-memory policy object
   linked list. All the policy names are unique, hence it would return a single
   object for a given name. If the policy name is a wild character "*", it
   returns all the polices in the domain.
*/

DWORD
DirCliGPFindPolicyByName(
    LDAP *pLd,
    PCSTR pszPolicyName,
    PCSTR pszDomain,
    PDIR_GROUP_POLICY_OBJECT *ppPolicyObject
    )
{
    DWORD dwError = 0;
    PSTR ppszAttrs[] = {
             ATTR_NAME_DISPLAYNAME,
             ATTR_NAME_GPCMACHINEEXTENSIONS,
             ATTR_NAME_CN,
             ATTR_NAME_VERSION_NUMBER,
             NULL};
    PSTR pszFilter = NULL;
    PSTR pszSearchBase = NULL;
    PSTR pszPolicyDN = NULL;
    PSTR pszParentDN = NULL;
    PSTR pszversionNumber = NULL;
    LDAPMessage *pSearchRes = NULL;
    LDAPMessage *pEntry = NULL;
    BerElement *ber = NULL;
    PSTR pszAttr = NULL;
    PDIR_GROUP_POLICY_OBJECT pPolicyObject = NULL;
    PDIR_GROUP_POLICY_OBJECT pPolicyObjectHead = NULL;
    PDIR_GROUP_POLICY_OBJECT pTemp = NULL;

    DWORD dwCount = 0;

    if (!pLd || !ppPolicyObject)
    {
        dwError = ERROR_INVALID_PARAMETER;
        BAIL_ON_VMAFD_ERROR(dwError);
    }

    if (IsNullOrEmptyString(pszPolicyName) ||
        IsNullOrEmptyString(pszDomain))
    {
        dwError = ERROR_INVALID_PARAMETER;
        BAIL_ON_VMAFD_ERROR(dwError);
    }

    dwError = DirCliGetDomainDN(pszDomain, &pszSearchBase);
    BAIL_ON_VMAFD_ERROR(dwError);

    if(IsNullOrEmptyString(pszDomain))
    {
        dwError = ERROR_INVALID_PARAMETER;
        BAIL_ON_VMAFD_ERROR(dwError);
    }

    dwError = VmAfdAllocateStringPrintf(
                 &pszFilter,
                 "(&(%s=%s)(%s=%s))",
                 ATTR_NAME_OBJECTCLASS,
                 OBJECT_CLASS_GROUP_POLICY_CONTAINER,
                 ATTR_NAME_DISPLAYNAME,
                 pszPolicyName);
    BAIL_ON_VMAFD_ERROR(dwError);

    dwError = ldap_search_ext_s(
                 pLd,
                 pszSearchBase,
                 LDAP_SCOPE_SUBTREE,
                 pszFilter,
                 ppszAttrs,
                 FALSE, // attrs only
                 NULL,  // serverctrls
                 NULL,  // clientctrls
                 NULL,  // timeout
                 0,
                 &pSearchRes);
    BAIL_ON_VMAFD_ERROR(dwError);

    dwCount = ldap_count_entries(pLd, pSearchRes);

    if (!dwCount)
    {
        dwError = ERROR_GP_NO_SUCH_POLICY;
        BAIL_ON_VMAFD_ERROR(dwError);
    }

    for (pEntry = ldap_first_entry(pLd, pSearchRes); pEntry != NULL;
         pEntry = ldap_next_entry(pLd, pEntry))
    {
        dwError = VmAfdAllocateMemory(
                     sizeof(DIR_GROUP_POLICY_OBJECT),
                     (void **)&pPolicyObject);
        BAIL_ON_VMAFD_ERROR(dwError);

        pszPolicyDN = ldap_get_dn(pLd, pEntry);
        if (IsNullOrEmptyString(pszPolicyDN))
        {
            dwError = ERROR_INVALID_STATE;
            BAIL_ON_VMAFD_ERROR(dwError);
        }

        // Retrieve domainDN from PolicyDN, have to go up 3 levels to reach the root domain
        dwError = DirCliGPGetParentDN(pszPolicyDN, 3, &pszParentDN);
        BAIL_ON_VMAFD_ERROR(dwError);

        dwError = VmAfdAllocateStringA(pszParentDN,&pPolicyObject->pszDomainDN);
        BAIL_ON_VMAFD_ERROR(dwError);

        for (pszAttr = ldap_first_attribute(pLd, pEntry, &ber); pszAttr != NULL;
             pszAttr = ldap_next_attribute(pLd, pEntry, ber))
        {
            if (!VmAfdStringCompareA(pszAttr, ATTR_NAME_DISPLAYNAME, TRUE))
            {
                dwError = DirCliCopyQueryResultAttributeString(
                             pLd,
                             pEntry,
                             pszAttr,
                             FALSE,
                             &pPolicyObject->pszPolicyName);
                BAIL_ON_VMAFD_ERROR(dwError);
            }
            else if (!VmAfdStringCompareA(
                         pszAttr,
                         ATTR_NAME_GPCMACHINEEXTENSIONS,
                         FALSE))
            {

                dwError = DirCliCopyQueryResultAttributeString(
                              pLd,
                              pEntry,
                              pszAttr,
                              FALSE,
                              &pPolicyObject->pszPolicyJson);
                BAIL_ON_VMAFD_ERROR(dwError);
            }
            else if (!VmAfdStringCompareA(pszAttr, ATTR_NAME_CN, TRUE))
            {
                dwError = DirCliCopyQueryResultAttributeString(
                             pLd,
                             pEntry,
                             pszAttr,
                             FALSE,
                             &pPolicyObject->pszPolicyCN);
                BAIL_ON_VMAFD_ERROR(dwError);
            }
            else if (!VmAfdStringCompareA(
                         pszAttr, ATTR_NAME_VERSION_NUMBER, TRUE))
            {
                dwError = DirCliCopyQueryResultAttributeString(
                             pLd,
                             pEntry,
                             pszAttr,
                             FALSE,
                             &pszversionNumber);
                BAIL_ON_VMAFD_ERROR(dwError);

                pPolicyObject->dwVersion = atol(pszversionNumber);
            }
            else
            {
                dwError = ERROR_INVALID_STATE;
                BAIL_ON_VMAFD_ERROR(dwError);
            }

            // Free string being reused
            VMAFD_SAFE_FREE_MEMORY(pszAttr);
            VMAFD_SAFE_FREE_MEMORY(pszversionNumber);
        }

        if (!pPolicyObjectHead)
        {
            pPolicyObjectHead = pPolicyObject;
        }
        else
        {
            //Tail add Linked List
            pTemp = pPolicyObjectHead;
            while (pTemp && pTemp->pNext)
                pTemp = pTemp->pNext;
            pTemp->pNext = pPolicyObject;
        }
        pPolicyObject = NULL;

        if (ber)
        {
            ber_free(ber, 0);
            ber = NULL;
        }

        // Free string being reused
        VMAFD_SAFE_FREE_MEMORY(pszParentDN);
        VMAFD_SAFE_FREE_MEMORY(pszPolicyDN);
    }

    *ppPolicyObject = pPolicyObjectHead;

cleanup:
    if (pSearchRes)
    {
        ldap_msgfree(pSearchRes);
    }
    if (ber)
    {
        ber_free(ber, 0);
    }

    VMAFD_SAFE_FREE_MEMORY(pszAttr);
    VMAFD_SAFE_FREE_MEMORY(pszPolicyDN);
    VMAFD_SAFE_FREE_MEMORY(pszversionNumber);
    VMAFD_SAFE_FREE_MEMORY(pszSearchBase);
    VMAFD_SAFE_FREE_MEMORY(pszFilter);
    VMAFD_SAFE_FREE_MEMORY(pszParentDN);
    return dwError;

error:
    if (ppPolicyObject)
    {
        *ppPolicyObject = NULL;
    }
    if (pPolicyObjectHead)
    {
        DirCliGPFreePolicyObject(pPolicyObjectHead);
    }
    goto cleanup;
}

/*
    Lists all the policy links by exploring the root of the domain.
*/

DWORD
DirCliGPListPolicyLinks(LDAP *pLd)
{
    DWORD dwError = 0;
    PSTR ppszAttrs[] = {ATTR_NAME_GPLINK, NULL};
    PSTR pszFilter = NULL;
    PSTR pszSearchBase = NULL;
    PSTR pszObjectDN = NULL;
    LDAPMessage *pSearchRes = NULL;
    LDAPMessage *pEntry = NULL;
    BerElement *ber = NULL;
    PSTR pszAttr = NULL;
    DWORD dwCount = 0;
    PSTR pszPolicyName = NULL;
    PSTR pszgpLink = NULL;
    const char * pszPolicyDN = NULL;
    json_t *jsongpLinkArray = NULL;
    size_t index = 0;
    json_t *value = NULL;
    json_error_t *pError = NULL;

    if (!pLd)
    {
        dwError = ERROR_INVALID_PARAMETER;
        BAIL_ON_VMAFD_ERROR(dwError);
    }

    // Get the root domain name
    dwError = DirCliGetDefaultDomainName(pLd, &pszSearchBase);
    BAIL_ON_VMAFD_ERROR(dwError);

    // Check for OUs and Domains with gpLinks.
    dwError = VmAfdAllocateStringPrintf(
                  &pszFilter,
                  "(&(|(%s=%s)(%s=%s))(%s=*))",
                  ATTR_NAME_OBJECTCLASS,
                  OBJECT_CLASS_DOMAIN_DNS,
                  ATTR_NAME_OBJECTCLASS,
                  OBJECT_CLASS_ORGANIZATIONAL_UNIT,
                  ATTR_NAME_GPLINK);
    BAIL_ON_VMAFD_ERROR(dwError);

    dwError = ldap_search_ext_s(
                  pLd,
                  pszSearchBase,
                  LDAP_SCOPE_SUBTREE,
                  pszFilter,
                  ppszAttrs,
                  FALSE, // attrs only
                  NULL,  // serverctrls
                  NULL,  // clientctrls
                  NULL,  // timeout
                  0,
                  &pSearchRes);
    BAIL_ON_VMAFD_ERROR(dwError);

    dwCount = ldap_count_entries(pLd, pSearchRes);
    //fprintf(stdout, "The number of results are %d \n", dwCount);
    if (!dwCount)
    {
        dwError = ERROR_GP_NO_SUCH_POLICY;
        BAIL_ON_VMAFD_ERROR(dwError);
    }

    for (pEntry = ldap_first_entry(pLd, pSearchRes); pEntry != NULL;
         pEntry = ldap_next_entry(pLd, pEntry))
    {
        pszObjectDN = ldap_get_dn(pLd, pEntry);
        if (IsNullOrEmptyString(pszObjectDN))
        {
            dwError = ERROR_INVALID_STATE;
            BAIL_ON_VMAFD_ERROR(dwError);
        }

        pszAttr = ldap_first_attribute(pLd, pEntry, &ber);
        if (IsNullOrEmptyString(pszObjectDN))
        {
            dwError = ERROR_INVALID_STATE;
            BAIL_ON_VMAFD_ERROR(dwError);
        }

        if (!VmAfdStringCompareA(pszAttr, ATTR_NAME_GPLINK, TRUE))
        {
            dwError = DirCliCopyQueryResultAttributeString(
                         pLd,
                         pEntry,
                         pszAttr,
                         FALSE,
                         &pszgpLink);
            BAIL_ON_VMAFD_ERROR(dwError);

            fprintf(stdout, "\nDN = %s \n", pszObjectDN);
            fprintf(stdout, "Links:\n");

            // Parse the json and exact individual links
            jsongpLinkArray = json_loads(pszgpLink, 0, pError);
            if (!jsongpLinkArray)
            {
                dwError = ERROR_GP_GPLINK_JSON_ERROR;
                BAIL_ON_VMAFD_ERROR(dwError);
            }

            json_array_foreach(jsongpLinkArray, index, value)
            {
                pszPolicyDN = json_string_value(value);
                if (!pszPolicyDN)
                {
                    dwError = ERROR_GP_JSON_CONVERSION_ERROR;
                    BAIL_ON_VMAFD_ERROR(dwError);
                }
                //fprintf(stdout,"Policy name is %s \n",pszPolicyDN);
                dwError = DirCliGPGetPolicyNameFromPolicyDN(
                              pLd,
                              pszPolicyDN,
                              &pszPolicyName);
                BAIL_ON_VMAFD_ERROR(dwError);

                fprintf(stdout, "   %lu : %s \n", index + 1, pszPolicyName);
                // Reuse pointer, free it
                VMAFD_SAFE_FREE_MEMORY(pszPolicyName);
            }

            if (jsongpLinkArray)
            {
                json_decref(jsongpLinkArray);
                jsongpLinkArray = NULL;
            }

            // Reuse pointer, free it
            VMAFD_SAFE_FREE_MEMORY(pszgpLink);
        }
        else
        {
            dwError = ERROR_INVALID_STATE;
            BAIL_ON_VMAFD_ERROR(dwError);
        }

        if (ber)
        {
            ber_free(ber, 0);
            ber = NULL;
        }
        // Reuse the pointer, free it
        VMAFD_SAFE_FREE_MEMORY(pszObjectDN);
    }

cleanup:
    if (pSearchRes)
    {
        ldap_msgfree(pSearchRes);
    }
    if (jsongpLinkArray)
    {
        json_decref(jsongpLinkArray);
    }
    if (ber)
    {
        ber_free(ber, 0);
    }

    VMAFD_SAFE_FREE_MEMORY(pszSearchBase);
    VMAFD_SAFE_FREE_MEMORY(pszFilter);
    VMAFD_SAFE_FREE_MEMORY(pszAttr);
    VMAFD_SAFE_FREE_MEMORY(pError);
    VMAFD_SAFE_FREE_MEMORY(pszPolicyName);
    VMAFD_SAFE_FREE_MEMORY(pszgpLink);
    VMAFD_SAFE_FREE_MEMORY(pszObjectDN);
    return dwError;

error:
    ldap_perror(pLd, NULL);
    goto cleanup;
}

/*
    Retrieves policy name from the policy DN.
*/

DWORD
DirCliGPGetPolicyNameFromPolicyDN(
    LDAP *pLd,
    PCSTR pszPolicyDN,
    PSTR *ppszPolicyName
    )
{
    DWORD dwError = 0;
    PSTR ppszAttrs[] = {ATTR_NAME_DISPLAYNAME, NULL};
    PSTR pszFilter = NULL;
    PCSTR pszSearchBase = NULL;
    PSTR pszObjectDN = NULL;
    LDAPMessage *pSearchRes = NULL;
    LDAPMessage *pEntry = NULL;
    BerElement *ber = NULL;
    PSTR pszAttr = NULL;
    DWORD dwCount = 0;
    PSTR pszPolicyName = NULL;

    if (!pLd || IsNullOrEmptyString(pszPolicyDN) || !ppszPolicyName)
    {
        dwError = ERROR_INVALID_PARAMETER;
        BAIL_ON_VMAFD_ERROR(dwError);
    }

    // Get the root domain name
    pszSearchBase = pszPolicyDN;

    // Check for OUs and Domains with gpLinks.
    dwError = VmAfdAllocateStringPrintf(
                  &pszFilter,
                  "(&(%s=%s)(%s=*))",
                  ATTR_NAME_OBJECTCLASS,
                  OBJECT_CLASS_GROUP_POLICY_CONTAINER,
                  ATTR_NAME_DISPLAYNAME);
    BAIL_ON_VMAFD_ERROR(dwError);

    dwError = ldap_search_ext_s(
                  pLd,
                  pszSearchBase,
                  LDAP_SCOPE_BASE,
                  pszFilter,
                  ppszAttrs,
                  FALSE, // attrs only
                  NULL,  // serverctrls
                  NULL,  // clientctrls
                  NULL,  // timeout
                  0,
                  &pSearchRes);
    BAIL_ON_VMAFD_ERROR(dwError);

    dwCount = ldap_count_entries(pLd, pSearchRes);
    if (!dwCount)
    {
        dwError = ERROR_GP_NO_SUCH_POLICY;
        BAIL_ON_VMAFD_ERROR(dwError);
    }
    // Only one policy should exist
    if (dwCount > 1)
    {
        dwError = ERROR_INVALID_STATE;
        BAIL_ON_VMAFD_ERROR(dwError);
    }

    pEntry = ldap_first_entry(pLd, pSearchRes);
    if(!pEntry)
    {
        dwError = ERROR_INVALID_PARAMETER;
        BAIL_ON_VMAFD_ERROR(dwError);
    }

    pszObjectDN = ldap_get_dn(pLd, pEntry);
    if (IsNullOrEmptyString(pszObjectDN))
    {
        dwError = ERROR_INVALID_STATE;
        BAIL_ON_VMAFD_ERROR(dwError);
    }

    pszAttr = ldap_first_attribute(pLd, pEntry, &ber);
    if (IsNullOrEmptyString(pszObjectDN))
    {
        dwError = ERROR_INVALID_STATE;
        BAIL_ON_VMAFD_ERROR(dwError);
    }

    if (!VmAfdStringCompareA(pszAttr, ATTR_NAME_DISPLAYNAME, TRUE))
    {
        dwError = DirCliCopyQueryResultAttributeString(
                      pLd,
                      pEntry,
                      pszAttr,
                      FALSE,
                      &pszPolicyName);
        BAIL_ON_VMAFD_ERROR(dwError);
    }
    else
    {
        dwError = ERROR_INVALID_STATE;
        BAIL_ON_VMAFD_ERROR(dwError);
    }

    *ppszPolicyName = pszPolicyName;

cleanup:
    if (pSearchRes)
    {
        ldap_msgfree(pSearchRes);
    }
    if (ber)
    {
        ber_free(ber, 0);
    }
    VMAFD_SAFE_FREE_MEMORY(pszAttr);
    VMAFD_SAFE_FREE_MEMORY(pszObjectDN);
    VMAFD_SAFE_FREE_MEMORY(pszFilter);
    return dwError;

error:
    if (ppszPolicyName)
    {
        *ppszPolicyName = NULL;
    }
    if (dwError != LDAP_NO_SUCH_OBJECT)
    {
        ldap_perror(pLd, NULL);
    }
    VMAFD_SAFE_FREE_MEMORY(pszPolicyName);
    goto cleanup;
}

/*
    Creates a container for the given DN path.
    Creates a container in the path with object class attributes conatining
    "container" and "top"
    Used for the creation of the System and Polices conatiner under the domain 
    for storing the group policy objects.
*/

DWORD
DirCliGPCreateContainer(
    LDAP *pLd,
    PCSTR pszContainerDN
    )
{
    DWORD dwError = 0;
    PSTR ppszObjectClassValues[] = {"container", "top", NULL};
    char *modv_cn[] = {ATTR_NAME_CN_POLICIES, NULL};
    LDAPMod mod_object = {0};
    LDAPMod mod_cn = {0};
    LDAPMod *mods[] = {&mod_object, &mod_cn, NULL};

    if (!pLd || IsNullOrEmptyString(pszContainerDN))
    {
        dwError = ERROR_INVALID_PARAMETER;
        BAIL_ON_VMAFD_ERROR(dwError);
    }

    mod_cn.mod_op = LDAP_MOD_ADD;
    mod_cn.mod_type = ATTR_NAME_CN;
    mod_cn.mod_values = modv_cn;

    mod_object.mod_op = LDAP_MOD_ADD;
    mod_object.mod_type = ATTR_NAME_OBJECTCLASS;
    mod_object.mod_values = ppszObjectClassValues;

    dwError = ldap_add_ext_s(
                  pLd,
                  (PSTR)pszContainerDN,
                  mods,
                  NULL,
                  NULL);
    BAIL_ON_VMAFD_ERROR(dwError);

cleanup:
    return dwError;

error:
    goto cleanup;
}

/*
    Checks if the if the container exists in the  DN path.
    ContainerType is True for System Container
                     False for Policies Container
*/

DWORD
DirCliGPCheckContainer(
    LDAP *pLd,
    PCSTR pszContainerDN,
    BOOLEAN bContainerType,
    PBOOLEAN pbExists
    )
{
    DWORD dwError = 0;
    DWORD dwNumEntries = 0;
    LDAPMessage *pResult = NULL;
    PSTR pszFilter = NULL;

    if (!pLd || IsNullOrEmptyString(pszContainerDN) || !pbExists)
    {
        dwError = ERROR_INVALID_PARAMETER;
        BAIL_ON_VMAFD_ERROR(dwError);
    }

    if (bContainerType)
    {
      //System
      pszFilter = "(CN=" ATTR_NAME_CN_SYSTEM ")";
    }
    else
    {
      //Policies
      pszFilter = "(CN=" ATTR_NAME_CN_POLICIES ")";
    }

    dwError = ldap_search_ext_s(
                  pLd,
                  (PSTR)pszContainerDN,
                  LDAP_SCOPE_BASE,
                  pszFilter,
                  NULL, /* attributes      */
                  TRUE,
                  NULL, /* server controls */
                  NULL, /* client controls */
                  NULL, /* timeout         */
                  0,
                  &pResult);
    BAIL_ON_VMAFD_ERROR(dwError);

    dwNumEntries = ldap_count_entries(pLd, pResult);
    if (dwNumEntries > 1)
    {
        dwError = ERROR_INVALID_STATE;
        BAIL_ON_VMAFD_ERROR(dwError);
    }

    *pbExists = (dwNumEntries != 0);

cleanup:
    if (pResult)
    {
        ldap_msgfree(pResult);
    }
    return dwError;

error:
    if (pbExists)
    {
        *pbExists = FALSE;
    }

    goto cleanup;
}

/*
    Creates a new in-memory policy object from the given policy parameters.
*/

DWORD
DirCliGPCreateNewPolicyObject(
    PCSTR pszDomain,
    PCSTR pszPolicyName,
    PCSTR pszPolicyJson,
    PDIR_GROUP_POLICY_OBJECT *ppPolicyObject
    )
{
    DWORD dwError = 0;
    PDIR_GROUP_POLICY_OBJECT pPolicyObject = NULL;
    PSTR pszDomainDN = NULL;
    PSTR pszPolicyCN = NULL;
    uuid_t uuid;
    PSTR pszUuidStr = NULL;

    if (IsNullOrEmptyString(pszDomain)     ||
        IsNullOrEmptyString(pszPolicyName) ||
        IsNullOrEmptyString(pszPolicyJson) ||
        !ppPolicyObject)
    {
        dwError = ERROR_INVALID_PARAMETER;
        BAIL_ON_VMAFD_ERROR(dwError);
    }

    dwError = VmAfdAllocateMemory(
                  sizeof(DIR_GROUP_POLICY_OBJECT),
                  (void **)&pPolicyObject);
    BAIL_ON_VMAFD_ERROR(dwError);

    pPolicyObject->pNext = NULL;

    dwError = DirCliGetDomainDN(pszDomain, &pszDomainDN);
    BAIL_ON_VMAFD_ERROR(dwError);

    uuid_generate(uuid);

    dwError = VmAfdAllocateMemory(
                 (UUID_STR_LENGTH * sizeof(CHAR)),
                 (void **)&pszUuidStr);
    BAIL_ON_VMAFD_ERROR(dwError);

    uuid_unparse(uuid, pszUuidStr);

    if(IsNullOrEmptyString(pszUuidStr))
    {
        dwError = ERROR_INVALID_PARAMETER;
        BAIL_ON_VMAFD_ERROR(dwError);
    }

    dwError = VmAfdAllocateStringPrintf(
                  &pszPolicyCN,
                  "{%s}",
                  pszUuidStr);
    BAIL_ON_VMAFD_ERROR(dwError);

    dwError = VmAfdAllocateStringA(
                  pszPolicyName,
                  &pPolicyObject->pszPolicyName);
    BAIL_ON_VMAFD_ERROR(dwError);

    dwError = VmAfdAllocateStringA(
                  pszPolicyJson,
                  &pPolicyObject->pszPolicyJson);
    BAIL_ON_VMAFD_ERROR(dwError);

    dwError = VmAfdAllocateStringA(
                  pszPolicyCN,
                  &pPolicyObject->pszPolicyCN);
    BAIL_ON_VMAFD_ERROR(dwError);

    dwError = VmAfdAllocateStringA(
                  pszDomainDN,
                  &pPolicyObject->pszDomainDN);
    BAIL_ON_VMAFD_ERROR(dwError);

    pPolicyObject->dwVersion = 0;

    *ppPolicyObject = pPolicyObject;

cleanup:
    VMAFD_SAFE_FREE_MEMORY(pszDomainDN);
    VMAFD_SAFE_FREE_MEMORY(pszPolicyCN);
    VMAFD_SAFE_FREE_MEMORY(pszUuidStr);
    return dwError;

error:
    if (pPolicyObject)
    {
        DirCliGPFreePolicyObject(pPolicyObject);
    }
    if (ppPolicyObject)
    {
        *ppPolicyObject = NULL;
    }
    goto cleanup;
}

/*
    Enables editing of the in-memory policy  object.
*/

DWORD
DirCliGPEditPolicyObject(
    PDIR_GROUP_POLICY_OBJECT pPolicyObject,
    PCSTR pszPolicyName,
    PCSTR pszPolicyJson
    )
{
    DWORD dwError = 0;
    PSTR  pszNewPolicyName = NULL;
    PSTR  pszNewPolicyJson = NULL;

    if (!pPolicyObject || (IsNullOrEmptyString(pszPolicyName) && IsNullOrEmptyString(pszPolicyJson)))
    {
        dwError = ERROR_INVALID_PARAMETER;
        BAIL_ON_VMAFD_ERROR(dwError);
    }

    // if there is a policy name to update?
    if (pszPolicyName)
    {
        dwError = VmAfdAllocateStringA(pszPolicyName,&pszNewPolicyName);
        BAIL_ON_VMAFD_ERROR(dwError);

        VMAFD_SAFE_FREE_MEMORY(pPolicyObject->pszPolicyName);
        pPolicyObject->pszPolicyName = pszNewPolicyName;
    }

    // if there is a policy json to update?
    if (pszPolicyJson)
    {
        dwError = VmAfdAllocateStringA(pszPolicyJson,&pszNewPolicyJson);
        BAIL_ON_VMAFD_ERROR(dwError);

        VMAFD_SAFE_FREE_MEMORY(pPolicyObject->pszPolicyJson);
        pPolicyObject->pszPolicyJson = pszNewPolicyJson;
    }

    // Increment the version of the policy
    pPolicyObject->dwVersion++;

cleanup:
    return dwError;

error:
    VMAFD_SAFE_FREE_MEMORY(pszNewPolicyName);
    VMAFD_SAFE_FREE_MEMORY(pszNewPolicyJson);
    goto cleanup;
}

/*
    Free the in-memory policy object linked list.
*/

void DirCliGPFreePolicyObject(
    PDIR_GROUP_POLICY_OBJECT pPolicyObject
    )
{
    PDIR_GROUP_POLICY_OBJECT pPolicyObjectNext = NULL;

    while (pPolicyObject)
    {
        pPolicyObjectNext = pPolicyObject->pNext;
        VMAFD_SAFE_FREE_MEMORY(pPolicyObject->pszDomainDN);
        VMAFD_SAFE_FREE_MEMORY(pPolicyObject->pszPolicyName);
        VMAFD_SAFE_FREE_MEMORY(pPolicyObject->pszPolicyJson);
        VMAFD_SAFE_FREE_MEMORY(pPolicyObject->pszPolicyCN);
        VMAFD_SAFE_FREE_MEMORY(pPolicyObject);
        pPolicyObject = pPolicyObjectNext;
    }
}

/*
    Prints the policy object to console.
*/

DWORD
DirCliGPPrintPolicyObject(
    const DIR_GROUP_POLICY_OBJECT *pPolicyObject
    )
{
    DWORD dwError = 0;
    DWORD dwCount = 0;

    if (!pPolicyObject)
    {
        fprintf(stdout, "No Policies to print \n");
    }
    while (pPolicyObject)
    {
        fprintf(stdout, " ==================\n");
        fprintf(stdout, " Policy no        : %u \n", dwCount);
        fprintf(stdout, " PolicyName       : %s \n", pPolicyObject->pszPolicyName);
        fprintf(
            stdout,
            " PolicyPolicyDN   : cn=%s,cn=Policies,cn=System,%s \n",
            pPolicyObject->pszPolicyCN,
            pPolicyObject->pszDomainDN);
        fprintf(stdout, " PolicyJson       : %s \n", pPolicyObject->pszPolicyJson);
        fprintf(stdout, " Version          : %u \n", pPolicyObject->dwVersion);

        fprintf(stdout, " ==================\n");

        pPolicyObject = pPolicyObject->pNext;
        dwCount++;
    }

    return dwError;
}

/*
    Retrieves the parent DN of the given DN. The number levels of the parent is
   specified in the dwParentlevel. It doesn't check the boundaries of
   dwParentlevel.
 */

DWORD
DirCliGPGetParentDN(
    PCSTR pszOriginalDN,
    DWORD dwParentlevel,
    PSTR *ppszParentDN
    )
{
    DWORD dwError = 0;
    int flags = 0;
    PSTR pszParentDN = NULL;
    LDAPDN ldapDN = NULL;

    if (IsNullOrEmptyString(pszOriginalDN) || !ppszParentDN)
    {
        dwError = ERROR_INVALID_PARAMETER;
        BAIL_ON_VMAFD_ERROR(dwError);
    }

    dwError = ldap_str2dn(pszOriginalDN, &ldapDN, flags);
    BAIL_ON_VMAFD_ERROR(dwError);

    dwError = ldap_dn2str(
                  &ldapDN[dwParentlevel],
                  &pszParentDN,
                  LDAP_DN_FORMAT_LDAPV3);
    BAIL_ON_VMAFD_ERROR(dwError);

    *ppszParentDN = pszParentDN;

cleanup:
    if (ldapDN)
    {
        ldap_dnfree(ldapDN);
    }
    return dwError;

error:
    if (ppszParentDN)
    {
        *ppszParentDN = NULL;
    }
    VMAFD_SAFE_FREE_MEMORY(pszParentDN);
    goto cleanup;
}

/*
    Counts the polices in the in-memory policy linked list.
 */

DWORD
DirCliGPGetPolicyCount(
    const DIR_GROUP_POLICY_OBJECT *pPolicyObject,
    DWORD *pdwPolicyCount
    )
{
    DWORD dwError = 0;
    DWORD dwPolicyCount = 0;

    if (!pPolicyObject || !pdwPolicyCount)
    {
        dwError = ERROR_INVALID_PARAMETER;
        BAIL_ON_VMAFD_ERROR(dwError);
    }

    while (pPolicyObject)
    {
        pPolicyObject = pPolicyObject->pNext;
        dwPolicyCount++;
    }

    *pdwPolicyCount = dwPolicyCount;

error:
    if(pdwPolicyCount)
    {
        *pdwPolicyCount = 0;
    }
    return dwError;
}

/*
    Deletes a single policy by name.
    Deleting a policy also deletes all the associated links with it.
 */

DWORD
DirCliGPDeletePolicyByName(
    LDAP *pLd,
    PCSTR pszPolicyName,
    PCSTR pszDomain
    )
{
    DWORD dwError = 0;
    PDIR_GROUP_POLICY_OBJECT pPolicyObject = NULL;
    PDIR_GROUP_POLICY_OBJECT pPolicyObjectHead = NULL;
    PSTR pszPolicyDN = NULL;

    if (!pLd || IsNullOrEmptyString(pszPolicyName) || IsNullOrEmptyString(pszDomain))
    {
        dwError = ERROR_INVALID_PARAMETER;
        BAIL_ON_VMAFD_ERROR(dwError);
    }

    dwError = DirCliGPFindPolicyByName(
                  pLd,
                  pszPolicyName,
                  pszDomain,
                  &pPolicyObject);
    BAIL_ON_VMAFD_ERROR(dwError);

    pPolicyObjectHead = pPolicyObject;

    while (pPolicyObject)
    {
        if (IsNullOrEmptyString(pPolicyObject->pszPolicyCN) ||
            IsNullOrEmptyString(pPolicyObject->pszDomainDN))
        {
        dwError = ERROR_INVALID_PARAMETER;
        BAIL_ON_VMAFD_ERROR(dwError);
        }

        dwError = VmAfdAllocateStringPrintf(
                      &pszPolicyDN,
                      "cn=%s,cn=Policies,cn=System,%s",
                      pPolicyObject->pszPolicyCN,
                      pPolicyObject->pszDomainDN);
        BAIL_ON_VMAFD_ERROR(dwError);

        // Delete all the links
        dwError = DirCliGPDeleteAllPolicyLinksbyName(
                      pLd,
                      pszPolicyName,
                      pszDomain);
        BAIL_ON_VMAFD_ERROR(dwError);

        // LDAP delete
        dwError = ldap_delete_ext_s(pLd, pszPolicyDN, NULL, NULL);
        BAIL_ON_VMAFD_ERROR(dwError);

        fprintf(stdout, "Deleted policy %s \n", pszPolicyDN);
        pPolicyObject = pPolicyObject->pNext;

        //Free memory for pointer reuse
        VMAFD_SAFE_FREE_MEMORY(pszPolicyDN);
    }

cleanup:
    if (pPolicyObjectHead)
    {
        DirCliGPFreePolicyObject(pPolicyObjectHead);
    }
    VMAFD_SAFE_FREE_MEMORY(pszPolicyDN);
    return dwError;

error:
    goto cleanup;
}

/*
    Deletes all the associated links with a given policy.
    Takes the policy name and policy domain as inputs.
 */

DWORD
DirCliGPDeleteAllPolicyLinksbyName(
    LDAP *pLd,
    PCSTR pszPolicyName,
    PCSTR pszPolicyDomainName
    )
{
    DWORD dwError = 0;
    PSTR ppszAttrs[] = {ATTR_NAME_GPLINK, NULL};
    PSTR pszFilter = NULL;
    PSTR pszSearchBase = NULL;
    LDAPMessage *pSearchRes = NULL;
    LDAPMessage *pEntry = NULL;
    DWORD dwCount = 0;
    PDIR_GROUP_POLICY_OBJECT pPolicyObject = NULL;
    PSTR pszPolicyDomainDN = NULL;
    PSTR pszPolicyDN = NULL;
    BerElement *ber = NULL;
    PSTR pszAttr = NULL;
    PGPLINK_LIST pgPLinkList = NULL;
    PGPLINK_LIST pgPLinkListHead = NULL;
    PGPLINK_LIST pTemp = NULL;

    if (!pLd                                ||
         IsNullOrEmptyString(pszPolicyName) ||
         IsNullOrEmptyString(pszPolicyDomainName))
    {
        dwError = ERROR_INVALID_PARAMETER;
        BAIL_ON_VMAFD_ERROR(dwError);
    }

    dwError = DirCliGetDomainDN(
                  pszPolicyDomainName,
                  &pszPolicyDomainDN);
    BAIL_ON_VMAFD_ERROR(dwError);

    dwError = DirCliGPFindPolicyByName(
                  pLd,
                  pszPolicyName,
                  pszPolicyDomainName,
                  &pPolicyObject);
    BAIL_ON_VMAFD_ERROR(dwError);

    if (IsNullOrEmptyString(pPolicyObject->pszPolicyCN) ||
        IsNullOrEmptyString(pPolicyObject->pszDomainDN))
    {
        dwError = ERROR_INVALID_PARAMETER;
        BAIL_ON_VMAFD_ERROR(dwError);
    }

    // form a policyDN from the policy object
    dwError = VmAfdAllocateStringPrintf(
                  &pszPolicyDN,
                  "cn=%s,cn=Policies,cn=System,%s",
                  pPolicyObject->pszPolicyCN,
                  pPolicyObject->pszDomainDN);
    BAIL_ON_VMAFD_ERROR(dwError);

    // Get the root domain name for searching links
    dwError = DirCliGetDefaultDomainName(pLd, &pszSearchBase);
    BAIL_ON_VMAFD_ERROR(dwError);

    // Check for OUs and Domains with gpLinks.
    dwError = VmAfdAllocateStringPrintf(
                  &pszFilter,
                  "(&(|(%s=%s)(%s=%s))(%s=*))",
                  ATTR_NAME_OBJECTCLASS,
                  OBJECT_CLASS_DOMAIN_DNS,
                  ATTR_NAME_OBJECTCLASS,
                  OBJECT_CLASS_ORGANIZATIONAL_UNIT,
                  ATTR_NAME_GPLINK);
    BAIL_ON_VMAFD_ERROR(dwError);

    dwError = ldap_search_ext_s(
                  pLd,
                  pszSearchBase,
                  LDAP_SCOPE_SUBTREE,
                  pszFilter,
                  ppszAttrs,
                  FALSE, // attrs only
                  NULL,  // serverctrls
                  NULL,  // clientctrls
                  NULL,  // timeout
                  0,
                  &pSearchRes);
    BAIL_ON_VMAFD_ERROR(dwError);

    dwCount = ldap_count_entries(pLd, pSearchRes);
    if (!dwCount)
    {
        dwError = ERROR_GP_NO_SUCH_POLICY;
        BAIL_ON_VMAFD_ERROR(dwError);
    }

    for (pEntry = ldap_first_entry(pLd, pSearchRes); pEntry != NULL;
         pEntry = ldap_next_entry(pLd, pEntry))
    {
        dwError = VmAfdAllocateMemory(
                      sizeof(GPLINK_LIST),
                      (void **)&pgPLinkList);
        BAIL_ON_VMAFD_ERROR(dwError);

        pgPLinkList->pszObjectDN = ldap_get_dn(pLd, pEntry);
        if (IsNullOrEmptyString(pgPLinkList->pszObjectDN))
        {
            dwError = ERROR_INVALID_STATE;
            BAIL_ON_VMAFD_ERROR(dwError);
        }

        pszAttr = ldap_first_attribute(pLd, pEntry, &ber);
        if (pszAttr == NULL)
        {
            dwError = ldap_get_option(
                          pLd,
                          LDAP_OPT_ERROR_NUMBER,
                          &dwError);
            BAIL_ON_VMAFD_ERROR(dwError);
        }

        if (!VmAfdStringCompareA(pszAttr, ATTR_NAME_GPLINK, TRUE))
        {
            dwError = DirCliCopyQueryResultAttributeString(
                          pLd,
                          pEntry,
                          pszAttr,
                          FALSE,
                          &pgPLinkList->pszgPlink);
            BAIL_ON_VMAFD_ERROR(dwError);
        }
        else
        {
            dwError = ERROR_INVALID_STATE;
            BAIL_ON_VMAFD_ERROR(dwError);
        }

        if (!pgPLinkListHead)
        {
            pgPLinkListHead = pgPLinkList;
        }
        else
        {
            //Tail add Linked List
            pTemp = pgPLinkListHead;
            while (pTemp && pTemp->pNext)
                pTemp = pTemp->pNext;
            pTemp->pNext = pgPLinkList;
        }
        pgPLinkList = NULL;

        if(ber)
        {
            ber_free(ber, 0);
            ber = NULL;
        }
        VMAFD_SAFE_FREE_MEMORY(pszAttr);

    }

    dwError = DirCliGPRemoveLinkFromGPLinkList(
                  pLd,
                  pszPolicyDN,
                  pgPLinkListHead);
    BAIL_ON_VMAFD_ERROR(dwError);

cleanup:

    if (pSearchRes)
    {
        ldap_msgfree(pSearchRes);
    }
    if (pPolicyObject)
    {
        DirCliGPFreePolicyObject(pPolicyObject);
    }
    if (pgPLinkListHead)
    {
        DirCliGPFreegPLinkList(pgPLinkListHead);
    }

    VMAFD_SAFE_FREE_MEMORY(pszAttr);
    VMAFD_SAFE_FREE_MEMORY(pszPolicyDN);
    VMAFD_SAFE_FREE_MEMORY(pszPolicyDomainDN);
    VMAFD_SAFE_FREE_MEMORY(pszSearchBase);
    VMAFD_SAFE_FREE_MEMORY(pszFilter);

    return dwError;

error:
    if (ber)
    {
        ber_free(ber, 0);
    }
    ldap_perror(pLd, NULL);
    goto cleanup;
}

/*
    Removes a single link corresponding to the policyDN from the Json array of
   links.
 */

DWORD
DirCliGPRemoveLinkFromGPLinkList(
    LDAP *pLd,
    PCSTR pszPolicyDN,
    const GPLINK_LIST *pgPLinkList
    )
{
    DWORD dwError = 0;
    json_t *jsongpLinkArray = NULL;
    size_t index = 0;
    json_t *value = NULL;
    json_error_t *pError = NULL;
    BOOLEAN bIsUpdated = FALSE;
    PSTR pszUpdatedgpLink = NULL;
    const char * pszCurrentDN = NULL;

    if (!pLd || IsNullOrEmptyString(pszPolicyDN) || !pgPLinkList)
    {
        dwError = ERROR_INVALID_PARAMETER;
        BAIL_ON_VMAFD_ERROR(dwError);
    }

    while (pgPLinkList)
    {
        // Parse the json and exact individual links
        jsongpLinkArray = json_loads(pgPLinkList->pszgPlink, 0, pError);
        if (!jsongpLinkArray)
        {
            dwError = ERROR_GP_GPLINK_JSON_ERROR;
            BAIL_ON_VMAFD_ERROR(dwError);
        }

        json_array_foreach(jsongpLinkArray, index, value)
        {
            pszCurrentDN =json_string_value(value);
            if(!pszCurrentDN)
            {
                dwError = ERROR_GP_JSON_CONVERSION_ERROR;
                BAIL_ON_VMAFD_ERROR(dwError);
            }

            if (!VmAfdStringCompareA(pszPolicyDN,pszCurrentDN , FALSE))
            {
                dwError = json_array_remove(jsongpLinkArray, index);
                if (dwError)
                {
                    dwError = ERROR_GP_JSON_ARRAY_DELETE_FAILED;
                    BAIL_ON_VMAFD_ERROR(dwError);
                }

                bIsUpdated = TRUE;
            }

        }

        if (bIsUpdated)
        {
            pszUpdatedgpLink = json_dumps(jsongpLinkArray, 0);
            if(!pszUpdatedgpLink)
            {
                dwError = ERROR_GP_JSON_CONVERSION_ERROR;
                BAIL_ON_VMAFD_ERROR(dwError);
            }

            dwError = DirCliLdapUpdateAttribute(
                          pLd,
                          pgPLinkList->pszObjectDN,
                          ATTR_NAME_GPLINK,
                          pszUpdatedgpLink,
                          FALSE);
            BAIL_ON_VMAFD_ERROR(dwError);

            bIsUpdated = FALSE;
        }

        fprintf(stdout, "Deleted link from DN =%s \n", pgPLinkList->pszObjectDN);

        pgPLinkList = pgPLinkList->pNext;

        if (jsongpLinkArray)
        {
            json_decref(jsongpLinkArray);
            jsongpLinkArray = NULL;
        }
        VMAFD_SAFE_FREE_MEMORY(pszUpdatedgpLink);
    }

cleanup:
    if (jsongpLinkArray)
    {
        json_decref(jsongpLinkArray);
    }
    VMAFD_SAFE_FREE_MEMORY(pszUpdatedgpLink);
    VMAFD_SAFE_FREE_MEMORY(pError);
    return dwError;

error:
    ldap_perror(pLd, NULL);
    goto cleanup;
}

/*
    Searches for dead-links(linked to objects but the policy is deleted) with in
   the root and deletes them.
 */

DWORD
DirCliGPCleanDeadLinks(LDAP *pLd)
{
    DWORD dwError = 0;
    PSTR ppszAttrs[] = {ATTR_NAME_GPLINK, NULL};
    PSTR pszFilter = NULL;
    PSTR pszSearchBase = NULL;
    PSTR pszObjectDN = NULL;
    LDAPMessage *pSearchRes = NULL;
    LDAPMessage *pEntry = NULL;
    BerElement *ber = NULL;
    PSTR pszAttr = NULL;
    DWORD dwCount = 0;
    PSTR pszgpLink = NULL;
    PSTR pszUpdatedgpLink = NULL;
    json_t *jsongpLinkArray = NULL;
    size_t index = 0;
    json_t *value = NULL;
    json_error_t *pError = NULL;
    PSTR pszPolicyName = NULL;
    const char * pszPolicyDN =NULL;
    BOOL bIsUpdated = FALSE;

    if (!pLd)
    {
        dwError = ERROR_INVALID_PARAMETER;
        BAIL_ON_VMAFD_ERROR(dwError);
    }

    // Get the root domain name for searching links
    dwError = DirCliGetDefaultDomainName(pLd, &pszSearchBase);
    BAIL_ON_VMAFD_ERROR(dwError);

    // Check for OUs and Domains with gpLinks.
    dwError = VmAfdAllocateStringPrintf(
                  &pszFilter,
                  "(&(|(%s=%s)(%s=%s))(%s=*))",
                  ATTR_NAME_OBJECTCLASS,
                  OBJECT_CLASS_DOMAIN_DNS,
                  ATTR_NAME_OBJECTCLASS,
                  OBJECT_CLASS_ORGANIZATIONAL_UNIT,
                  ATTR_NAME_GPLINK);
    BAIL_ON_VMAFD_ERROR(dwError);

    dwError = ldap_search_ext_s(
                  pLd,
                  pszSearchBase,
                  LDAP_SCOPE_SUBTREE,
                  pszFilter,
                  ppszAttrs,
                  FALSE, // attrs only
                  NULL,  // serverctrls
                  NULL,  // clientctrls
                  NULL,  // timeout
                  0,
                  &pSearchRes);
    BAIL_ON_VMAFD_ERROR(dwError);

    dwCount = ldap_count_entries(pLd, pSearchRes);
    if (!dwCount)
    {
        dwError = ERROR_GP_NO_SUCH_POLICY;
        BAIL_ON_VMAFD_ERROR(dwError);
    }

    for (pEntry = ldap_first_entry(pLd, pSearchRes); pEntry != NULL;
         pEntry = ldap_next_entry(pLd, pEntry))
    {
        pszObjectDN = ldap_get_dn(pLd, pEntry);
        if (IsNullOrEmptyString(pszObjectDN))
        {
            dwError = ERROR_INVALID_STATE;
            BAIL_ON_VMAFD_ERROR(dwError);
        }

        pszAttr = ldap_first_attribute(pLd, pEntry, &ber);
        if (IsNullOrEmptyString(pszAttr))
        {
            dwError = ERROR_INVALID_STATE;
            BAIL_ON_VMAFD_ERROR(dwError);
        }

        if (!VmAfdStringCompareA(pszAttr, ATTR_NAME_GPLINK, TRUE))
        {
            dwError = DirCliCopyQueryResultAttributeString(
                          pLd,
                          pEntry,
                          pszAttr,
                          FALSE,
                          &pszgpLink);
            BAIL_ON_VMAFD_ERROR(dwError);

            fprintf(stdout, "Scanning DN =%s \n", pszObjectDN);

            // Parse the json and exact individual links
            jsongpLinkArray = json_loads(pszgpLink, 0, pError);
            if (!jsongpLinkArray)
            {
                dwError = ERROR_GP_GPLINK_JSON_ERROR;
                BAIL_ON_VMAFD_ERROR(dwError);
            }

            bIsUpdated = FALSE;

            json_array_foreach(jsongpLinkArray, index, value)
            {
                pszPolicyDN = json_string_value(value);
                if (!pszPolicyDN)
                {
                    dwError = ERROR_GP_JSON_CONVERSION_ERROR;
                    BAIL_ON_VMAFD_ERROR(dwError);
                }

                // Check if the DN exist
                dwError = DirCliGPGetPolicyNameFromPolicyDN(
                              pLd,
                              pszPolicyDN,
                              &pszPolicyName);
                if (dwError == ERROR_GP_NO_SUCH_POLICY ||
                    dwError == LDAP_NO_SUCH_OBJECT)
                {
                    fprintf(
                        stdout,
                        "Deleting deadlink DN =%s \n",
                        pszPolicyDN);

                    dwError = json_array_remove(jsongpLinkArray, index);
                    if (dwError)
                    {
                        dwError = ERROR_GP_JSON_ARRAY_DELETE_FAILED;
                        BAIL_ON_VMAFD_ERROR(dwError);
                    }

                    bIsUpdated = TRUE;
                }
                BAIL_ON_VMAFD_ERROR(dwError);

                if (bIsUpdated)
                {
                    pszUpdatedgpLink = json_dumps(jsongpLinkArray, 0);
                    if (!pszUpdatedgpLink)
                    {
                        dwError = ERROR_GP_JSON_CONVERSION_ERROR;
                        BAIL_ON_VMAFD_ERROR(dwError);
                    }

                    dwError = DirCliLdapUpdateAttribute(
                                 pLd,
                                 pszObjectDN,
                                 ATTR_NAME_GPLINK,
                                 pszUpdatedgpLink,
                                 FALSE);
                    BAIL_ON_VMAFD_ERROR(dwError);
                }
                // Reusing pointer in the loop, free it
                VMAFD_SAFE_FREE_MEMORY(pszPolicyName);
                VMAFD_SAFE_FREE_MEMORY(pszUpdatedgpLink);
            }

            // Reusing pointer in the loop, free it
            VMAFD_SAFE_FREE_MEMORY(pszgpLink);

            if (jsongpLinkArray)
            {
                json_decref(jsongpLinkArray);
                jsongpLinkArray = NULL;
            }
        }
        else
        {
            dwError = ERROR_INVALID_STATE;
            BAIL_ON_VMAFD_ERROR(dwError);
        }

        if (ber)
        {
            ber_free(ber, 0);
            ber =NULL;
        }

        VMAFD_SAFE_FREE_MEMORY(pszAttr);
        VMAFD_SAFE_FREE_MEMORY(pszObjectDN);
    }

cleanup:
    if (pSearchRes)
    {
        ldap_msgfree(pSearchRes);
    }
    if (ber)
    {
        ber_free(ber, 0);
    }
    if (jsongpLinkArray)
    {
        json_decref(jsongpLinkArray);
    }

    VMAFD_SAFE_FREE_MEMORY(pszPolicyName);
    VMAFD_SAFE_FREE_MEMORY(pszUpdatedgpLink);
    VMAFD_SAFE_FREE_MEMORY(pszgpLink);
    VMAFD_SAFE_FREE_MEMORY(pszAttr);
    VMAFD_SAFE_FREE_MEMORY(pszObjectDN);
    VMAFD_SAFE_FREE_MEMORY(pError);
    VMAFD_SAFE_FREE_MEMORY(pszSearchBase);
    VMAFD_SAFE_FREE_MEMORY(pszFilter);
    return dwError;

error:
    ldap_perror(pLd, NULL);
    goto cleanup;
}

/*
    Forms a string from the berval structures.
 */

DWORD
DirCliGPGetStrFromBerval(struct berval la_attr, PSTR *ppszBervalStr)
{
    DWORD dwError = 0;
    PSTR pszBervalStr = NULL;

    if (!ppszBervalStr)
    {
        dwError = ERROR_INVALID_PARAMETER;
        BAIL_ON_VMAFD_ERROR(dwError);
    }

    dwError = VmAfdAllocateMemory(
                  la_attr.bv_len + 1,
                  (void **)&pszBervalStr);
    BAIL_ON_VMAFD_ERROR(dwError);

    strncpy(
        pszBervalStr,
        la_attr.bv_val,
        la_attr.bv_len);
    pszBervalStr[la_attr.bv_len] = '\0';

    *ppszBervalStr = pszBervalStr;

cleanup:
    return dwError;

error:
    if (ppszBervalStr)
    {
        *ppszBervalStr = NULL;
    }
    VMAFD_SAFE_FREE_MEMORY(pszBervalStr);
    goto cleanup;
}

void DirCliGPShowJsonError(
         json_error_t *pError
         )
{
    if (!pError)
    {
        return;
    }
    fprintf(
        stderr,
        "Json error: \n line: %d\n error: %s\n",
        pError->line,
        pError->text);
}

/*
    Links a given policy to a domain.
 */

DWORD
DirCliGPLinkPolicyToDomain(
    LDAP *pLd,
    PCSTR pszPolicyName,
    PCSTR pszDomain
    )
{
    DWORD dwError = 0;
    PSTR pszPolicyDN = NULL;
    PSTR pszDomainDN = NULL;
    PSTR pszCurrentgpLink = NULL;
    PSTR pszUpdatedgpLink = NULL;
    BOOLEAN bExists = FALSE;
    BOOLEAN bAlreadyLinked = FALSE;
    json_t *jsonStrPolicyDN = NULL;
    json_t *jsongpLinkArray = NULL;
    json_error_t *pError = NULL;
    size_t index = 0;
    json_t *value = NULL;
    const char * pszCurrentDN =NULL;
    PDIR_GROUP_POLICY_OBJECT pPolicyObject = NULL;

    if (!pLd || IsNullOrEmptyString(pszPolicyName) || IsNullOrEmptyString(pszDomain))
    {
        dwError = ERROR_INVALID_PARAMETER;
        BAIL_ON_VMAFD_ERROR(dwError);
    }

    dwError = DirCliGetDomainDN(pszDomain, &pszDomainDN);
    BAIL_ON_VMAFD_ERROR(dwError);

    dwError = DirCliGPFindPolicyByName(
                  pLd,
                  pszPolicyName,
                  pszDomain,
                  &pPolicyObject);
    BAIL_ON_VMAFD_ERROR(dwError);

    if (IsNullOrEmptyString(pPolicyObject->pszPolicyCN) ||
        IsNullOrEmptyString(pPolicyObject->pszDomainDN))
    {
        dwError = ERROR_INVALID_PARAMETER;
        BAIL_ON_VMAFD_ERROR(dwError);
    }

    // form a policyDN from the policy object
    dwError = VmAfdAllocateStringPrintf(
                  &pszPolicyDN,
                  "cn=%s,cn=Policies,cn=System,%s",
                  pPolicyObject->pszPolicyCN,
                  pPolicyObject->pszDomainDN);
    BAIL_ON_VMAFD_ERROR(dwError);

    // Check if the gpLink attribute is present in the domain path?
    dwError = DirCliLdapGetAttribute(
                  pLd,
                  pszDomainDN,
                  ATTR_NAME_GPLINK,
                  &bExists,
                  &pszCurrentgpLink);
    BAIL_ON_VMAFD_ERROR(dwError);

    jsonStrPolicyDN = json_string(pszPolicyDN);
    if(!jsonStrPolicyDN)
    {
        dwError = ERROR_GP_JSON_CONVERSION_ERROR;
         BAIL_ON_VMAFD_ERROR(dwError);
    }

    if (bExists)
    {
        // Attribute already exists
        jsongpLinkArray = json_loads(pszCurrentgpLink, 0, pError);
        if (!jsongpLinkArray)
        {
            dwError = ERROR_GP_GPLINK_JSON_ERROR;
            BAIL_ON_VMAFD_ERROR(dwError);
        }

        // See if it is already linked
        json_array_foreach(jsongpLinkArray, index, value)
        {
            pszCurrentDN = json_string_value(value);
            if(!pszCurrentDN)
            {
                dwError = ERROR_GP_JSON_CONVERSION_ERROR;
                BAIL_ON_VMAFD_ERROR(dwError);
            }

            if (!VmAfdStringCompareA(pszPolicyDN,pszCurrentDN , FALSE))
            {
                fprintf(
                    stdout,
                    "Policy \"%s\" already linked to domain \"%s\"\n",
                    pPolicyObject->pszPolicyName,
                    pszDomainDN);

                bAlreadyLinked = TRUE;
            }
        }

        if (!bAlreadyLinked)
        {
            dwError = json_array_append(jsongpLinkArray, jsonStrPolicyDN);
            BAIL_ON_VMAFD_ERROR(dwError);

            pszUpdatedgpLink = json_dumps(jsongpLinkArray, 0);
            if (!pszUpdatedgpLink)
            {
                dwError = ERROR_GP_JSON_CONVERSION_ERROR;
                BAIL_ON_VMAFD_ERROR(dwError);
            }

            dwError = DirCliLdapUpdateAttribute(
                          pLd,
                          pszDomainDN,
                          ATTR_NAME_GPLINK,
                          pszUpdatedgpLink,
                          FALSE);
            BAIL_ON_VMAFD_ERROR(dwError);

            fprintf(
                stdout,
                "Policy \"%s\" successfully linked to domain \"%s\" \n",
                pPolicyObject->pszPolicyName,
                pszDomainDN);
        }
    }
    else
    {
        jsongpLinkArray = json_array();
        if(!jsongpLinkArray)
        {
            dwError = ERROR_GP_JSON_CONVERSION_ERROR;
            BAIL_ON_VMAFD_ERROR(dwError);
        }

        dwError = json_array_append(jsongpLinkArray, jsonStrPolicyDN);
        BAIL_ON_VMAFD_ERROR(dwError);

        pszUpdatedgpLink = json_dumps(jsongpLinkArray, 0);
        if(!pszUpdatedgpLink)
        {
            dwError = ERROR_GP_JSON_CONVERSION_ERROR;
            BAIL_ON_VMAFD_ERROR(dwError);
        }

        dwError = DirCliLdapUpdateAttribute(
                      pLd,
                      pszDomainDN,
                      ATTR_NAME_GPLINK,
                      pszUpdatedgpLink,
                      FALSE);
        BAIL_ON_VMAFD_ERROR(dwError);

        fprintf(
            stdout,
            "Policy \"%s\" successfully linked to domain \"%s\" \n",
            pPolicyObject->pszPolicyName,
            pszDomainDN);
    }

cleanup:
    if (pPolicyObject)
    {
        DirCliGPFreePolicyObject(pPolicyObject);
    }
    if (jsonStrPolicyDN)
    {
        json_decref(jsonStrPolicyDN);
    }
    if (jsongpLinkArray)
    {
        json_decref(jsongpLinkArray);
    }

    VMAFD_SAFE_FREE_MEMORY(pError);
    VMAFD_SAFE_FREE_MEMORY(pszPolicyDN);
    VMAFD_SAFE_FREE_MEMORY(pszDomainDN);
    VMAFD_SAFE_FREE_MEMORY(pszCurrentgpLink);
    VMAFD_SAFE_FREE_MEMORY(pszUpdatedgpLink);

    return dwError;

error:
    fprintf(stdout, "Policy link failed!! \n");
    DirCliGPShowJsonError(pError);
    goto cleanup;
}

/*
    Unlinks a given policy from Domain.
 */

DWORD
DirCliGPUnlinkPolicyfromDomain(
    LDAP *pLd,
    PCSTR pszPolicyName,
    PCSTR pszDomain
    )
{
    DWORD dwError = 0;
    PSTR pszPolicyDN = NULL;
    PSTR pszDomainDN = NULL;
    PSTR pszCurrentgpLink = NULL;
    PSTR pszUpdatedgpLink = NULL;
    const char * pszCurrentDN = NULL;
    BOOLEAN bExists = FALSE;
    int dIndexToRemove = -1;
    json_t *jsonStrPolicyDN = NULL;
    json_t *jsongpLinkArray = NULL;
    json_error_t *pError = NULL;
    size_t index = 0;
    json_t *value = NULL;
    PDIR_GROUP_POLICY_OBJECT pPolicyObject = NULL;

    if (!pLd || IsNullOrEmptyString(pszPolicyName) || IsNullOrEmptyString(pszDomain))
    {
        dwError = ERROR_INVALID_PARAMETER;
        BAIL_ON_VMAFD_ERROR(dwError);
    }

    dwError = DirCliGetDomainDN(pszDomain, &pszDomainDN);
    BAIL_ON_VMAFD_ERROR(dwError);

    dwError = DirCliGPFindPolicyByName(
                  pLd,
                  pszPolicyName,
                  pszDomain,
                  &pPolicyObject);
    BAIL_ON_VMAFD_ERROR(dwError);

    if (IsNullOrEmptyString(pPolicyObject->pszPolicyCN) ||
        IsNullOrEmptyString(pPolicyObject->pszDomainDN))
    {
        dwError = ERROR_INVALID_PARAMETER;
        BAIL_ON_VMAFD_ERROR(dwError);
    }

    // form a policyDN from the policy object
    dwError = VmAfdAllocateStringPrintf(
                  &pszPolicyDN,
                  "cn=%s,cn=Policies,cn=System,%s",
                  pPolicyObject->pszPolicyCN,
                  pPolicyObject->pszDomainDN);
    BAIL_ON_VMAFD_ERROR(dwError);

    // Check if the gpLink attribute is present in the domain path?
    dwError = DirCliLdapGetAttribute(
                  pLd,
                  pszDomainDN,
                  ATTR_NAME_GPLINK,
                  &bExists,
                  &pszCurrentgpLink);
    BAIL_ON_VMAFD_ERROR(dwError);

    jsonStrPolicyDN = json_string(pszPolicyDN);
    if (!jsonStrPolicyDN)
    {
        dwError = ERROR_GP_JSON_CONVERSION_ERROR;
        BAIL_ON_VMAFD_ERROR(dwError);
    }

    if (bExists)
    {
        // Attribute already exists
        jsongpLinkArray = json_loads(pszCurrentgpLink, 0, pError);
        if (!jsongpLinkArray)
        {
            dwError = ERROR_GP_GPLINK_JSON_ERROR;
            BAIL_ON_VMAFD_ERROR(dwError);
        }

        // See if its linked ?
        json_array_foreach(jsongpLinkArray, index, value)
        {
            pszCurrentDN = json_string_value(value);
            if(!pszCurrentDN)
            {
                dwError = ERROR_GP_JSON_CONVERSION_ERROR;
                BAIL_ON_VMAFD_ERROR(dwError);
            }

            if (!VmAfdStringCompareA(pszPolicyDN, pszCurrentDN, FALSE))
            {
                dIndexToRemove = index;
                break;
            }
        }

        if (dIndexToRemove != -1)
        {
            dwError = json_array_remove(jsongpLinkArray, dIndexToRemove);
            if (dwError)
            {
                dwError = ERROR_GP_JSON_ARRAY_DELETE_FAILED;
                BAIL_ON_VMAFD_ERROR(dwError);
            }

            pszUpdatedgpLink = json_dumps(jsongpLinkArray, 0);
            if (!pszUpdatedgpLink)
            {
                dwError = ERROR_GP_JSON_CONVERSION_ERROR;
                BAIL_ON_VMAFD_ERROR(dwError);
            }

            dwError = DirCliLdapUpdateAttribute(
                          pLd,
                          pszDomainDN,
                          ATTR_NAME_GPLINK,
                          pszUpdatedgpLink,
                          FALSE);
            BAIL_ON_VMAFD_ERROR(dwError);
        }
        else
        {
            // Attribute exists, but not linked
            dwError = ERROR_GP_NO_SUCH_LINK;
            BAIL_ON_VMAFD_ERROR(dwError);
        }
    }
    else
    {
        // Attribute doesn't exist, nothing to unlink
        dwError = ERROR_GP_NO_SUCH_LINK;
        BAIL_ON_VMAFD_ERROR(dwError);
    }

    fprintf(
        stdout,
        "Policy \"%s\" successfully unlinked from domain \"%s\" \n",
        pPolicyObject->pszPolicyName,
        pszDomainDN);
cleanup:
    if (pPolicyObject)
    {
        DirCliGPFreePolicyObject(pPolicyObject);
    }
    if (jsonStrPolicyDN)
    {
        json_decref(jsonStrPolicyDN);
    }
    if (jsongpLinkArray)
    {
        json_decref(jsongpLinkArray);
    }

    VMAFD_SAFE_FREE_MEMORY(pError);
    VMAFD_SAFE_FREE_MEMORY(pszPolicyDN);
    VMAFD_SAFE_FREE_MEMORY(pszDomainDN);
    VMAFD_SAFE_FREE_MEMORY(pszCurrentgpLink);
    VMAFD_SAFE_FREE_MEMORY(pszUpdatedgpLink);

    return dwError;

error:
    fprintf(stdout, "Policy unlink failed!! \n");
    DirCliGPShowJsonError(pError);
    goto cleanup;
}

/*
    Links a given policy to an OU.
 */

DWORD
DirCliGPLinkPolicyToOU(
    LDAP *pLd,
    PCSTR pszPolicyName,
    PCSTR pszOuDN,
    PCSTR pszDomain
    )
{
    DWORD dwError = 0;
    PSTR pszPolicyDN = NULL;
    PSTR pszDomainDN = NULL;
    PSTR pszCurrentgpLink = NULL;
    PSTR pszUpdatedgpLink = NULL;
    const char * pszCurrentDN = NULL;
    BOOLEAN bExists = FALSE;
    BOOLEAN bAlreadyLinked = FALSE;
    json_t *jsonStrPolicyDN = NULL;
    json_t *jsongpLinkArray = NULL;
    json_error_t *pError = NULL;
    size_t index = 0;
    json_t *value = NULL;
    PDIR_GROUP_POLICY_OBJECT pPolicyObject = NULL;

    if (!pLd                               ||
        IsNullOrEmptyString(pszPolicyName) ||
        IsNullOrEmptyString(pszOuDN)       ||
        IsNullOrEmptyString(pszDomain))
    {
        dwError = ERROR_INVALID_PARAMETER;
        BAIL_ON_VMAFD_ERROR(dwError);
    }

    dwError = DirCliGetDomainDN(pszDomain, &pszDomainDN);
    BAIL_ON_VMAFD_ERROR(dwError);

    dwError = DirCliGPFindPolicyByName(
                  pLd,
                  pszPolicyName,
                  pszDomain,
                  &pPolicyObject);
    BAIL_ON_VMAFD_ERROR(dwError);

    if (IsNullOrEmptyString(pPolicyObject->pszPolicyCN) ||
        IsNullOrEmptyString(pPolicyObject->pszDomainDN))
    {
        dwError = ERROR_INVALID_PARAMETER;
        BAIL_ON_VMAFD_ERROR(dwError);
    }

    // form a policyDN from the policy object
    dwError = VmAfdAllocateStringPrintf(
                  &pszPolicyDN,
                  "cn=%s,cn=Policies,cn=System,%s",
                  pPolicyObject->pszPolicyCN,
                  pPolicyObject->pszDomainDN);
    BAIL_ON_VMAFD_ERROR(dwError);

    // Check if the gpLink attribute is present in the domain path?
    dwError = DirCliLdapGetAttribute(
                  pLd,
                  pszOuDN,
                  ATTR_NAME_GPLINK,
                  &bExists,
                  &pszCurrentgpLink);
    BAIL_ON_VMAFD_ERROR(dwError);

    jsonStrPolicyDN = json_string(pszPolicyDN);
    if (!jsonStrPolicyDN)
    {
        dwError = ERROR_GP_JSON_CONVERSION_ERROR;
        BAIL_ON_VMAFD_ERROR(dwError);
    }

    if (bExists)
    {
        // Attribute already exists
        jsongpLinkArray = json_loads(pszCurrentgpLink, 0, pError);
        if (!jsongpLinkArray)
        {
            dwError = ERROR_GP_GPLINK_JSON_ERROR;
            BAIL_ON_VMAFD_ERROR(dwError);
        }

        // See it it already linked
        json_array_foreach(jsongpLinkArray, index, value)
        {
            pszCurrentDN = json_string_value(value);
            if(!pszCurrentDN)
            {
                dwError = ERROR_GP_JSON_CONVERSION_ERROR;
                BAIL_ON_VMAFD_ERROR(dwError);
            }

            if (!VmAfdStringCompareA(
                    pszPolicyDN,
                    pszCurrentDN,
                    FALSE))
            {
                fprintf(
                    stdout,
                    "Policy \"%s\" already linked to OU \"%s\"\n",
                    pPolicyObject->pszPolicyName,
                    pszOuDN);

                bAlreadyLinked = TRUE;
            }
        }

        if (!bAlreadyLinked)
        {
            dwError = json_array_append(jsongpLinkArray, jsonStrPolicyDN);
            BAIL_ON_VMAFD_ERROR(dwError);

            pszUpdatedgpLink = json_dumps(jsongpLinkArray, 0);
            if (!pszUpdatedgpLink)
            {
                dwError = ERROR_GP_JSON_CONVERSION_ERROR;
                BAIL_ON_VMAFD_ERROR(dwError);
            }

            dwError = DirCliLdapUpdateAttribute(
                          pLd,
                          pszOuDN,
                          ATTR_NAME_GPLINK,
                          pszUpdatedgpLink,
                          FALSE);
            BAIL_ON_VMAFD_ERROR(dwError);

            fprintf(
                stdout,
                "Policy \"%s\" successfully linked to OU \"%s\" \n",
                pPolicyObject->pszPolicyName,
                pszOuDN);
        }
    }
    else
    {
        jsongpLinkArray = json_array();
        if(!jsongpLinkArray)
        {
            dwError = ERROR_GP_JSON_ARRAY_INIT_FAILED;
            BAIL_ON_VMAFD_ERROR(dwError);
        }

        dwError = json_array_append(jsongpLinkArray, jsonStrPolicyDN);
        BAIL_ON_VMAFD_ERROR(dwError);

        pszUpdatedgpLink = json_dumps(jsongpLinkArray, 0);
        if (!pszUpdatedgpLink)
        {
            dwError = ERROR_GP_JSON_CONVERSION_ERROR;
            BAIL_ON_VMAFD_ERROR(dwError);
        }

        dwError = DirCliLdapUpdateAttribute(
                      pLd,
                      pszOuDN,
                      ATTR_NAME_GPLINK,
                      pszUpdatedgpLink,
                      FALSE);
        BAIL_ON_VMAFD_ERROR(dwError);

        fprintf(
            stdout,
            "Policy \"%s\" successfully linked to OU \"%s\" \n",
            pPolicyObject->pszPolicyName,
            pszOuDN);
    }

cleanup:
    if (pPolicyObject)
    {
        DirCliGPFreePolicyObject(pPolicyObject);
    }
    if (jsonStrPolicyDN)
    {
        json_decref(jsonStrPolicyDN);
    }
    if (jsongpLinkArray)
    {
        json_decref(jsongpLinkArray);
    }

    VMAFD_SAFE_FREE_MEMORY(pError);
    VMAFD_SAFE_FREE_MEMORY(pszPolicyDN);
    VMAFD_SAFE_FREE_MEMORY(pszDomainDN);
    VMAFD_SAFE_FREE_MEMORY(pszCurrentgpLink);
    VMAFD_SAFE_FREE_MEMORY(pszUpdatedgpLink);

    return dwError;

error:
    fprintf(stdout, "Policy link failed!! \n");
    DirCliGPShowJsonError(pError);
    goto cleanup;
}

/*
    Unlinks a given policy from a OU.
 */
DWORD
DirCliGPUnlinkPolicyfromOU(
    LDAP *pLd,
    PCSTR pszPolicyName,
    PCSTR pszOuDN,
    PCSTR pszDomain
    )
{
    DWORD dwError = 0;
    PSTR pszPolicyDN = NULL;
    PSTR pszDomainDN = NULL;
    PSTR pszCurrentgpLink = NULL;
    PSTR pszUpdatedgpLink = NULL;
    const char * pszCurrentDN =NULL;
    BOOLEAN bExists = FALSE;
    int dIndexToRemove = -1;
    json_t *jsonStrPolicyDN = NULL;
    json_t *jsongpLinkArray = NULL;
    json_error_t *pError = NULL;
    size_t index = 0;
    json_t *value = NULL;
    PDIR_GROUP_POLICY_OBJECT pPolicyObject = NULL;

    if (!pLd                               ||
        IsNullOrEmptyString(pszPolicyName) ||
        IsNullOrEmptyString(pszOuDN)       ||
        IsNullOrEmptyString(pszDomain))
    {
        dwError = ERROR_INVALID_PARAMETER;
        BAIL_ON_VMAFD_ERROR(dwError);
    }

    dwError = DirCliGetDomainDN(pszDomain, &pszDomainDN);
    BAIL_ON_VMAFD_ERROR(dwError);

    dwError = DirCliGPFindPolicyByName(
                  pLd,
                  pszPolicyName,
                  pszDomain,
                  &pPolicyObject);
    BAIL_ON_VMAFD_ERROR(dwError);

    if (IsNullOrEmptyString(pPolicyObject->pszPolicyCN) ||
        IsNullOrEmptyString(pPolicyObject->pszDomainDN))
    {
        dwError = ERROR_INVALID_PARAMETER;
        BAIL_ON_VMAFD_ERROR(dwError);
    }

    // form a policyDN from the policy object
    dwError = VmAfdAllocateStringPrintf(
                  &pszPolicyDN,
                  "cn=%s,cn=Policies,cn=System,%s",
                  pPolicyObject->pszPolicyCN,
                  pPolicyObject->pszDomainDN);
    BAIL_ON_VMAFD_ERROR(dwError);

    // Check if the gpLink attribute is present in the domain path?
    dwError = DirCliLdapGetAttribute(
                 pLd,
                 pszOuDN,
                 ATTR_NAME_GPLINK,
                 &bExists,
                 &pszCurrentgpLink);
    BAIL_ON_VMAFD_ERROR(dwError);

    jsonStrPolicyDN = json_string(pszPolicyDN);
    if (!jsonStrPolicyDN)
    {
        dwError = ERROR_GP_JSON_CONVERSION_ERROR;
        BAIL_ON_VMAFD_ERROR(dwError);
    }

    if (bExists)
    {
         // Attribute already exists
        jsongpLinkArray = json_loads(
                              pszCurrentgpLink,
                              0,
                              pError);
        if (!jsongpLinkArray)
        {
            dwError = ERROR_GP_GPLINK_JSON_ERROR;
            BAIL_ON_VMAFD_ERROR(dwError);
        }

        // See if its linked ?
        json_array_foreach(jsongpLinkArray, index, value)
        {
            pszCurrentDN = json_string_value(value);
            if(!pszCurrentDN)
            {
                dwError = ERROR_GP_JSON_CONVERSION_ERROR;
                BAIL_ON_VMAFD_ERROR(dwError);
            }

            if (!VmAfdStringCompareA(pszPolicyDN,pszCurrentDN,FALSE))
            {
                dIndexToRemove = index;
                break;
            }
        }

        if (dIndexToRemove != -1)
        {
            dwError = json_array_remove(jsongpLinkArray, dIndexToRemove);
            if (dwError)
            {
                dwError = ERROR_GP_JSON_ARRAY_DELETE_FAILED;
                BAIL_ON_VMAFD_ERROR(dwError);
            }

            pszUpdatedgpLink = json_dumps(jsongpLinkArray, 0);
            if(!pszUpdatedgpLink)
            {
                dwError = ERROR_GP_JSON_CONVERSION_ERROR;
                BAIL_ON_VMAFD_ERROR(dwError);
            }

            dwError = DirCliLdapUpdateAttribute(
                          pLd,
                          pszOuDN,
                          ATTR_NAME_GPLINK,
                          pszUpdatedgpLink,
                          FALSE);
            BAIL_ON_VMAFD_ERROR(dwError);
        }
        else
        {
            // Attribute exists, but not linked
            dwError = ERROR_GP_NO_SUCH_LINK;
            BAIL_ON_VMAFD_ERROR(dwError);
        }
    }
    else
    {
        // Attribute doesn't exist, nothing to unlink
        dwError = ERROR_GP_NO_SUCH_LINK;
        BAIL_ON_VMAFD_ERROR(dwError);
    }

    fprintf(
        stdout,
        "Policy \"%s\" successfully unlinked from OU \"%s\" \n",
        pPolicyObject->pszPolicyName,
        pszOuDN);
cleanup:

    if (pPolicyObject)
    {
        DirCliGPFreePolicyObject(pPolicyObject);
    }
    if (jsonStrPolicyDN)
    {
        json_decref(jsonStrPolicyDN);
    }
    if (jsongpLinkArray)
    {
        json_decref(jsongpLinkArray);
    }

    VMAFD_SAFE_FREE_MEMORY(pError);
    VMAFD_SAFE_FREE_MEMORY(pszPolicyDN);
    VMAFD_SAFE_FREE_MEMORY(pszDomainDN);
    VMAFD_SAFE_FREE_MEMORY(pszCurrentgpLink);
    VMAFD_SAFE_FREE_MEMORY(pszUpdatedgpLink);

    return dwError;

error:
    fprintf(stdout, "Policy unlink failed!! \n");
    goto cleanup;
}

/*
    Prints the in-memory GPLink Linked List.
 */

DWORD
DirCliGPPrintGplinkList(
    const GPLINK_LIST *pgPLinkList
    )
{
    DWORD dwError = 0;
    DWORD dwCount = 0;

    fprintf(stdout, "Printing gPList\n");

    if (!pgPLinkList)
    {
        fprintf(stdout, "gPList is empty \n");
    }
    while (pgPLinkList)
    {
        fprintf(
            stdout,
            " %d DN: %s  \n gPLink: %s \n",
            dwCount,
            pgPLinkList->pszObjectDN,
            pgPLinkList->pszgPlink);
        pgPLinkList = pgPLinkList->pNext;
        dwCount++;
    }

    return dwError;
}

/*
    Frees in-memory GPLink Linked List.
 */

void
DirCliGPFreegPLinkList(
    PGPLINK_LIST pgPLinkList
    )
{
    PGPLINK_LIST pgPLinkListNext = NULL;

    while (pgPLinkList)
    {
        pgPLinkListNext = pgPLinkList->pNext;
        VMAFD_SAFE_FREE_MEMORY(pgPLinkList->pszObjectDN);
        VMAFD_SAFE_FREE_MEMORY(pgPLinkList->pszgPlink);
        VMAFD_SAFE_FREE_MEMORY(pgPLinkList);
        pgPLinkList = pgPLinkListNext;
    }
}

/*
    Returns a list of all the top level DN's for a given DN and its
   corresponding links. It is a list of parentDN's starting with "OU" or "DN".
*/
DWORD
DirCliGPGetScopeOfManagementList(
    LDAP *pLd,
    PCSTR pszTargetDN,
    PGPLINK_LIST *ppgPLinkList
    )
{
    DWORD dwError = 0;
    PSTR pszFirstAttr = NULL;
    PSTR pszObjectDN = NULL;
    PSTR pszParentDN = NULL;
    PSTR pszgPLink = NULL;
    BOOLEAN bExists = FALSE;
    PGPLINK_LIST pgPLinkList = NULL;
    PGPLINK_LIST pgPLinkListHead = NULL;
    PGPLINK_LIST pTemp = NULL;


    if(!pLd || IsNullOrEmptyString(pszTargetDN) || !ppgPLinkList )
    {
        dwError = ERROR_INVALID_PARAMETER;
        BAIL_ON_VMAFD_ERROR(dwError);
    }

    // Make a copy of the incoming string
    dwError = VmAfdAllocateStringA(pszTargetDN,&pszObjectDN);
    BAIL_ON_VMAFD_ERROR(dwError);

    while (1)
    {
        //Get the attribute of the current DN.
        dwError = DirCliGPGetFirstAttributeofDN(pszObjectDN, &pszFirstAttr);
        BAIL_ON_VMAFD_ERROR(dwError);

        fprintf(stdout,"Scanning, DN: %s , Attr: %s \n",pszObjectDN,pszFirstAttr);

        if (!VmAfdStringCompareA(pszFirstAttr, "DC", FALSE) ||
            !VmAfdStringCompareA(pszFirstAttr, "OU", FALSE))
        {
            dwError = VmAfdAllocateMemory(
                          sizeof(GPLINK_LIST),
                          (void **)&pgPLinkList);
            BAIL_ON_VMAFD_ERROR(dwError);

            //Check if there are policies associated with the given OU or DC DN?
            dwError = DirCliLdapGetAttribute(
                          pLd,
                          pszObjectDN,
                          ATTR_NAME_GPLINK,
                          &bExists,
                          &pszgPLink);
            BAIL_ON_VMAFD_ERROR(dwError);

            //Copy the DNs and policy links
            if (bExists)
            {
                //Copy the DNs
                dwError = VmAfdAllocateStringA(pszObjectDN,&pgPLinkList->pszObjectDN);
                BAIL_ON_VMAFD_ERROR(dwError);

                //Copy the linked policies.
                dwError = VmAfdAllocateStringA(pszgPLink,&pgPLinkList->pszgPlink);
                BAIL_ON_VMAFD_ERROR(dwError);
            }
            if (!pgPLinkListHead)
            {
                pgPLinkListHead = pgPLinkList;
            }
            else
            {
                //Tail add Linked List
                pTemp = pgPLinkListHead;
                while (pTemp && pTemp->pNext)
                    pTemp = pTemp->pNext;
                pTemp->pNext = pgPLinkList;
            }
            pgPLinkList = NULL;

            // Add it to the linked list untill we encounter DN.
            if (!VmAfdStringCompareA(pszFirstAttr, "DC", FALSE))
            {
                break;
            }

            //Get the parent DN and recurse through the search.
            dwError = DirCliGPGetParentDN(pszObjectDN, 1, &pszParentDN);
            BAIL_ON_VMAFD_ERROR(dwError);

            // free loop variables being reused
            VMAFD_SAFE_FREE_MEMORY(pszObjectDN);
            VMAFD_SAFE_FREE_MEMORY(pszgPLink);
            VMAFD_SAFE_FREE_MEMORY(pszFirstAttr);

            pszObjectDN = pszParentDN;
        }
    }

    *ppgPLinkList = pgPLinkListHead;

cleanup:
    VMAFD_SAFE_FREE_MEMORY(pszObjectDN);
    VMAFD_SAFE_FREE_MEMORY(pszgPLink);
    VMAFD_SAFE_FREE_MEMORY(pszFirstAttr);
    return dwError;

error:
    if (ppgPLinkList)
    {
        *ppgPLinkList = NULL;
    }
    if (pgPLinkListHead)
    {
        DirCliGPFreegPLinkList(pgPLinkListHead);
    }
    goto cleanup;
}

/*
    Reverses the singly linked list inplace
*/

DWORD
DirCliGPReverseLinkedList(
    PGPLINK_LIST pgPLinkList,
    PGPLINK_LIST *ppgPLinkListReversed
    )
{
    DWORD dwError = 0;
    PGPLINK_LIST pgPLinkListHead = NULL;
    PGPLINK_LIST pgPLinkListRest = NULL;
    PGPLINK_LIST pgPLinkListTemp = NULL;

    if (!pgPLinkList || !ppgPLinkListReversed)
    {
        dwError = ERROR_INVALID_PARAMETER;
        BAIL_ON_VMAFD_ERROR(dwError);
    }
    //Init the head to the incoming list
    pgPLinkListHead = pgPLinkList;

    //Separate the head and body
    pgPLinkListRest = pgPLinkListHead->pNext;
    pgPLinkListHead->pNext = NULL;

    //Iterate through the end of list
    while (pgPLinkListRest != NULL)
    {
        pgPLinkListTemp = pgPLinkListRest->pNext;
        pgPLinkListRest->pNext = pgPLinkListHead;
        pgPLinkListHead = pgPLinkListRest;
        pgPLinkListRest = pgPLinkListTemp;
    }

    *ppgPLinkListReversed = pgPLinkListHead;

cleanup:
    return dwError;

error:
    if(ppgPLinkListReversed)
    {
        *ppgPLinkListReversed =NULL;
    }
    goto cleanup;
}

/*
    Forms the final list of applicable policies for a given DN.
*/

DWORD
DirCliGPGetResultantPolicesForDN(
    LDAP *pLd,
    PCSTR psztargetDN,
    PCSTR pszDomain,
    PDIR_GROUP_POLICY_OBJECT *ppPolicyObjectHead
    )
{
    DWORD dwError = 0;
    PGPLINK_LIST pSOMlist =NULL;
    PGPLINK_LIST pSOMlistReverse = NULL;
    PDIR_GROUP_POLICY_OBJECT pPolicyObjectHead = NULL;

    if(!pLd || IsNullOrEmptyString(psztargetDN) || !ppPolicyObjectHead)
    {
        dwError = ERROR_INVALID_PARAMETER;
        BAIL_ON_VMAFD_ERROR(dwError);
    }

    // Get the scope of managemnt list for the given DN
    dwError = DirCliGPGetScopeOfManagementList(
                 pLd,
                 psztargetDN,
                 &pSOMlist);
    BAIL_ON_VMAFD_ERROR(dwError);

    //Reverse the SOM list
    dwError= DirCliGPReverseLinkedList(
                 pSOMlist,
                 &pSOMlistReverse);
    BAIL_ON_VMAFD_ERROR(dwError);

    //Process the SOM list and get the resultant policies.
    dwError = DirCliGPProcessSOMListForPolicies(
                  pLd,
                  pSOMlistReverse,
                  pszDomain,
                  &pPolicyObjectHead
    );
    BAIL_ON_VMAFD_ERROR(dwError);

    *ppPolicyObjectHead = pPolicyObjectHead;

cleanup:
    if(pSOMlist)
    {
        DirCliGPFreegPLinkList(pSOMlist);
    }

    return dwError;
error:
    if(ppPolicyObjectHead)
    {
        *ppPolicyObjectHead =NULL;
    }
    if(pPolicyObjectHead)
    {
        DirCliGPFreePolicyObject(pPolicyObjectHead);
    }
    goto cleanup;
}

/*
   Takes the reversed SOM list, processes each link and returns the final
   policy list.
*/

DWORD
DirCliGPProcessSOMListForPolicies(
    LDAP *pLd,
    PGPLINK_LIST pgPLinkList,
    PCSTR pszDomain,
    PDIR_GROUP_POLICY_OBJECT *ppPolicyObjectHead
    )
{
    DWORD dwError =0;
    json_t *jsongpLinkArray = NULL;
    size_t index = 0;
    json_t *value = NULL;
    json_error_t *pError = NULL;
    const char *pszCurrentDN = NULL;
    PSTR pszPolicyName =NULL;
    BOOLEAN bExists =FALSE;
    DWORD dwPolicyOrder =0;
    PDIR_GROUP_POLICY_OBJECT pPolicyObjectHead = NULL;
    PDIR_GROUP_POLICY_OBJECT pPolicyObject = NULL;
    PDIR_GROUP_POLICY_OBJECT pTemp = NULL;

    if(!pLd || !pgPLinkList || IsNullOrEmptyString(pszDomain) || !ppPolicyObjectHead)
    {
        dwError = ERROR_INVALID_PARAMETER;
        BAIL_ON_VMAFD_ERROR(dwError);
    }

    //Process links in from the SOM list
    while(pgPLinkList)
    {
        //fprintf(stdout,"Processing policies from object %s \n",pgPLinkList->pszObjectDN);
        // Parse the json and exact individual links
        jsongpLinkArray = json_loads(pgPLinkList->pszgPlink, 0, pError);
        if (!jsongpLinkArray)
        {
            dwError = ERROR_GP_GPLINK_JSON_ERROR;
            BAIL_ON_VMAFD_ERROR(dwError);
        }

        //For each individual link, get the policy
        json_array_foreach(jsongpLinkArray, index, value)
        {
            pszCurrentDN = json_string_value(value);
            if (!pszCurrentDN)
            {
                dwError = ERROR_GP_JSON_CONVERSION_ERROR;
                BAIL_ON_VMAFD_ERROR(dwError);
            }

            //Get the policy name from policy DN.
            dwError = DirCliGPGetPolicyNameFromPolicyDN(
                          pLd,
                          pszCurrentDN,
                          &pszPolicyName);
            BAIL_ON_VMAFD_ERROR(dwError);

            dwError = DirCliGPCheckIfPolicyExistsInList(
                          pPolicyObjectHead,
                          pszPolicyName,
                          &bExists);
            BAIL_ON_VMAFD_ERROR(dwError);

            // if the  policy does already exists in the policy list
            // add the policy to the list
            if (!bExists)
            {
                // get the policy object
                dwError = DirCliGPFindPolicyByName(
                              pLd,
                              pszPolicyName,
                              pszDomain,
                              &pPolicyObject);
                BAIL_ON_VMAFD_ERROR(dwError);

                //Add the attributes  of order and kind to the policy
                dwError = DirCliGPAddKindAndOrderToPolicy(
                              pLd,
                              pgPLinkList->pszObjectDN,
                              dwPolicyOrder,
                              pPolicyObject);
                BAIL_ON_VMAFD_ERROR(dwError);

                if (!pPolicyObjectHead)
                {
                    pPolicyObjectHead = pPolicyObject;
                }
                else
                {
                    //Tail add Linked List
                    pTemp = pPolicyObjectHead;
                    while (pTemp && pTemp->pNext)
                        pTemp = pTemp->pNext;
                    pTemp->pNext = pPolicyObject;
                }
                pPolicyObject = NULL;
            }

            //free for reuse
            VMAFD_SAFE_FREE_MEMORY(pszPolicyName);
        }

        //if the there links in the list increment the order.
        if(json_array_size(jsongpLinkArray)!=0)
        {
            dwPolicyOrder++;
        }

        //free for reuse
        if (jsongpLinkArray)
        {
            json_decref(jsongpLinkArray);
            jsongpLinkArray = NULL;
        }

        //Process the next link
        pgPLinkList = pgPLinkList->pNext;
    }

    *ppPolicyObjectHead =pPolicyObjectHead;

cleanup:
    if (jsongpLinkArray)
    {
        json_decref(jsongpLinkArray);
        jsongpLinkArray = NULL;
    }

    VMAFD_SAFE_FREE_MEMORY(pError);
    VMAFD_SAFE_FREE_MEMORY(pszPolicyName);

    return dwError;

error:
    if(pPolicyObjectHead)
    {
        DirCliGPFreePolicyObject(pPolicyObjectHead);
    }

    goto cleanup;
}

/*
    Adds the kind of the policy i.e Domain, OU.
    Adds the implementation order of polcies.
    Policies of the same DN have the same  implementation order number.
*/

DWORD
DirCliGPAddKindAndOrderToPolicy(
    LDAP *pLd,
    PCSTR pszObjectDN,
    DWORD dwPolicyOrder,
    PDIR_GROUP_POLICY_OBJECT pPolicyObject
    )
{
    DWORD dwError =0;
    PSTR pszAttr = NULL;
    json_t * jsonPolicyDataObject = NULL;
    json_t * jsonOrder =NULL;
    json_t * jsonKind  =NULL;
    json_error_t *pError = NULL;

    if(!pLd || IsNullOrEmptyString(pszObjectDN) || !pPolicyObject)
    {
        dwError = ERROR_INVALID_PARAMETER;
        BAIL_ON_VMAFD_ERROR(dwError);
    }

    jsonPolicyDataObject = json_loads(
        pPolicyObject->pszPolicyJson,
        0,
        pError);
    if (!jsonPolicyDataObject)
    {
        dwError = ERROR_GP_GPLINK_JSON_ERROR;
        BAIL_ON_VMAFD_ERROR(dwError);
    }

    //Add the order to the policy object
    jsonOrder=json_integer(dwPolicyOrder);
    if (!jsonOrder)
    {
        dwError = ERROR_GP_JSON_CONVERSION_ERROR;
        BAIL_ON_VMAFD_ERROR(dwError);
    }

    //Steals the reference for jsonOrder
    dwError = json_object_set_new(jsonPolicyDataObject,"order",jsonOrder);
    BAIL_ON_VMAFD_ERROR(dwError);

    //Add the policy kind to the policy object
    dwError = DirCliGPGetFirstAttributeofDN(pszObjectDN,&pszAttr);
    BAIL_ON_VMAFD_ERROR(dwError);

    if (!VmAfdStringCompareA(pszAttr,"OU", FALSE))
    {
        jsonKind = json_string("ou");
        if (!jsonKind)
        {
            dwError = ERROR_GP_JSON_CONVERSION_ERROR;
            BAIL_ON_VMAFD_ERROR(dwError);
        }
    }
    else if(!VmAfdStringCompareA(pszAttr,"DC", FALSE))
    {
        jsonKind = json_string("domain");
        if (!jsonKind)
        {
            dwError = ERROR_GP_JSON_CONVERSION_ERROR;
            BAIL_ON_VMAFD_ERROR(dwError);
        }
    }
    else
    {
        //Invalid DN
        dwError = ERROR_INVALID_PARAMETER;
        BAIL_ON_VMAFD_ERROR(dwError);
    }

    //Add the policy kind
    dwError = json_object_set_new(jsonPolicyDataObject,"kind",jsonKind);
    BAIL_ON_VMAFD_ERROR(dwError);

    //Free old policy
    VMAFD_SAFE_FREE_MEMORY(pPolicyObject->pszPolicyJson);

    //Add the new policy object
    pPolicyObject->pszPolicyJson = json_dumps(jsonPolicyDataObject, 0);
    if (!pPolicyObject->pszPolicyJson)
    {
        dwError = ERROR_GP_JSON_CONVERSION_ERROR;
        BAIL_ON_VMAFD_ERROR(dwError);
    }

cleanup:
    if(jsonPolicyDataObject)
    {
        json_decref(jsonPolicyDataObject);
    }

    VMAFD_SAFE_FREE_MEMORY(pError);
    VMAFD_SAFE_FREE_MEMORY(pszAttr);
    return dwError;

error:
    goto cleanup;
}

/*
    Checks if the policy already exists in the policy list.
    Don't add duplicate policies in to the list
*/

DWORD
DirCliGPCheckIfPolicyExistsInList(
    const DIR_GROUP_POLICY_OBJECT *pPolicyObjectHead,
    PCSTR pszPolicyName,
    PBOOLEAN pbExists
    )
{
    DWORD dwError = 0;
    *pbExists = FALSE;

    if(IsNullOrEmptyString(pszPolicyName) || !pbExists)
    {
        dwError = ERROR_INVALID_PARAMETER;
        BAIL_ON_VMAFD_ERROR(dwError);
    }

    while (pPolicyObjectHead)
    {
        if (!VmAfdStringCompareA(
                pPolicyObjectHead->pszPolicyName,
                pszPolicyName,
                FALSE))
        {
            *pbExists = TRUE;
            break;
        }
        pPolicyObjectHead = pPolicyObjectHead->pNext;
    }

cleanup:
    return dwError;

error:
    if (pbExists)
    {
        *pbExists = FALSE;
    }
    goto cleanup;
}

/*
   Return the first attribute of a DN.
   if DN : OU=Business,OU=HR,CN=Leo, Returns "OU"
*/

DWORD
DirCliGPGetFirstAttributeofDN(
    PCSTR pszObjectDN,
    PSTR *ppszAttr
    )
{
    DWORD dwError = 0;
    int flags =0;
    LDAPDN ldapDN = NULL;
    LDAPDN ldapDNHead = NULL;
    PSTR pszAttr = NULL;

    if(IsNullOrEmptyString(pszObjectDN) || !ppszAttr)
    {
        dwError = ERROR_INVALID_PARAMETER;
        BAIL_ON_VMAFD_ERROR(dwError);
    }

    dwError = ldap_str2dn(pszObjectDN, &ldapDN, flags);
    BAIL_ON_VMAFD_ERROR(dwError);

    ldapDNHead = ldapDN;

    if(*ldapDN != NULL)
    {
        dwError = DirCliGPGetStrFromBerval((**ldapDN)->la_attr,&pszAttr);
        BAIL_ON_VMAFD_ERROR(dwError);
    }

    *ppszAttr = pszAttr;

cleanup:
    if (ldapDNHead)
    {
        ldap_dnfree(ldapDNHead);
    }
    return dwError;

error:
    if(ppszAttr)
    {
        *ppszAttr =NULL;
    }
    VMAFD_SAFE_FREE_MEMORY(pszAttr);
    goto cleanup;
}
