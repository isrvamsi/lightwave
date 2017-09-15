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

//options for group policies

static struct option _pstGpOptions[] =
    {
        {OPT_SERVERNAME, required_argument, 0, 0}, //--server-name
        {OPT_DOMAINNAME, required_argument, 0, 0}, //--domain-name
        {OPT_LOGIN,      required_argument, 0, 0}, //--login
        {OPT_PASSWORD,   required_argument, 0, 0}, //--password
        {OPT_TARGET_DN,  required_argument, 0, 0}, //--object-dn
        {OPT_JSON_FILE,  required_argument, 0, 0}, //--json-file
        {OPT_POLICY_NAME,required_argument, 0, 0}, //--policy-name
        {       0       ,         0       , 0, 0}  // NULL
    };

DWORD
DirCliExecGPRequest(
    int   argc,
    char* argv[]
    )
{
    DWORD dwError = 0;
    PGP_CLI_ARGS pGPArgs = NULL;

    if (!argc || !argv)
    {
        dwError = ERROR_INVALID_PARAMETER;
        BAIL_ON_VMAFD_ERROR(dwError);
    }

    //Allocate memory for the args
    dwError = VmAfdAllocateMemory(
                  sizeof(GP_CLI_ARGS),
                  (void **)&pGPArgs);
    BAIL_ON_VMAFD_ERROR(dwError);

    //Get the command from the args
    dwError = VmAfdAllocateStringA(argv[0],&pGPArgs->pszGPCommand);
    BAIL_ON_VMAFD_ERROR(dwError);

    //Get the command line args from the rest of the string
    dwError = DirCliGPParseCliArgs(argc, argv, pGPArgs);
    BAIL_ON_VMAFD_ERROR(dwError);

    //Check if a help command is issued
    if(!VmAfdStringCompareA(
            pGPArgs->pszGPCommand,
            COMMAND_GP_HELP,
            FALSE))
    {
        DirCliGPShowHelp();
    }
    else
    {
        //Route according to the command
        dwError = DirCliGPRouteCliCmd(pGPArgs);
        BAIL_ON_VMAFD_ERROR(dwError);
    }

cleanup:
    if(pGPArgs)
    {
        DirCliGPFreeGPArgs(pGPArgs);
    }
    return dwError;

error:
    goto cleanup;
}

DWORD
DirCliGPParseCliArgs(
    int argc,
    char *argv[],
    PGP_CLI_ARGS pGPArgs
    )
{
    DWORD dwError =0;
    int nOptionIndex =0;
    int nOption =0;

    while (1)
    {

        nOption = getopt_long(
                      argc,
                      argv,
                      "",
                      _pstGpOptions,
                      &nOptionIndex);
        if (nOption == -1)
            break;

        switch (nOptionIndex)
        {
        case 0:
            dwError = VmAfdAllocateStringA(optarg,&pGPArgs->pszServer);
            break;
        case 1:
            dwError = VmAfdAllocateStringA(optarg,&pGPArgs->pszDomain);
            break;
        case 2:
            dwError = VmAfdAllocateStringA(optarg,&pGPArgs->pszLogin);
            break;
        case 3:
            dwError = VmAfdAllocateStringA(optarg,&pGPArgs->pszPassword);
            break;
        case 4:
            dwError = VmAfdAllocateStringA(optarg,&pGPArgs->pszTargetDN);
            break;
        case 5:
            dwError = VmAfdAllocateStringA(optarg,&pGPArgs->pszJsonFile);
            break;
        case 6:
            dwError = VmAfdAllocateStringA(optarg,&pGPArgs->pszPolicyName);
            break;
        default:
            fprintf(stdout,"unrecognised arguments \n");
            dwError = ERROR_INVALID_PARAMETER;
        }
        BAIL_ON_VMAFD_ERROR(dwError);
    }
    if (optind < argc)
    {
        fprintf(stdout,"\n Invalid arguments: ");
        while (optind < argc)
        {
            if(!IsNullOrEmptyString(argv[optind]))
            {
                fprintf(stdout,"%s ", argv[optind++]);
            }
        }
    }

cleanup:
    return dwError;

error:
    goto cleanup;

}

DWORD
DirCliGPPrintCliArgs(
    const GP_CLI_ARGS *pGPArgs
    )
{
    DWORD dwError =0;

    if(!pGPArgs)
    {
        dwError = ERROR_INVALID_PARAMETER;
        BAIL_ON_VMAFD_ERROR(dwError);
    }

    if (!IsNullOrEmptyString(pGPArgs->pszServer))
    {
        fprintf(stdout, "Servername : %s \n", pGPArgs->pszServer);
    }
    if (!IsNullOrEmptyString(pGPArgs->pszDomain))
    {
        fprintf(stdout, "Domain name : %s \n", pGPArgs->pszDomain);
    }
    if (!IsNullOrEmptyString(pGPArgs->pszLogin))
    {
        fprintf(stdout, "Login : %s \n", pGPArgs->pszLogin);
    }
    if (!IsNullOrEmptyString(pGPArgs->pszPassword))
    {
        fprintf(stdout, "Password : %s \n", pGPArgs->pszPassword);
    }
    if (!IsNullOrEmptyString(pGPArgs->pszTargetDN))
    {
        fprintf(stdout, "ObjectDN : %s \n", pGPArgs->pszTargetDN);
    }
    if (!IsNullOrEmptyString(pGPArgs->pszJsonFile))
    {
        fprintf(stdout, "Json File : %s \n", pGPArgs->pszJsonFile);
    }
    if (!IsNullOrEmptyString(pGPArgs->pszPolicyName))
    {
        fprintf(stdout, "Policy name : %s \n", pGPArgs->pszPolicyName);
    }
    if (!IsNullOrEmptyString(pGPArgs->pszGPCommand))
    {
        fprintf(stdout, "Command : %s \n", pGPArgs->pszGPCommand);
    }

error:
    return dwError;
}

void
DirCliGPFreeGPArgs(
    PGP_CLI_ARGS pGPArgs
    )
{
    if(pGPArgs)
    {
        VMAFD_SAFE_FREE_MEMORY(pGPArgs->pszServer);
        VMAFD_SAFE_FREE_MEMORY(pGPArgs->pszDomain);
        VMAFD_SAFE_FREE_MEMORY(pGPArgs->pszLogin);
        VMAFD_SAFE_FREE_MEMORY(pGPArgs->pszPassword);
        VMAFD_SAFE_FREE_MEMORY(pGPArgs->pszTargetDN);
        VMAFD_SAFE_FREE_MEMORY(pGPArgs->pszJsonFile);
        VMAFD_SAFE_FREE_MEMORY(pGPArgs->pszPolicyName);
        VMAFD_SAFE_FREE_MEMORY(pGPArgs->pszGPCommand);
        VMAFD_SAFE_FREE_MEMORY(pGPArgs);
    }
}

DWORD
DirCliGPRouteCliCmd(
    GP_CLI_ARGS *pGPArgs
    )
{
    DWORD dwError=0;
    LDAP *pLd = NULL;
    PDIR_GROUP_POLICY_OBJECT pPolicyObject = NULL;
    PSTR pszPolicyJson =NULL;

    dwError = DirCliGPValidateInitArgs(pGPArgs);
    BAIL_ON_VMAFD_ERROR(dwError);

    //Check if this is a help command and display help command

    //Init connection to LDAP
    dwError = DirCliGPGroupPolicyInit(
                  pGPArgs->pszLogin,
                  pGPArgs->pszPassword,
                  pGPArgs->pszServer,
                  pGPArgs->pszDomain,
                  &pLd);
    BAIL_ON_VMAFD_ERROR(dwError);

    //Start the command routing
    if(!IsNullOrEmptyString(pGPArgs->pszGPCommand))
    {
        if(!VmAfdStringCompareA(pGPArgs->pszGPCommand,COMMAND_GP_CREATE,FALSE))
        {
            //check if the policyname is not NULL or empty
            if (IsNullOrEmptyString(pGPArgs->pszPolicyName))
            {
                fprintf(stdout, "Missing arg %s \n", OPT_POLICY_NAME);
                dwError = ERROR_GP_INVALID_ARGUMENTS;
                BAIL_ON_VMAFD_ERROR(dwError);
            }

            dwError = DirCliGPGetPolicyJsonFromArgs(pGPArgs,&pszPolicyJson);
            BAIL_ON_VMAFD_ERROR(dwError);

            dwError = DirCliGPCreateNewPolicyObject(
                          pGPArgs->pszDomain,
                          pGPArgs->pszPolicyName,
                          pszPolicyJson,
                          &pPolicyObject);
            BAIL_ON_VMAFD_ERROR(dwError);

            dwError = DirCliGPAddPolicyObject(pLd, pPolicyObject);
            BAIL_ON_VMAFD_ERROR(dwError);

            fprintf(stdout, "Adding policy %s complete\n",pGPArgs->pszDomain);
        }
        else if (!VmAfdStringCompareA(
                      pGPArgs->pszGPCommand,
                      COMMAND_GP_READ_POLICIES,
                      FALSE))
        {
            // Get all policies by using the wild character
            dwError = DirCliGPFindPolicyByName(
                          pLd,
                          "*",
                          pGPArgs->pszDomain,
                          &pPolicyObject);
            BAIL_ON_VMAFD_ERROR(dwError);

            dwError = DirCliGPPrintPolicyObject(pPolicyObject);
            BAIL_ON_VMAFD_ERROR(dwError);

            fprintf(stdout,"Reading policy objects complete\n");

        }
        else if(!VmAfdStringCompareA(
                     pGPArgs->pszGPCommand,
                     COMMAND_GP_READ_LINKS,
                     FALSE))
        {
            dwError = DirCliGPListPolicyLinks(pLd);
            BAIL_ON_VMAFD_ERROR(dwError);

            fprintf(stdout,"Reading policy links complete \n");
        }
        else if(!VmAfdStringCompareA(
                     pGPArgs->pszGPCommand,
                     COMMAND_GP_UPDATE_POLICY,
                     FALSE))
        {
            //check if the policyname is not NULL or empty
            if (IsNullOrEmptyString(pGPArgs->pszPolicyName))
            {
                fprintf(stdout, "Missing arg \"%s\" \n", OPT_POLICY_NAME);
                dwError = ERROR_GP_INVALID_ARGUMENTS;
                BAIL_ON_VMAFD_ERROR(dwError);
            }

            dwError = DirCliGPGetPolicyJsonFromArgs(pGPArgs, &pszPolicyJson);
            BAIL_ON_VMAFD_ERROR(dwError);

            //Fetch the existing policy from memory
            dwError = DirCliGPFindPolicyByName(
                          pLd,
                          pGPArgs->pszPolicyName,
                          pGPArgs->pszDomain,
                          &pPolicyObject);
            BAIL_ON_VMAFD_ERROR(dwError);

            dwError = DirCliGPEditPolicyObject(
                          pPolicyObject,
                          pGPArgs->pszPolicyName,
                          pszPolicyJson);
            BAIL_ON_VMAFD_ERROR(dwError);

            dwError = DirCliGPUpdatePolicyObject(pLd, pPolicyObject);
            BAIL_ON_VMAFD_ERROR(dwError);
        }
        else if((!VmAfdStringCompareA(
                      pGPArgs->pszGPCommand,
                      COMMAND_GP_DELETE_POLICY,
                      FALSE)))
        {
            //check if the policyname is not NULL or empty
            if (IsNullOrEmptyString(pGPArgs->pszPolicyName))
            {
                fprintf(stdout, "Missing arg \"%s\" \n", OPT_POLICY_NAME);
                dwError = ERROR_GP_INVALID_ARGUMENTS;
                BAIL_ON_VMAFD_ERROR(dwError);
            }

            dwError=DirCliGPDeletePolicyByName(
                        pLd,
                        pGPArgs->pszPolicyName,
                        pGPArgs->pszDomain);
            BAIL_ON_VMAFD_ERROR(dwError);

            fprintf(stdout,"Deleted policy %s from %s \n",
                               pGPArgs->pszPolicyName,
                               pGPArgs->pszDomain);
        }
        else if(!VmAfdStringCompareA(
                     pGPArgs->pszGPCommand,
                     COMMAND_GP_LINK_POLICY_TO_OU,
                     FALSE))
        {
            dwError = DirCliGPValidateOUArgs(pGPArgs);
            BAIL_ON_VMAFD_ERROR(dwError);

            dwError = DirCliGPLinkPolicyToOU(
                          pLd,
                          pGPArgs->pszPolicyName,
                          pGPArgs->pszTargetDN,
                          pGPArgs->pszDomain);
            BAIL_ON_VMAFD_ERROR(dwError);

            fprintf(stdout,"Linked policy %s to OU: %s \n",
                            pGPArgs->pszPolicyName,
                            pGPArgs->pszTargetDN);
        }
        else if (!VmAfdStringCompareA(
                      pGPArgs->pszGPCommand,
                      COMMAND_GP_LINK_POLICY_TO_DOMAIN,
                      FALSE))
        {
            //Check for policyname
            if (IsNullOrEmptyString(pGPArgs->pszPolicyName))
            {
                fprintf(stdout, "Missing arg \"%s\" \n", OPT_POLICY_NAME);
                dwError = ERROR_GP_INVALID_ARGUMENTS;
                BAIL_ON_VMAFD_ERROR(dwError);
            }

            dwError = DirCliGPLinkPolicyToDomain(
                          pLd,
                          pGPArgs->pszPolicyName,
                          pGPArgs->pszDomain);
            BAIL_ON_VMAFD_ERROR(dwError);

            fprintf(stdout, "Linked policy %s to Domain: %s \n",
                            pGPArgs->pszPolicyName,
                            pGPArgs->pszDomain);
        }
        else if (!VmAfdStringCompareA(
                      pGPArgs->pszGPCommand,
                      COMMAND_GP_UNLINK_POLICY_FROM_OU,
                      FALSE))
        {
            dwError = DirCliGPValidateOUArgs(pGPArgs);
            BAIL_ON_VMAFD_ERROR(dwError);

            dwError = DirCliGPUnlinkPolicyfromOU(
                          pLd,
                          pGPArgs->pszPolicyName,
                          pGPArgs->pszTargetDN,
                          pGPArgs->pszDomain);
            BAIL_ON_VMAFD_ERROR(dwError);

            fprintf(stdout, "Unlinked policy %s from OU: %s \n",
                                pGPArgs->pszPolicyName,
                                pGPArgs->pszTargetDN);
        }
        else if (!VmAfdStringCompareA(
                      pGPArgs->pszGPCommand,
                      COMMAND_GP_UNLINK_POLICY_FROM_DOMAIN,
                      FALSE))
        {
            //Check for policyname
            if (IsNullOrEmptyString(pGPArgs->pszPolicyName))
            {
                fprintf(stdout, "Missing arg \"%s\" \n", OPT_POLICY_NAME);
                dwError = ERROR_GP_INVALID_ARGUMENTS;
                BAIL_ON_VMAFD_ERROR(dwError);
            }

            dwError = DirCliGPUnlinkPolicyfromDomain(
                          pLd,
                          pGPArgs->pszPolicyName,
                          pGPArgs->pszDomain);
            BAIL_ON_VMAFD_ERROR(dwError);

            fprintf(stdout, "Unlinked policy \"%s\" from Domain: %s \n",
                            pGPArgs->pszPolicyName,
                            pGPArgs->pszDomain);
        }
        else if (!VmAfdStringCompareA(
                      pGPArgs->pszGPCommand,
                      COMMAND_GP_CLEAN_DEAD_LINKS,
                      FALSE))
        {
            dwError = DirCliGPCleanDeadLinks(pLd);
            BAIL_ON_VMAFD_ERROR(dwError);

            fprintf(stdout,"Cleaning deadlinks complete \n");
        }
        else if (!VmAfdStringCompareA(
                      pGPArgs->pszGPCommand,
                      COMMAND_GET_RESULTANT_POLICIES,
                      FALSE))
        {
            //Check for target DN
            if (IsNullOrEmptyString(pGPArgs->pszTargetDN))
            {
                fprintf(stdout, "Missing arg \"%s\" \n", OPT_TARGET_DN);
                dwError = ERROR_GP_INVALID_ARGUMENTS;
                BAIL_ON_VMAFD_ERROR(dwError);
            }

            dwError = DirCliGPGetResultantPolicesForDN(
                          pLd,
                          pGPArgs->pszTargetDN,
                          pGPArgs->pszDomain,
                          &pPolicyObject);
            BAIL_ON_VMAFD_ERROR(dwError);

            dwError = DirCliGPPrintPolicyObject(pPolicyObject);
            BAIL_ON_VMAFD_ERROR(dwError);
        }
        else
        {
            dwError = ERROR_GP_UNKNOWN_COMMAND;
            BAIL_ON_VMAFD_ERROR(dwError);
        }
    }
    else
    {
        fprintf(stdout,"Missing arg grouppolicy command \n");
    }

cleanup:
    if (pLd)
    {
        DirCliLdapClose(pLd);
    }
    if(pPolicyObject)
    {
        DirCliGPFreePolicyObject(pPolicyObject);
    }
    VMAFD_SAFE_FREE_MEMORY(pszPolicyJson);
    return dwError;

error:
    goto cleanup;
}

DWORD
DirCliGPValidateInitArgs(
    PGP_CLI_ARGS pGPArgs
    )
{
    DWORD dwError=0;

    if(!pGPArgs)
    {
        dwError = ERROR_INVALID_PARAMETER;
        BAIL_ON_VMAFD_ERROR(dwError);
    }

    //Check for  login, password, servername and domain
    if(IsNullOrEmptyString(pGPArgs->pszServer))
    {
        fprintf(stdout,"Missing arg \"%s\" \n",OPT_SERVERNAME);
        dwError = ERROR_GP_INVALID_ARGUMENTS;
        BAIL_ON_VMAFD_ERROR(dwError);
    }

    if(IsNullOrEmptyString(pGPArgs->pszDomain))
    {
        fprintf(stdout, "Missing arg \"%s\" \n", OPT_DOMAINNAME);
        dwError = ERROR_GP_INVALID_ARGUMENTS;
        BAIL_ON_VMAFD_ERROR(dwError);
    }

    if(IsNullOrEmptyString(pGPArgs->pszLogin))
    {
        fprintf(stdout,"Missing arg \"%s\" \n",OPT_LOGIN);
        dwError = ERROR_GP_INVALID_ARGUMENTS;
        BAIL_ON_VMAFD_ERROR(dwError);
    }

    if(IsNullOrEmptyString(pGPArgs->pszPassword))
    {
        //Free if a NULL string exists
        if(pGPArgs->pszPassword)
        {
            VMAFD_SAFE_FREE_MEMORY(pGPArgs->pszPassword);
        }

        // promt for password again if no password exists
        dwError=DirCliReadPassword(
                    pGPArgs->pszLogin,
                    pGPArgs->pszDomain,
                    NULL,
                    &pGPArgs->pszPassword);
        BAIL_ON_VMAFD_ERROR(dwError);
    }

cleanup:
    return dwError;

error:
    goto cleanup;
}

DWORD
DirCliGPValidateOUArgs(
    const GP_CLI_ARGS *pGPArgs
    )
{
    DWORD dwError=0;
    PSTR  pszAttr = NULL;

    if(!pGPArgs)
    {
        dwError = ERROR_INVALID_PARAMETER;
        BAIL_ON_VMAFD_ERROR(dwError);
    }

    //Check for pszTargetDN
    if(IsNullOrEmptyString(pGPArgs->pszTargetDN))
    {
        fprintf(stdout,"Missing arg \"%s\" \n",OPT_TARGET_DN);
        dwError = ERROR_GP_INVALID_ARGUMENTS;
        BAIL_ON_VMAFD_ERROR(dwError);
    }

    dwError = DirCliGPGetFirstAttributeofDN(pGPArgs->pszTargetDN,&pszAttr);
    BAIL_ON_VMAFD_ERROR(dwError);

    if (VmAfdStringCompareA(pszAttr, ATTR_NAME_OU, FALSE))
    {
        fprintf(stdout,"target-dn is not an OU DN ");
        dwError = ERROR_GP_INVALID_ARGUMENTS;
        BAIL_ON_VMAFD_ERROR(dwError);
    }

    //Check for policyname
    if(IsNullOrEmptyString(pGPArgs->pszPolicyName))
    {
        fprintf(stdout,"Missing arg \"%s\" \n",OPT_POLICY_NAME);
        dwError = ERROR_GP_INVALID_ARGUMENTS;
        BAIL_ON_VMAFD_ERROR(dwError);
    }

cleanup:
    VMAFD_SAFE_FREE_MEMORY(pszAttr);
    return dwError;

error:
    goto cleanup;
}

DWORD
DirCliGPGetPolicyJsonFromArgs(
    const GP_CLI_ARGS *pGPArgs,
    PSTR *ppszPolicyJson
    )
{
    DWORD dwError =0;
    DWORD dwIndex =0;
    json_t *root = NULL;
    const char * pszKey =NULL;
    json_t *jsonValue = NULL;
    const char *  pszValue = NULL;
    json_error_t error;
    PSTR pszPolicyJson = NULL;
    BOOLEAN bIsValid = FALSE;
    const char *KeyArray[NUM_KEYS_IN_POLICY_JSON];

    KeyArray[0] = POLICY_JSON_TYPE_KEY;
    KeyArray[1] = POLICY_JSON_ENABLED_KEY;
    KeyArray[2] = POLICY_JSON_START_TIME_KEY;
    KeyArray[3] = POLICY_JSON_INTERVAL_KEY;
    KeyArray[4] = POLICY_JSON_POLICY_INFO_KEY;

    if(!pGPArgs || !ppszPolicyJson)
    {
        dwError = ERROR_INVALID_PARAMETER;
        BAIL_ON_VMAFD_ERROR(dwError);
    }

    if(IsNullOrEmptyString(pGPArgs->pszJsonFile))
    {
        fprintf(stdout,"Missing arg \"%s\" \n",OPT_JSON_FILE);
        dwError = ERROR_GP_INVALID_ARGUMENTS;
        BAIL_ON_VMAFD_ERROR(dwError);
    }

    root = json_load_file(pGPArgs->pszJsonFile, 0, &error);
    if (!root)
    {
        dwError = ERROR_GP_POLICY_JSON_FORMAT_INVALID;
        fprintf(
            stderr,
            "Unable to load the policy json: %s at source: %s at line: %d \n",
            error.text,
            error.source,
            error.line);
        BAIL_ON_VMAFD_ERROR(dwError);
    }

    if (!json_is_object(root))
    {
        dwError = ERROR_GP_POLICY_JSON_FORMAT_INVALID;
        BAIL_ON_VMAFD_ERROR(dwError);
    }

    //Validate the policy json format
    //Policy json had four fileds : "type","enabled","start_time","interval","policy_info"
    if(json_object_size(root)!= NUM_KEYS_IN_POLICY_JSON)
    {
        fprintf(stdout,"Invalid key count in the policy json \n");
        dwError = ERROR_GP_POLICY_JSON_FORMAT_INVALID;
        BAIL_ON_VMAFD_ERROR(dwError);
    }

    //Check that every key is present in the json
    for(dwIndex =0;dwIndex<NUM_KEYS_IN_POLICY_JSON; dwIndex++)
    {
        jsonValue = json_object_get(root, KeyArray[dwIndex]);
        if (!jsonValue)
        {
            fprintf(stdout, "Missing \"%s\" key from the policy json \n",KeyArray[dwIndex]);
            dwError = ERROR_GP_POLICY_JSON_FORMAT_INVALID;
            BAIL_ON_VMAFD_ERROR(dwError);
        }
    }

    json_object_foreach(root,pszKey,jsonValue)
    {
        //Validate enabled key
        if (!VmAfdStringCompareA(pszKey, POLICY_JSON_ENABLED_KEY, TRUE))
        {
            if (!json_is_boolean(jsonValue))
            {
                fprintf(
                    stdout,
                    "Invalid value for  \"%s\" key in the policy json \n",
                     POLICY_JSON_ENABLED_KEY);
                dwError = ERROR_GP_POLICY_JSON_FORMAT_INVALID;
                BAIL_ON_VMAFD_ERROR(dwError);
            }
        }
        else if (!VmAfdStringCompareA(pszKey, POLICY_JSON_START_TIME_KEY, TRUE))
        {
            //validate start time
            dwError = DirCliGPValidatePolicyStartTime(jsonValue, &bIsValid);
            BAIL_ON_VMAFD_ERROR(dwError);

            if(!bIsValid)
            {
                fprintf(
                    stdout,
                    "Invalid value for  \"%s\" key in the policy json \n",
                    POLICY_JSON_START_TIME_KEY);
                dwError = ERROR_GP_POLICY_JSON_FORMAT_INVALID;
                BAIL_ON_VMAFD_ERROR(dwError);
            }
        }
        else if (!VmAfdStringCompareA(pszKey, POLICY_JSON_INTERVAL_KEY, TRUE))
        {
            //validate interval
            dwError = DirCliGPValidatePolicyInterval(jsonValue, &bIsValid);
            BAIL_ON_VMAFD_ERROR(dwError);

            if(!bIsValid)
            {
                fprintf(
                    stdout,
                    "Invalid value for  \"%s\" key in the policy json \n",
                    POLICY_JSON_INTERVAL_KEY);
                dwError = ERROR_GP_POLICY_JSON_FORMAT_INVALID;
                BAIL_ON_VMAFD_ERROR(dwError);
            }
        }
        else if(!VmAfdStringCompareA(pszKey, POLICY_JSON_POLICY_INFO_KEY, TRUE))
        {
            if (!json_is_object(jsonValue))
            {
                fprintf(
                    stdout,
                    "Invalid value for  \"%s\" key in the policy json \n",
                     POLICY_JSON_ENABLED_KEY);
                dwError = ERROR_GP_POLICY_JSON_FORMAT_INVALID;
                BAIL_ON_VMAFD_ERROR(dwError);
            }
        }
        else
        {
            //validate type key
            pszValue = json_string_value(jsonValue);
            if (IsNullOrEmptyString(pszValue))
            {
                fprintf(
                    stdout,
                    "Invalid value for \"%s\" key in the policy json \n",
                    POLICY_JSON_TYPE_KEY);
                dwError = ERROR_GP_POLICY_JSON_FORMAT_INVALID;
                BAIL_ON_VMAFD_ERROR(dwError);
            }
        }

    }

    pszPolicyJson = json_dumps(root,0);
    if(!pszPolicyJson)
    {
        dwError = ERROR_GP_JSON_CONVERSION_ERROR;
        BAIL_ON_VMAFD_ERROR(dwError);
    }

    *ppszPolicyJson = pszPolicyJson;
cleanup:
    if(root)
    {
        json_decref(root);
    }
    return dwError;

error:
    if(ppszPolicyJson)
    {
        *ppszPolicyJson = NULL;
    }
    VMAFD_SAFE_FREE_MEMORY(pszPolicyJson);
    goto cleanup;
}


DWORD
DirCliGPValidatePolicyStartTime(
    json_t *jsonPolicyTime,
    PBOOLEAN pbIsValid
    )
{
    DWORD dwError = 0;
    DWORD years = 0, month = 0, days = 0;
    DWORD hours = 0, minutes = 0, seconds = 0;
    DWORD dwScanCount =0;
    const char *pszPolicyTime = NULL;

    if (!pbIsValid || !jsonPolicyTime)
    {
        dwError = ERROR_INVALID_PARAMETER;
        BAIL_ON_VMAFD_ERROR(dwError);
    }

    pszPolicyTime = json_string_value(jsonPolicyTime);
    if (IsNullOrEmptyString(pszPolicyTime))
    {
        fprintf(
            stdout,
            "Invalid value for \"%s\" key in the policy json \n",
            POLICY_JSON_START_TIME_KEY);
        dwError = ERROR_GP_POLICY_JSON_FORMAT_INVALID;
        BAIL_ON_VMAFD_ERROR(dwError);
    }

    dwScanCount = sscanf(
                      pszPolicyTime, "%u-%u-%u %u:%u:%u",
                      &years,
                      &month,
                      &days,
                      &hours,
                      &minutes,
                      &seconds);
    if(dwScanCount!=6)
    {
        dwError = ERROR_GP_POLICY_JSON_TIME_FORMAT_INVALID;
        BAIL_ON_VMAFD_ERROR(dwError);
    }

    *pbIsValid = TRUE;

cleanup:
    return dwError;

error:
    if (pbIsValid)
    {
        *pbIsValid = FALSE;
    }
    goto cleanup;
}

/*
Interval can be
1) Time string    "6s" => taken as 6 seconds
2) Number string  "6m"  => taken as 6 minutes
3) Time string    "6h" => taken as 6 hours
4) Time string    "6d" => taken as 6 days
*/
DWORD
DirCliGPValidatePolicyInterval(
    json_t *jsonPolicyInterval,
    PBOOLEAN pbIsValid
    )
{
    DWORD dwError = 0;
    int lInterval = 0;
    PSTR pszError = NULL;
    const char *pszPolicyInterval = NULL;

    if (!pbIsValid || !jsonPolicyInterval)
    {
        dwError = ERROR_INVALID_PARAMETER;
        BAIL_ON_VMAFD_ERROR(dwError);
    }

    pszPolicyInterval = json_string_value(jsonPolicyInterval);
    if (IsNullOrEmptyString(pszPolicyInterval))
    {
        fprintf(
            stdout,
            "Invalid value for \"%s\" key in the policy json \n",
            POLICY_JSON_INTERVAL_KEY);
        dwError = ERROR_GP_POLICY_JSON_FORMAT_INVALID;
        BAIL_ON_VMAFD_ERROR(dwError);
    }

    lInterval = strtol(pszPolicyInterval, &pszError, 10);
    if (lInterval < 0)
    {
        lInterval = -1;
    }
    else if (lInterval > 0)
    {
        char chMultiplier = 's';
        int nMultiplier = 1;
        if (pszError && *pszError)
        {
            chMultiplier = *pszError;
        }
        switch (chMultiplier)
        {
        case 's':
            nMultiplier = 1;
            break;
        case 'm':
            nMultiplier = 60;
            break;
        case 'h':
            nMultiplier = 60 * 60;
            break;
        case 'd':
            nMultiplier = 60 * 60 * 24;
            break;
        default:
            dwError = ERROR_GP_POLICY_JSON_INTERVAL_FORMAT_INVALID;
            BAIL_ON_VMAFD_ERROR(dwError);
        }
        lInterval *= nMultiplier;
    }
    else if (pszError && *pszError)
    {
        dwError = ERROR_GP_POLICY_JSON_INTERVAL_FORMAT_INVALID;
        BAIL_ON_VMAFD_ERROR(dwError);
    }

    *pbIsValid = TRUE;

cleanup:
    return dwError;

error:
    if (pbIsValid)
    {
        *pbIsValid = FALSE;
    }
    goto cleanup;
}

void
DirCliGPShowHelp(
    )
{
    fprintf(
        stdout,
        "* All the policies are tracked uniquely by their names.\n"
        "* The first argument should be group policy and second argument should be the\n"
        "group policy command, the rest of the parameters can be in any order.The user\n"
        "would be prompted for a password after the command is executed.\n"
        "* Compulsory Arguments: Every command is executed with administrator privileges\n"
        "and needs the parameters login, server-name, domain-name, and password.\n"
        "\n"
        "*create: Creates a new policy, takes the policy name and JSON file with policy\n"
        "data as inputs.\n"
        "Ex:\n"
        "./dir-cli grouppolicy create  --login administrator --server-name 10.20.153.48\n"
        "--domain-name vsphere.local --policy-name updatepolicy --json-file\n"
        "updatepolicy.json\n"
        "\n"
        "*read-links: Reads all the existing links in the domain.\n"
        "Ex:\n"
        "./dir-cli grouppolicy read-links  --login administrator --server-name\n"
        "10.20.153.48 --domain-name vsphere.local\n"
        "\n"
        "*read-policies: Reads all the policies in the domain.\n"
        "Ex:\n"
        "./dir-cli grouppolicy read-policies  --login administrator --server-name\n"
        "10.20.153.48 --domain-name vsphere.local\n"
        "\n"
        "*update:\n"
        "./dir-cli grouppolicy update  --login administrator --server-name 10.20.153.48\n"
        "--domain-name vsphere.local --policy-name updatepolicy --json-file\n"
        "updatepolicy1.json\n"
        "\n"
        "*delete: Deletes a policy based by searching by its name. All the policies can\n"
        "be deleted by specifying a wildcard (\"*\") for the policy name. Deleting a policy\n"
        "also deletes all its links.\n"
        "Ex:\n"
        "./dir-cli grouppolicy delete --login administrator --server-name 10.20.153.48\n"
        "--domain-name vsphere.local --policy-name updatepolicy\n"
        "\n"
        "*link-ou: Links a policy to an OU. Takes the policy name and the DN of the OU as\n"
        "its arguments.\n"
        "Ex:\n"
        "./dir-cli grouppolicy link-ou  --login administrator --server-name 10.20.153.48\n"
        "--domain-name vsphere.local --policy-name updatepolicy --target-dn\n"
        "OU=Natrium,DC=vSphere,DC=local\n"
        "\n"
        "*unlink-ou: Unlinks a policy from an OU. Takes the policy name and the DN of the\n"
        "OU as its arguments.\n"
        "Ex:\n"
        "./dir-cli grouppolicy unlink-ou  --login administrator --server-name\n"
        "10.20.153.48 --domain-name vsphere.local --policy-name updatepolicy --target-dn\n"
        "OU=Natrium,DC=vSphere,DC=local\n"
        "\n"
        "*link-domain: Links a policy to the domain specified in \"domain-name\".\n"
        "Ex:\n"
        "./dir-cli grouppolicy link-domain  --login administrator --server-name\n"
        "10.20.153.48 --domain-name vsphere.local --policy-name updatepolicy\n"
        "\n"
        "*unlink-domain: Unlinks a policy from the domain specified in \"domain-name\".\n"
        "Ex:\n"
        "./dir-cli grouppolicy unlink-domain  --login administrator --server-name\n"
        "10.20.153.48 --domain-name vsphere.local --policy-name updatepolicy\n"
        "\n"
        "*resultant-policies: Displays the final list of applicable policies for a given\n"
        "DN. The DN is specified in the \"target-dn\" parameter. It scans all the OU and\n"
        "domain linked policies for the given DN and assigns \"order\" and \"kind\" to the\n"
        "policies.\n"
        "Ex:\n"
        "./dir-cli grouppolicy resultant-policies  --login administrator --server-name\n"
        "10.20.153.48 --domain-name vsphere.local --target-dn DC=vsphere,DC=local\n"
        "\n"
        "*clean-dead-links: Removes any policy links which have no corresponding policy\n"
        "objects. If the policy delete operation fails in-between, this can leave a few\n"
        "dead links.clean-dead-link is useful for this use case.\n"
        "Ex:\n"
        "./dir-cli grouppolicy clean-dead-links --login administrator --server-name\n"
        "10.20.153.48 --domain-name vsphere.local\n"
        "\n\n"
        "Json policy format \n"
        "\"{"
          "\"type\": \"update\", -> Should not be NULL string. \n"
          "\"enabled\": true,    -> It should be json boolean.\n"
          "\"start_time\": \"2015-05-30 18:13:04\", -> Date format.\n"
          "\"interval\": \"6h\", ->  Inteval  can be 6(6s),6s,6m,6h,6d.\n"
          "\"policy_info\": {    ->  policy_info should be a json object. \n"
            "\"type\": \"security\", \n"
           " \"altertype\": \"update\",\n"
           " \"packages\": [ \n"
           " \"diffutils\", \n"
           " \"vim\" \n"
            "] \n"
         "} \n"
        "}\" \n"
        );
    return;
}