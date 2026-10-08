# security-automation-realworld

Security Automation Project 2 — Automated NSG Containment with Microsoft Sentinel
Project Overview
This project demonstrates a real-world security automation and SOAR workflow using Microsoft Sentinel and Azure Logic Apps.
The scenario detects a risky Network Security Group rule that allows SSH from the Internet and automatically removes the rule.
The project combines:
- Microsoft Sentinel
- Azure Logic Apps
- Azure Activity Logs
- Log Analytics
- KQL
- Sentinel Analytics Rules
- Sentinel Automation Rules
- Managed Identity
- Azure RBAC
- Azure Resource Manager REST API
- Network Security Groups
Scenario
A potentially dangerous NSG rule is created:
Source: Internet
Protocol: TCP
Destination Port: 22
Action: Allow

The security automation workflow detects the configuration change and automatically attempts to remove it.
Risky NSG Rule Created
        ↓
Azure Activity Log
        ↓
Log Analytics
        ↓
Microsoft Sentinel
        ↓
Analytics Rule
        ↓
Security Incident
        ↓
Automation Rule
        ↓
Logic App Playbook
        ↓
Remove NSG Rule
        ↓
Add Incident Comment
        ↓
Create Investigation Tasks

Project Architecture
Azure Network Security Group
             |
             | Security Rule Created
             v
      Azure Activity Log
             |
             v
        Log Analytics
             |
             v
      Microsoft Sentinel
             |
        Analytics Rule
             |
             v
        Security Alert
             |
             v
        Sentinel Incident
             |
        Automation Rule
             |
             v
       Logic App Playbook
        /             \
       /               \
   Success             Failure
      |                   |
      v                   v
Remove NSG Rule      Failure Comment
      |                   |
      v                   v
Success Comment      Manual Task
      |
      v
Investigation Tasks

Objectives
This project demonstrates how to:
- Detect Azure network configuration changes
- Create Sentinel security alerts and incidents
- Automatically invoke security playbooks
- Use Logic Apps for security orchestration
- Authenticate with managed identities
- Apply least-privilege RBAC
- Call Azure Resource Manager APIs
- Automatically remove risky NSG rules
- Add incident comments
- Add analyst investigation tasks
- Configure success and failure branches
- Troubleshoot Sentinel and Logic Apps automation
Azure Resources
Main resource group:
rg-security-automation-realworld

Example Log Analytics workspace:
law-secauto-realworld-10655

Network Security Group:
nsg-secauto-lab

Risky test rule:
AllowSSHFromInternet

Logic App:
pb-secauto-contain-ssh

1. Configure Variables
LOCATION="canadacentral"

RG="rg-security-automation-realworld"

LAW="law-secauto-realworld-$RANDOM"

DIAG="diag-secauto-realworld"

NSG="nsg-secauto-lab"

RULE="AllowSSHFromInternet"

PLAYBOOK="pb-secauto-contain-ssh"

SUB_ID=$(az account show \
  --query id \
  --output tsv)

Verify:
echo "$RG"
echo "$LAW"
echo "$NSG"
echo "$RULE"
echo "$SUB_ID"

2. Create the Resource Group
az group create \
  --name "$RG" \
  --location "$LOCATION"

3. Create Log Analytics
az monitor log-analytics workspace create \
  --resource-group "$RG" \
  --workspace-name "$LAW" \
  --location "$LOCATION" \
  --sku PerGB2018 \
  --retention-time 30

Get the resource ID:
LAW_ID=$(az monitor log-analytics workspace show \
  --resource-group "$RG" \
  --workspace-name "$LAW" \
  --query id \
  --output tsv)

Get the query/customer ID:
WORKSPACE_ID=$(az monitor log-analytics workspace show \
  --resource-group "$RG" \
  --workspace-name "$LAW" \
  --query customerId \
  --output tsv)

4. Enable Microsoft Sentinel
az extension add \
  --name log-analytics-solution \
  --upgrade

az monitor log-analytics solution create \
  --resource-group "$RG" \
  --solution-type SecurityInsights \
  --workspace "$LAW"

5. Send Azure Activity Logs to Log Analytics
MSYS_NO_PATHCONV=1 az monitor diagnostic-settings subscription create \
  --name "$DIAG" \
  --workspace "$LAW_ID" \
  --location "$LOCATION" \
  --logs '[{"category":"Administrative","enabled":true}]'

MSYS_NO_PATHCONV=1 is used because Git Bash can incorrectly convert Azure ARM resource IDs such as:
/subscriptions/...

into Windows paths.
6. Create the Test NSG
az network nsg create \
  --resource-group "$RG" \
  --name "$NSG" \
  --location "$LOCATION"

The NSG is not attached to a VM or subnet, making it suitable for this security lab.
Get its resource ID:
NSG_ID=$(az network nsg show \
  --resource-group "$RG" \
  --name "$NSG" \
  --query id \
  --output tsv)

7. Create the Sentinel Detection Rule
Create a scheduled analytics rule named:
Risky SSH NSG Rule Created

Example KQL:
AzureActivity
| where TimeGenerated > ago(1h)
| where ResourceGroup =~ "rg-security-automation-realworld"
| where OperationNameValue contains "Microsoft.Network/networkSecurityGroups"
| where ActivityStatusValue =~ "Success"
| project
    TimeGenerated,
    Caller,
    ResourceGroup,
    ResourceId,
    OperationNameValue,
    ActivityStatusValue,
    CorrelationId,
    Properties_d

Recommended configuration:
Run every:
5 minutes

Lookup:
1 hour

Threshold:
Greater than 0

Enable:
Create incidents from alerts triggered by this analytics rule

8. Create the Logic App Playbook
Create:
pb-secauto-contain-ssh

Use the trigger:
Microsoft Sentinel incident

The basic workflow is:
Microsoft Sentinel incident
        ↓
Add initial comment
        ↓
HTTP DELETE
       / \
      /   \
Success  Failure
   |        |
   v        v
Comment   Failure Comment
   |        |
   v        v
Tasks    Manual Task

9. Enable Managed Identity
Enable a system-assigned managed identity for:
pb-secauto-contain-ssh

Retrieve its principal ID:
PB_PRINCIPAL_ID=$(az resource show \
  --resource-group "$RG" \
  --name "$PLAYBOOK" \
  --resource-type "Microsoft.Logic/workflows" \
  --query identity.principalId \
  --output tsv)

10. Give the Playbook Sentinel Permissions
Get the resource group ID:
RG_ID=$(az group show \
  --name "$RG" \
  --query id \
  --output tsv)

Assign:
MSYS_NO_PATHCONV=1 az role assignment create \
  --assignee-object-id "$PB_PRINCIPAL_ID" \
  --assignee-principal-type ServicePrincipal \
  --role "Microsoft Sentinel Responder" \
  --scope "$RG_ID"

This allows the playbook to modify Sentinel incidents.
11. Give the Playbook Network Permissions
Assign least-privilege access to the test NSG:
MSYS_NO_PATHCONV=1 az role assignment create \
  --assignee-object-id "$PB_PRINCIPAL_ID" \
  --assignee-principal-type ServicePrincipal \
  --role "Network Contributor" \
  --scope "$NSG_ID"

This allows the Logic App to modify the lab NSG without granting subscription-wide permissions.
12. Add Initial Incident Comment
Use:
Microsoft Sentinel
→ Add comment to incident (V3)

Example message:
SECURITY AUTOMATION STARTED

A network security rule allowing inbound SSH from the Internet
was detected.

Automated containment has started.

For:
Incident ARM id

always use:
Microsoft Sentinel incident
→ Incident ARM ID

or:
triggerBody()?['object']?['id']

13. Automatically Remove the Risky NSG Rule
Add an HTTP action.
Method:
DELETE

URI:
https://management.azure.com/subscriptions/<SUBSCRIPTION-ID>/resourceGroups/rg-security-automation-realworld/providers/Microsoft.Network/networkSecurityGroups/nsg-secauto-lab/securityRules/AllowSSHFromInternet?api-version=2025-07-01

Replace:
<SUBSCRIPTION-ID>

with the actual subscription ID.
Do not leave angle brackets around it.
Correct:
/subscriptions/12345678-1234-1234-1234-123456789abc/

Incorrect:
/subscriptions/<12345678-1234-1234-1234-123456789abc>/

Authentication:
Managed Identity

Managed identity:
System-assigned managed identity

Audience:
https://management.azure.com/

or leave it at the Azure Resource Manager default where supported.
14. Add Success Handling
After a successful HTTP request, add:
Add comment to incident (V3)

Message:
AUTOMATED CONTAINMENT COMPLETED

The risky SSH rule was automatically removed from
nsg-secauto-lab.

The incident remains open for analyst verification.

Configure its Run After setting:
HTTP
→ Is successful

15. Add Investigation Tasks
Example task:
Verify automatic containment

Description:
Confirm that AllowSSHFromInternet no longer exists
on nsg-secauto-lab.

Second task:
Investigate initiating identity

Description:
Review the Azure Activity event.

Determine:
- who created the rule;
- whether the change was authorized;
- whether similar changes occurred elsewhere.

Important:
Every task must use the original Incident ARM ID from:
Microsoft Sentinel incident

Do not use the output from a previous comment or task.
Correct:
.../Microsoft.SecurityInsights/incidents/<incident-guid>

Incorrect:
.../incidents/<incident-guid>/Comments/<guid>

Incorrect:
.../incidents/<incident-guid>/Tasks/<guid>

16. Configure Failure Handling
Create another incident comment.
Message:
AUTOMATED CONTAINMENT FAILED

The playbook could not remove the risky NSG rule.

Manual analyst action is required immediately.

Configure:
Run after:
☑ Has failed
☑ Has timed out
☐ Is successful

Then add a task:
Manually remove risky NSG rule

This provides a fallback if automated containment fails.
17. Give Sentinel Permission to Run the Playbook
Find the Sentinel service principal:
SENTINEL_SP_ID=$(az ad sp list \
  --display-name "Azure Security Insights" \
  --query "[0].id" \
  --output tsv)

Assign:
MSYS_NO_PATHCONV=1 az role assignment create \
  --assignee-object-id "$SENTINEL_SP_ID" \
  --assignee-principal-type ServicePrincipal \
  --role "Microsoft Sentinel Automation Contributor" \
  --scope "$RG_ID"

18. Create the Sentinel Automation Rule
Create:
Automatically contain dangerous SSH NSG rule

Trigger:
When incident is created

Condition:
Analytics rule name
contains
Risky SSH NSG Rule Created

Action:
Run playbook

Playbook:
pb-secauto-contain-ssh

19. Simulate the Security Event
Create the risky rule:
az network nsg rule create \
  --resource-group "$RG" \
  --nsg-name "$NSG" \
  --name "$RULE" \
  --priority 100 \
  --direction Inbound \
  --access Allow \
  --protocol Tcp \
  --source-address-prefixes Internet \
  --source-port-ranges "*" \
  --destination-address-prefixes "*" \
  --destination-port-ranges 22

20. Verify the Detection Pipeline
Check Azure Activity:
az monitor activity-log list \
  --offset 2h \
  --query "[?contains(resourceId, 'nsg-secauto-lab')].{Time:eventTimestamp,Operation:operationName.value,Status:status.value,ResourceId:resourceId}" \
  --output table

Then check Log Analytics:
AzureActivity
| where TimeGenerated > ago(4h)
| where ResourceGroup =~ "rg-security-automation-realworld"
| where OperationNameValue contains "networkSecurityGroups"
| order by TimeGenerated desc

21. Verify Automatic Containment
Check whether the rule still exists:
az network nsg rule show \
  --resource-group "$RG" \
  --nsg-name "$NSG" \
  --name "$RULE"

After successful remediation, Azure should report that the rule cannot be found.
22. Review the Logic App Run
Navigate to:
Azure Portal
→ Logic Apps
→ pb-secauto-contain-ssh
→ Run history

A successful execution should resemble:
Microsoft Sentinel incident        ✅
        ↓
Initial incident comment           ✅
        ↓
HTTP DELETE                        ✅
        ↓
Containment success comment        ✅
        ↓
Verify containment task            ✅
        ↓
Investigate identity task          ✅

The failure branch should normally show:
Failure comment                    Skipped
Manual remediation task            Skipped

Troubleshooting
HTTP Action Returns BadRequest
Check the URI.
Wrong:
/subscriptions/<subscription-id>/

Correct:
/subscriptions/subscription-id/

Remove the < > characters.
HTTP Action Returns 403
Verify that the Logic App managed identity has:
Network Contributor

on the NSG.
az role assignment list \
  --assignee "$PB_PRINCIPAL_ID" \
  --all \
  --output table

Task Action Returns BadRequest
Check the Incident ARM ID.
If it ends with:
/Tasks/<guid>

or:
/Comments/<guid>

the wrong dynamic field was selected.
Use:
Microsoft Sentinel incident
→ Incident ARM ID

or:
triggerBody()?['object']?['id']

Logic App Shows No Runs
Check the pipeline in this order:
AzureActivity
      ↓
SecurityAlert
      ↓
Sentinel Incident
      ↓
Automation Rule
      ↓
Logic App

If there is no Sentinel incident, the Logic App cannot run automatically.
AzureActivity Doesn't Match the Exact Security Rule Operation
Use a broader query:
AzureActivity
| where TimeGenerated > ago(4h)
| where ResourceGroup =~ "rg-security-automation-realworld"
| where OperationNameValue contains "networkSecurityGroups"
| project
    TimeGenerated,
    OperationNameValue,
    ActivityStatusValue,
    ResourceId,
    Properties_d

Then inspect how Azure recorded the operation.
Cleanup
Delete the subscription diagnostic setting:
az monitor diagnostic-settings subscription delete \
  --name "$DIAG"

Delete the project resource group:
az group delete \
  --name "$RG" \
  --yes \
  --no-wait

This removes the:
NSG
Logic App
Log Analytics workspace
Sentinel resources
API connections
Project RBAC scope

Skills Demonstrated
This project demonstrates experience with:
Microsoft Sentinel
Security Automation
SOAR
Azure Logic Apps
KQL
Azure Activity Logs
Log Analytics
Analytics Rules
Automation Rules
Managed Identity
Azure RBAC
Network Security Groups
Azure Resource Manager REST API
Incident Response
Automated Remediation
Failure Handling
Least Privilege
Azure CLI

Project Summary
This project implements an end-to-end Azure security automation workflow that detects network security configuration changes and automatically responds to risky NSG rules.
The complete workflow follows the security operations model:
Detect
   ↓
Alert
   ↓
Create Incident
   ↓
Automate Response
   ↓
Contain Threat
   ↓
Document Action
   ↓
Assign Investigation Tasks

The project demonstrates how Microsoft Sentinel and Azure Logic Apps can be combined to create practical SOAR workflows that reduce manual incident-response effort while maintaining analyst visibility and fallback procedures.