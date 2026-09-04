Assign permissions to RG for app - sim lab.

az account set --subscription "Visual Studio Professional Subscription"
appId=$(az ad app list --display-name secops-lab-deployer --query [0].appId -o tsv)
subId=$(az account show --query id -o tsv)
az group create --name ONPREMSIM-LAB-COMPUTE-RG --location westeurope
az role assignment create --assignee $appId --role Contributor --scope /subscriptions/$subId/resourceGroups/ONPREMSIM-LAB-COMPUTE-RG
