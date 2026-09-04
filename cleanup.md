az vm delete -g ONPREMSIM-LAB-COMPUTE-RG -n onprem-jump01 --yes
az disk delete -g ONPREMSIM-LAB-COMPUTE-RG -n onprem-jump01-osdisk --yes
az network nic delete -g ONPREMSIM-LAB-COMPUTE-RG -n onprem-jump01-nic
az resource delete --resource-group ONPREMSIM-LAB-COMPUTE-RG --name shutdown-computevm-onprem-jump01 --resource-type Microsoft.DevTestLab/schedules
