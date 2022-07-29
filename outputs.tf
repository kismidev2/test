

output "security_center_workspace__lzensub1" {
  value = {
    for k, v in azurerm_security_center_workspace.lzensub1: k => v.id
  }
}

output "virtual_network__lzenrg1" {
  value = {
    for k, v in azurerm_virtual_network.lzenrg1: k => v.id
  }
}


output "firewall__lzenrg1" {
  value = {
    for k, v in azurerm_firewall.lzenrg1 : k => v.id
  }
}

output "public_ip_address__lzenrg1_1" {
  value = {
    for pip in azurerm_public_ip.lzenrg11 : pip.id => pip.ip_address
  }
}

output "ddos_protection_plan_name__lzenrg1" {
  value = azurerm_network_ddos_protection_plan.lzenrg1.name
}

output "dns_zone__lzenrg1" {
  value = {
    for k, v in azurerm_dns_zone.lzenrg1 : k => v.id
  }
}


# output "cost_management_export__lzenrg1" {
#   value = {
#     for k, v in azurerm_resource_group_cost_management_export.lzenrg1 : k => v.id
#   }
# }

output "virtual_network_peering_lzenvn1" {
  value = {
    for k, v in azurerm_virtual_network_peering.lzenvn1 : k => v.id
  }
}

output "virtual_network_peering_lzenvn2" {
  value = {
    for k, v in azurerm_virtual_network_peering.lzenvn2 : k => v.id
  }
}
output "azurerm_log_analytics_workspace__lzenrg1" {
  value = {
    for k, v in azurerm_log_analytics_workspace.lzenrg1 : k => v.id
  }
}



output "storage_account__lzenrg1" {
  value = {
    for k, v in azurerm_storage_account.lzenrg1 : k => v.id
  }
}

output "storage_access_key__lzenrg1" {
  value = {
    for k, v in azurerm_storage_account.lzenrg1 : k => v.primary_access_key
  }
  sensitive = true
}

output "storage_connection_string__lzenrg1" {
  value = {
    for k, v in azurerm_storage_account.lzenrg1 : k => v.primary_connection_string
  }
  sensitive = true
}

output "containerId__lzenrg1" {
  value = {
    for k in azurerm_resource_group_template_deployment.container1__lzenrg1 : k.name => jsondecode(k.output_content).containerId.value
  }
}

output "queueId__lzenrg1" {
  value = {
    for k in azurerm_resource_group_template_deployment.queue1__lzenrg1 : k.name => jsondecode(k.output_content).queueId.value
  }
}

output "shareId__lzenrg1" {
  value = {
    for k in azurerm_resource_group_template_deployment.share1__lzenrg1 : k.name => jsondecode(k.output_content).shareId.value
  }
}

output "tableId__lzenrg1" {
  value = {
    for k in azurerm_resource_group_template_deployment.table1__lzenrg1 : k.name => jsondecode(k.output_content).tableId.value
  }
}

output "resource_group_name__lzenrg1" {
  value = azurerm_resource_group.lzenrg1.name
}


output "network_security_group__lzenrg2" {
  value = {
    for k, v in azurerm_network_security_group.lzenrg21 : k => v.id
  }
}

output "virtual_network__lzenrg2" {
  value = {
    for k, v in azurerm_virtual_network.lzenrg2: k => v.id
  }
}


output "ddos_protection_plan_name__lzenrg2" {
  value = azurerm_network_ddos_protection_plan.lzenrg2.name
}

output "dns_zone__lzenrg2" {
  value = {
    for k, v in azurerm_dns_zone.lzenrg2 : k => v.id
  }
}


output "subnet__lzenrg2" {
  value = {
    for subnet in azurerm_subnet.lzenrg2: subnet.name => subnet.address_prefixes
  }
}

output "public_load_balancer__lzenrg2" {
  value = {
    for lb in azurerm_lb.lzenrg2 : lb.name => lb.id
  }
}

output "public_ip_address__lzenrg2" {
  value = {
    for pip in azurerm_public_ip.lzenrg2 : pip.id => pip.ip_address
  }
}

output "key_vault__lzenrg2" {
  value = {
    for k, v in azurerm_key_vault.lzenrg2 : k => v.id
  }
}

output "azurerm_log_analytics_workspace__lzenrg2" {
  value = {
    for k, v in azurerm_log_analytics_workspace.lzenrg2 : k => v.id
  }
}



output "recovery_services_vault__lzenrg2" {
  value = {
    for k, v in azurerm_recovery_services_vault.lzenrg2 : k => v.id
  }
}

output "protected_vm__lzenrg2" {
  value = {
    for k, v in azurerm_backup_protected_vm.lzenrg2 : k => v.id
  }
}

output "protected_file_share__lzenrg2" {
  value = {
    for k, v in azurerm_backup_protected_file_share.lzenrg2 : k => v.id
  }
}

output "storage_account__lzenrg2" {
  value = {
    for k, v in azurerm_storage_account.lzenrg2 : k => v.id
  }
}

output "storage_access_key__lzenrg2" {
  value = {
    for k, v in azurerm_storage_account.lzenrg2 : k => v.primary_access_key
  }
  sensitive = true
}

output "storage_connection_string__lzenrg2" {
  value = {
    for k, v in azurerm_storage_account.lzenrg2 : k => v.primary_connection_string
  }
  sensitive = true
}

output "containerId__lzenrg2" {
  value = {
    for k in azurerm_resource_group_template_deployment.container1__lzenrg2 : k.name => jsondecode(k.output_content).containerId.value
  }
}

output "queueId__lzenrg2" {
  value = {
    for k in azurerm_resource_group_template_deployment.queue1__lzenrg2 : k.name => jsondecode(k.output_content).queueId.value
  }
}

output "shareId__lzenrg2" {
  value = {
    for k in azurerm_resource_group_template_deployment.share1__lzenrg2 : k.name => jsondecode(k.output_content).shareId.value
  }
}

output "tableId__lzenrg2" {
  value = {
    for k in azurerm_resource_group_template_deployment.table1__lzenrg2 : k.name => jsondecode(k.output_content).tableId.value
  }
}

output "automation_account__lzenrg2" {
  value = {
    for k, v in azurerm_automation_account.lzenrg2 : k => v.id
  }
}

output "automation_runbook__lzenrg2" {
  value = {
    for k, v in azurerm_automation_runbook.lzenrg2 : k => v.id
  }
}

output "automation_dsc_configuration__lzenrg2" {
  value = {
    for k, v in azurerm_automation_dsc_configuration.lzenrg2 : k => v.id
  }
}

output "automation_dsc_nodeconfiguration__lzenrg2" {
  value = {
    for k, v in azurerm_automation_dsc_nodeconfiguration.lzenrg2 : k => v.id
  }
}

output "virtual_machine__lzenrg2" {
  value = {
    for k, v in azurerm_linux_virtual_machine.lzenrg2 : k => v.id
  }
}

output "public_ip_address__lzenrg2_1" {
  value = {
    for pip in azurerm_public_ip.lzenrg21 : pip.id => pip.ip_address
  }
}

output "resource_group_name__lzenrg2" {
  value = azurerm_resource_group.lzenrg2.name
}


