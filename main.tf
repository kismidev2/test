terraform {
  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = ">=2.70.0"
    }
  }
}

provider "azurerm" {
  alias = "lzensub1"
  tenant_id       = var.tenant_id__lzensub1
  subscription_id = var.subscription_id__lzensub1
  client_id       = var.serviceprincipal_id__lzensub1
  client_secret   = var.serviceprincipal_key__lzensub1
  features {}
}


resource "azurerm_security_center_workspace" "lzensub1" {
  provider = azurerm.lzensub1
  for_each     = var.security_center__lzensub1
  scope        = format("/%s/%s", "subscriptions", var.subscription_id__lzensub1)
  workspace_id = azurerm_log_analytics_workspace.lzenrg1[split(":", each.value.linked_log_analytics_workspace)[1]].id
}

resource "azurerm_security_center_assessment_policy" "lzensub1" {
  provider = azurerm.lzensub1
  for_each = {
    for policy in flatten([
      for workspace_key, workspace_value in var.security_center__lzensub1 : [
        for policy_key, policy_value in workspace_value.assessment_policy : {
          name         = policy_key
          display_name = policy_value.display_name
          severity     = policy_value.severity
          description  = policy_value.description
        }
      ]
    ]) : "${policy.name}" => policy
  }

  display_name = each.value.display_name
  severity     = each.value.severity
  description  = each.value.description
}

resource "azurerm_security_center_assessment" "lzensub1" {
  provider = azurerm.lzensub1
  for_each = {
    for assessment in flatten([
      for workspace_key, workspace_value in var.security_center__lzensub1 : [
        for assessment_key, assessment_value in workspace_value.assessment : {
          name = assessment_key
          assessment_policy_name = assessment_value.policy_name
          target_resource_name = assessment_value.target_resource_name
          status_code = assessment_value.status_code
        }
      ]
    ]) : "${assessment.name}" => assessment
  }

  assessment_policy_id = azurerm_security_center_assessment_policy.lzensub1[each.value.assessment_policy_name].id
  target_resource_id   = azurerm_log_analytics_workspace.lzenrg1[split(":", each.value.target_resource_name)[1]].id

  status {
    code = each.value.status_code
  }
}

resource "azurerm_advanced_threat_protection" "lzensub1" {
  provider = azurerm.lzensub1
  for_each = {
    for atp in flatten([
      for workspace_key, workspace_value in var.security_center__lzensub1 : [
        for atp_key, atp_value in workspace_value.linked_advanced_threat_protection : {
          name = atp_key
          target_resource_name = atp_value.target_resource_name
          enabled = atp_value.enabled
        }
      ]
    ]) : "${atp.name}" => atp
  }

  target_resource_id = azurerm_storage_account.lzenrg1[split(":", each.value.target_resource_name)[1]].id
  enabled = each.value.enabled
}

resource "azurerm_virtual_network" "lzenrg1" {
  provider = azurerm.lzensub1
  for_each            = var.virtual_network__lzenrg1
  name                = each.key
  location            = azurerm_resource_group.lzenrg1.location
  resource_group_name = azurerm_resource_group.lzenrg1.name
  address_space       = each.value.vnet_address_space

  dynamic "ddos_protection_plan" {
    for_each = "${each.value.enable_ddos_protection}" == true ? [1] : []
    content {
      id     = azurerm_network_ddos_protection_plan.lzenrg1.id
      enable = true
    }
  }
}


resource "azurerm_subnet" "lzenrg11" {
  provider = azurerm.lzensub1
  for_each             = var.firewall__lzenrg1 
  name                 = "AzureFirewallSubnet"
  resource_group_name  = azurerm_resource_group.lzenrg1.name
  virtual_network_name = azurerm_virtual_network.lzenrg1[each.value.included_vnet_name].name
  address_prefixes     = [ each.value.address_prefixes ]
}

resource "azurerm_public_ip" "lzenrg11" {
  provider = azurerm.lzensub1
  for_each            = var.firewall__lzenrg1 
  name                = "${each.key}-pip"
  resource_group_name = azurerm_resource_group.lzenrg1.name
  location            = azurerm_resource_group.lzenrg1.location
  allocation_method   = "Static"
  sku                 = "Standard"
}

resource "azurerm_firewall" "lzenrg1" {
  provider = azurerm.lzensub1
  for_each            = var.firewall__lzenrg1
  name                = each.key
  location            = azurerm_resource_group.lzenrg1.location
  resource_group_name = azurerm_resource_group.lzenrg1.name
  sku_tier            = each.value.sku_tier
  sku_name            = each.value.sku_name

  ip_configuration {
    name                 = each.value.ip_config_name  
    subnet_id            = azurerm_subnet.lzenrg11[each.key].id
    public_ip_address_id = azurerm_public_ip.lzenrg11[each.key].id
  }
}

resource "azurerm_firewall_network_rule_collection" "lzenrg1" {
  provider = azurerm.lzensub1
  for_each = {
    for collection in flatten([
      for fw_key, fw_value in var.firewall__lzenrg1 : [
        for collection_key, collection_value in fw_value.network_rule_collection : {
          name          = collection_key
          firewall_name = fw_key
          priority      = collection_value.priority
          action        = collection_value.action
        }
      ]
    ]) : "${collection.name}" => collection
  }

  name                = each.value.name
  azure_firewall_name = azurerm_firewall.lzenrg1[each.value.firewall_name].name
  resource_group_name = azurerm_resource_group.lzenrg1.name
  priority            = each.value.priority
  action              = each.value.action 

  dynamic "rule" {
    for_each = {
      for rule in flatten([
        for fw_key, fw_value in var.firewall__lzenrg1: [
          for rule_key, rule_value in fw_value.network_rules : {
            name                  = rule_key
            source_addresses      = rule_value.source_addresses
            destination_ports     = rule_value.destination_ports
            destination_addresses = rule_value.destination_addresses
            protocols             = rule_value.protocols
          }
        ]
      ]) : "${rule.name}" => rule
    }
    iterator = rule

    content {
      name                  = rule.key
      source_addresses      = rule.value.source_addresses 
      destination_ports     = rule.value.destination_ports 
      destination_addresses = rule.value.destination_addresses 
      protocols             = rule.value.protocols
    }
  }
}

resource "azurerm_firewall_application_rule_collection" "lzenrg1" {
  provider = azurerm.lzensub1
  for_each = {
    for collection in flatten([
      for fw_key, fw_value in var.firewall__lzenrg1 : [
        for collection_key, collection_value in fw_value.application_rule_collection : {
          name          = collection_key
          firewall_name = fw_key
          priority      = collection_value.priority
          action        = collection_value.action
        }
      ]
    ]) : "${collection.name}" => collection
  }

  name                = each.value.name
  azure_firewall_name = azurerm_firewall.lzenrg1[each.value.firewall_name].name
  resource_group_name = azurerm_resource_group.lzenrg1.name
  priority            = each.value.priority
  action              = each.value.action

  dynamic "rule" {
    for_each = {
      for rule in flatten([
        for fw_key, fw_value in var.firewall__lzenrg1: [
          for rule_key, rule_value in fw_value.application_rules : {
            name             = rule_key
            source_addresses = rule_value.source_addresses
            target_fqdns     = rule_value.target_fqdns
            port             = rule_value.protocol_port
            type             = rule_value.protocol_type 
          }
        ]
      ]) : "${rule.name}" => rule
    }
    iterator = rule

    content {
      name             = rule.key
      source_addresses = rule.value.source_addresses 
      target_fqdns     = rule.value.target_fqdns

      protocol {
        port = rule.value.port   
        type = rule.value.type    
      }
    }
  }
}

resource "azurerm_firewall_nat_rule_collection" "lzenrg1" {
  provider = azurerm.lzensub1
  for_each = {
    for collection in flatten([
      for fw_key, fw_value in var.firewall__lzenrg1 : [
        for collection_key, collection_value in fw_value.nat_rule_collection : {
          name          = collection_key
          firewall_name = fw_key
          priority      = collection_value.priority
          action        = collection_value.action
        }
      ]
    ]) : "${collection.name}" => collection
  }

  name                = each.value.name
  azure_firewall_name = azurerm_firewall.lzenrg1[each.value.firewall_name].name
  resource_group_name = azurerm_resource_group.lzenrg1.name
  priority            = each.value.priority
  action              = each.value.action  

  dynamic "rule" {
    for_each = {
      for rule in flatten([
        for fw_key, fw_value in var.firewall__lzenrg1: [
          for rule_key, rule_value in fw_value.nat_rules : {
            name               = rule_key
            source_addresses   = rule_value.source_addresses
            destination_ports  = rule_value.destination_ports
            translated_port    = rule_value.translated_port       
            translated_address = rule_value.translated_address   
            protocols          = rule_value.protocols
            firewall_name      = fw_key
          }
        ]
      ]) : "${rule.name}" => rule
    }
    iterator = rule

    content {
      name                  = rule.key
      source_addresses      = rule.value.source_addresses 
      destination_ports     = rule.value.destination_ports 
      destination_addresses = [azurerm_public_ip.lzenrg11[each.value.firewall_name].ip_address]
      translated_port       = rule.value.translated_port       
      translated_address    = rule.value.translated_address
      protocols             = rule.value.protocols
    }
  }
}


resource "azurerm_network_ddos_protection_plan" "lzenrg1" {
  provider = azurerm.lzensub1
  name                = var.ddos_protection_plan_name__lzenrg1
  location            = azurerm_resource_group.lzenrg1.location
  resource_group_name = azurerm_resource_group.lzenrg1.name
}

resource "azurerm_dns_zone" "lzenrg1" {
  provider = azurerm.lzensub1
  for_each = var.dns_zone__lzenrg1
  name = each.key
  resource_group_name = azurerm_resource_group.lzenrg1.name
}

resource "azurerm_dns_a_record" "lzenrg1" {
  provider = azurerm.lzensub1
  for_each = {
    for record in flatten([
      for zone_key, zone_value in var.dns_zone__lzenrg1 : [
          for record_key, record_value in zone_value.dns_a_record : {
            included_zone_name = zone_key
            name    = record_key
            ttl     = record_value.ttl
            records = record_value.records
          }
        ]
    ]) : "${record.name}" => record
  }

  name      = each.value.name
  zone_name = each.value.included_zone_name
  resource_group_name = azurerm_resource_group.lzenrg1.name
  ttl       = each.value.ttl
  records   = each.value.records
}

resource "azurerm_dns_ns_record" "lzenrg1" {
  provider = azurerm.lzensub1
  for_each = {
    for record in flatten([
      for zone_key, zone_value in var.dns_zone__lzenrg1 : [
          for record_key, record_value in zone_value.dns_ns_record : {
            included_zone_name = zone_key
            name    = record_key
            ttl     = record_value.ttl
            records = record_value.records
          }
        ]
    ]) : "${record.name}" => record
  }

  name      = each.value.name
  zone_name = each.value.included_zone_name
  resource_group_name = azurerm_resource_group.lzenrg1.name
  ttl       = each.value.ttl
  records   = each.value.records
}

resource "azurerm_dns_cname_record" "lzenrg1" {
  provider = azurerm.lzensub1
  for_each = {
    for record in flatten([
      for zone_key, zone_value in var.dns_zone__lzenrg1 : [
          for record_key, record_value in zone_value.dns_cname_record : {
            included_zone_name = zone_key
            name    = record_key
            ttl     = record_value.ttl
            record = record_value.record
          }
        ]
    ]) : "${record.name}" => record
  }

  name      = each.value.name
  zone_name = each.value.included_zone_name
  resource_group_name = azurerm_resource_group.lzenrg1.name
  ttl       = each.value.ttl
  record   = each.value.record
}

resource "azurerm_dns_ptr_record" "lzenrg1" {
  provider = azurerm.lzensub1
  for_each = {
    for record in flatten([
      for zone_key, zone_value in var.dns_zone__lzenrg1 : [
          for record_key, record_value in zone_value.dns_ptr_record : {
            included_zone_name = zone_key
            name    = record_key
            ttl     = record_value.ttl
            records = record_value.records
          }
        ]
    ]) : "${record.name}" => record
  }

  name      = each.value.name
  zone_name = each.value.included_zone_name
  resource_group_name = azurerm_resource_group.lzenrg1.name
  ttl       = each.value.ttl
  records   = each.value.records
}

resource "azurerm_resource_provider_registration" "lzenrg1" {
  provider = azurerm.lzensub1
  name = "Microsoft.CostManagementExports"
}

# network_rules을 사용하지 않으면 정상적으로 만들어짐 -> network_rules을 설정하면 권한 문제 발생
# error msg: The exports service is not authorized to access the specified storage account
# https://github.com/MicrosoftDocs/azure-docs/issues/40519
resource "azurerm_resource_group_cost_management_export" "lzenrg1" {
  provider = azurerm.lzensub1
  for_each                     = var.cost_management_export__lzenrg1
  name                         = each.key
  resource_group_id            = azurerm_resource_group.lzenrg1.id
  recurrence_type              = each.value.recurrence_type
  recurrence_period_start_date = each.value.recurrence_period_start_date
  recurrence_period_end_date   = each.value.recurrence_period_end_date

  export_data_storage_location {
    container_id     = {for k in azurerm_resource_group_template_deployment.container1__lzenrg1 : k.name => jsondecode(k.output_content).containerId.value}[each.value.storage_container_name]
    root_folder_path = each.value.root_folder_path
  }
 
  export_data_options {
    type       = each.value.export_type
    time_frame = each.value.export_time_frame
  }
}

resource "azurerm_virtual_network_peering" "lzenvn1" {
  provider = azurerm.lzensub1
  for_each                  = var.virtual_network_peering
  name                      = each.key
  resource_group_name       = azurerm_resource_group.lzenrg1.name
  virtual_network_name      = azurerm_virtual_network.lzenrg1[each.value.linked_vnet_name_01].name
  remote_virtual_network_id = azurerm_virtual_network.lzenrg2[each.value.linked_vnet_name_02].id
}

resource "azurerm_virtual_network_peering" "lzenvn2" {
  provider = azurerm.lzensub1
  for_each                  = var.virtual_network_peering
  name                      = each.key
  resource_group_name       = azurerm_resource_group.lzenrg2.name
  virtual_network_name      = azurerm_virtual_network.lzenrg2[each.value.linked_vnet_name_02].name
  remote_virtual_network_id = azurerm_virtual_network.lzenrg1[each.value.linked_vnet_name_01].id
}

resource "azurerm_log_analytics_workspace" "lzenrg1" {
  provider = azurerm.lzensub1
  for_each                   = var.log_analytics_workspace__lzenrg1
  name                       = each.key
  location                   = azurerm_resource_group.lzenrg1.location
  resource_group_name        = azurerm_resource_group.lzenrg1.name
  sku                        = "PerGB2018"  
  retention_in_days          = each.value.retention_in_days          
  internet_query_enabled     = each.value.internet_query_enabled     
  internet_ingestion_enabled = each.value.internet_ingestion_enabled 
}


resource "azurerm_storage_account" "lzenrg1" {
  provider = azurerm.lzensub1
  for_each                  = var.storage_account__lzenrg1
  name                      = each.key
  resource_group_name       = azurerm_resource_group.lzenrg1.name
  location                  = azurerm_resource_group.lzenrg1.location
  account_kind              = each.value.account_kind
  account_tier              = each.value.account_tier
  account_replication_type  = each.value.account_replication_type
  access_tier               = each.value.access_tier
  min_tls_version           = each.value.min_tls_version
  enable_https_traffic_only = each.value.enable_https_traffic_only

  # tfsec:ignore:azure-storage-default-action-deny
  dynamic "network_rules" {
    for_each = each.value.network_rules
    iterator = rule
    content {
      default_action = rule.value.default_action
      bypass = rule.value.bypass
      ip_rules = rule.value.ip_rules
    }
  }
}

resource "azurerm_resource_group_template_deployment" "container1__lzenrg1" {
  provider = azurerm.lzensub1
  for_each = {
    for container in flatten([
      for sa_key, sa_value in var.storage_account__lzenrg1 : [
        for container_key, container_value in sa_value.storage_container : {
          name = container_key
          storage_account_name = sa_key
          container_access_type = container_value.container_access_type
        }
      ]
    ]) : "${container.name}" => container
  }

  name                = each.value.name
  resource_group_name = azurerm_resource_group.lzenrg1.name
  deployment_mode     = "Incremental"
  template_content = <<TEMPLATE
{
    "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
    "contentVersion": "1.0.0.0",
    "parameters": {},
    "variables": {
      "storageAccounts_name": "${each.value.storage_account_name}",
      "container_name": "${each.value.name}",
      "container_type": "${each.value.container_access_type}"
    },
    "resources": [
        {
            "type": "Microsoft.Storage/storageAccounts/blobServices/containers",
            "apiVersion": "2021-09-01",
            "name": "[concat(variables('storageAccounts_name'), '/default/', concat(variables('container_name')))]",
            "properties": {
                "immutableStorageWithVersioning": {
                    "enabled": false
                },
                "defaultEncryptionScope": "$account-encryption-key",
                "denyEncryptionScopeOverride": false,
                "publicAccess": "[variables('container_type')]"
            }
        }
    ],
    "outputs": {
        "containerId": {
            "type": "string",
            "value": "[resourceId('Microsoft.Storage/storageAccounts/blobServices/containers', variables('storageAccounts_name'), 'default', variables('container_name'))]"
        }
    }
}
TEMPLATE
  depends_on = [azurerm_storage_account.lzenrg1]
}

resource "azurerm_resource_group_template_deployment" "queue1__lzenrg1" {
  provider = azurerm.lzensub1
  for_each = {
    for queue in flatten([
      for sa_key, sa_value in var.storage_account__lzenrg1 : [
        for queue_key, queue_value in sa_value.storage_queue : {
          name = queue_key
          storage_account_name = sa_key
        }
      ]
    ]) : "${queue.name}" => queue
  }

  name                = each.value.name
  resource_group_name = azurerm_resource_group.lzenrg1.name
  deployment_mode     = "Incremental"
  template_content = <<TEMPLATE
{
    "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
    "contentVersion": "1.0.0.0",
    "parameters": {},
    "variables": {
      "storageAccounts_name": "${each.value.storage_account_name}",
      "queue_name": "${each.value.name}"
    },
    "resources": [
        {
            "type": "Microsoft.Storage/storageAccounts/queueServices/queues",
            "apiVersion": "2021-09-01",
            "name": "[concat(variables('storageAccounts_name'), '/default/', concat(variables('queue_name')))]",
            "properties": {
                "metadata": {}
            }
        }
    ],
    "outputs": {
        "queueId": {
            "type": "string",
            "value": "[resourceId('Microsoft.Storage/storageAccounts/queueServices/queues', variables('storageAccounts_name'), 'default', variables('queue_name'))]"
        }
    }
}
TEMPLATE
  depends_on = [azurerm_storage_account.lzenrg1]
}

resource "azurerm_resource_group_template_deployment" "share1__lzenrg1" {
  provider = azurerm.lzensub1
  for_each = {
    for share in flatten([
      for sa_key, sa_value in var.storage_account__lzenrg1 : [
        for share_key, share_value in sa_value.storage_share : {
          name = share_key
          storage_account_name = sa_key
          share_quota = share_value.quota
        }
      ]
    ]) : "${share.name}" => share
  }

  name                = each.value.name
  resource_group_name = azurerm_resource_group.lzenrg1.name
  deployment_mode     = "Incremental"
  template_content = <<TEMPLATE
{
    "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
    "contentVersion": "1.0.0.0",
    "parameters": {},
    "variables": {
        "storageAccounts_name": "${each.value.storage_account_name}",
        "share_name": "${each.value.name}",
        "share_quota": "${each.value.share_quota}"
    },
    "resources": [
        {
            "type": "Microsoft.Storage/storageAccounts/fileServices/shares",
            "apiVersion": "2021-09-01",
            "name": "[concat(variables('storageAccounts_name'), '/default/', concat(variables('share_name')))]",
            "properties": {
                "accessTier": "TransactionOptimized",
                "enabledProtocols": "SMB",
                "shareQuota": "[variables('share_quota')]"
            }
        }
    ],
    "outputs": {
        "shareId": {
            "type": "string",
            "value": "[resourceId('Microsoft.Storage/storageAccounts/fileServices/shares', variables('storageAccounts_name'), 'default', variables('share_name'))]"
        }
    }
}
TEMPLATE
  depends_on = [azurerm_storage_account.lzenrg1]
}

resource "azurerm_resource_group_template_deployment" "table1__lzenrg1" {
  provider = azurerm.lzensub1
  for_each = {
    for table in flatten([
      for sa_key, sa_value in var.storage_account__lzenrg1 : [
        for table_key, table_value in sa_value.storage_table : {
          name = table_key
          storage_account_name = sa_key
        }
      ]
    ]) : "${table.name}" => table
  }

  name                = each.value.name
  resource_group_name = azurerm_resource_group.lzenrg1.name
  deployment_mode     = "Incremental"
  template_content = <<TEMPLATE
{
    "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
    "contentVersion": "1.0.0.0",
    "parameters": {},
    "variables": {
      "storageAccounts_name": "${each.value.storage_account_name}",
      "table_name": "${each.value.name}"
    },
    "resources": [
        {
            "type": "Microsoft.Storage/storageAccounts/tableServices/tables",
            "apiVersion": "2021-09-01",
            "name": "[concat(variables('storageAccounts_name'), '/default/', concat(variables('table_name')))]",
            "properties": {}
        }
    ],
    "outputs": {
        "tableId": {
            "type": "string",
            "value": "[resourceId('Microsoft.Storage/storageAccounts/tableServices/tables', variables('storageAccounts_name'), 'default', variables('table_name'))]"
        }
    }
}
TEMPLATE
  depends_on = [azurerm_storage_account.lzenrg1]
}

resource "azurerm_resource_group" "lzenrg1" {
  provider = azurerm.lzensub1
  name     = var.name__lzenrg1
  location = var.location__lzenrg1
}

resource "azurerm_network_security_group" "lzenrg21" {
  provider = azurerm.lzensub1
  for_each            = var.network_security_group__lzenrg2
  name                = each.key
  location            = azurerm_resource_group.lzenrg2.location
  resource_group_name = azurerm_resource_group.lzenrg2.name

  dynamic "security_rule" {
    for_each = each.value.security_rules
    iterator = security_rule

    content {
      name                           = security_rule.value.name
      priority                       = security_rule.value.priority
      direction                      = security_rule.value.direction
      access                         = security_rule.value.access
      protocol                       = security_rule.value.protocol
      source_port_ranges             = split(",", replace(security_rule.value.source_port_ranges, "*", "0-65535"))
      destination_port_ranges        = split(",", replace(security_rule.value.destination_port_ranges, "*", "0-65535"))
      source_address_prefix          = length(split(",", security_rule.value.source_address_prefixes)) == 1 ? replace(security_rule.value.source_address_prefixes, "*", "0.0.0.0/0") : null
      source_address_prefixes        = length(split(",", security_rule.value.source_address_prefixes)) >= 2 ? split(",", security_rule.value.source_address_prefixes) : null
      destination_address_prefix     = length(split(",", security_rule.value.destination_address_prefixes)) == 1 ? replace(security_rule.value.destination_address_prefixes, "*", "0.0.0.0/0") : null
      destination_address_prefixes   = length(split(",", security_rule.value.destination_address_prefixes)) >= 2 ? split(",", security_rule.value.destination_address_prefixes) : null
      description                    = security_rule.value.description
    }
  }
}

resource "azurerm_subnet_network_security_group_association" "lzenrg21" {
  provider = azurerm.lzensub1
  for_each = {
    for association in flatten([
      for nsg_key, nsg_value in var.network_security_group__lzenrg2 : [
        for i in range(length(nsg_value.linked_subnet)) : {
          subnet_name = nsg_value.linked_subnet[i]
          nsg_name    = nsg_key
        }
      ]
    ]) : "${association.subnet_name}" => association
  }
  subnet_id                 = azurerm_subnet.lzenrg2["${each.value.subnet_name}"].id
  network_security_group_id = azurerm_network_security_group.lzenrg21["${each.value.nsg_name}"].id
}


resource "azurerm_virtual_network" "lzenrg2" {
  provider = azurerm.lzensub1
  for_each            = var.virtual_network__lzenrg2
  name                = each.key
  location            = azurerm_resource_group.lzenrg2.location
  resource_group_name = azurerm_resource_group.lzenrg2.name
  address_space       = each.value.vnet_address_space

  dynamic "ddos_protection_plan" {
    for_each = "${each.value.enable_ddos_protection}" == true ? [1] : []
    content {
      id     = azurerm_network_ddos_protection_plan.lzenrg2.id
      enable = true
    }
  }
}


resource "azurerm_network_ddos_protection_plan" "lzenrg2" {
  provider = azurerm.lzensub1
  name                = var.ddos_protection_plan_name__lzenrg2
  location            = azurerm_resource_group.lzenrg2.location
  resource_group_name = azurerm_resource_group.lzenrg2.name
}

resource "azurerm_dns_zone" "lzenrg2" {
  provider = azurerm.lzensub1
  for_each = var.dns_zone__lzenrg2
  name = each.key
  resource_group_name = azurerm_resource_group.lzenrg2.name
}

resource "azurerm_dns_a_record" "lzenrg2" {
  provider = azurerm.lzensub1
  for_each = {
    for record in flatten([
      for zone_key, zone_value in var.dns_zone__lzenrg2 : [
          for record_key, record_value in zone_value.dns_a_record : {
            included_zone_name = zone_key
            name    = record_key
            ttl     = record_value.ttl
            records = record_value.records
          }
        ]
    ]) : "${record.name}" => record
  }

  name      = each.value.name
  zone_name = each.value.included_zone_name
  resource_group_name = azurerm_resource_group.lzenrg2.name
  ttl       = each.value.ttl
  records   = each.value.records
}

resource "azurerm_dns_ns_record" "lzenrg2" {
  provider = azurerm.lzensub1
  for_each = {
    for record in flatten([
      for zone_key, zone_value in var.dns_zone__lzenrg2 : [
          for record_key, record_value in zone_value.dns_ns_record : {
            included_zone_name = zone_key
            name    = record_key
            ttl     = record_value.ttl
            records = record_value.records
          }
        ]
    ]) : "${record.name}" => record
  }

  name      = each.value.name
  zone_name = each.value.included_zone_name
  resource_group_name = azurerm_resource_group.lzenrg2.name
  ttl       = each.value.ttl
  records   = each.value.records
}

resource "azurerm_dns_cname_record" "lzenrg2" {
  provider = azurerm.lzensub1
  for_each = {
    for record in flatten([
      for zone_key, zone_value in var.dns_zone__lzenrg2 : [
          for record_key, record_value in zone_value.dns_cname_record : {
            included_zone_name = zone_key
            name    = record_key
            ttl     = record_value.ttl
            record = record_value.record
          }
        ]
    ]) : "${record.name}" => record
  }

  name      = each.value.name
  zone_name = each.value.included_zone_name
  resource_group_name = azurerm_resource_group.lzenrg2.name
  ttl       = each.value.ttl
  record   = each.value.record
}

resource "azurerm_dns_ptr_record" "lzenrg2" {
  provider = azurerm.lzensub1
  for_each = {
    for record in flatten([
      for zone_key, zone_value in var.dns_zone__lzenrg2 : [
          for record_key, record_value in zone_value.dns_ptr_record : {
            included_zone_name = zone_key
            name    = record_key
            ttl     = record_value.ttl
            records = record_value.records
          }
        ]
    ]) : "${record.name}" => record
  }

  name      = each.value.name
  zone_name = each.value.included_zone_name
  resource_group_name = azurerm_resource_group.lzenrg2.name
  ttl       = each.value.ttl
  records   = each.value.records
}

resource "azurerm_subnet" "lzenrg2" {
  provider = azurerm.lzensub1
  for_each             = var.subnet__lzenrg2 
  name                 = each.key     
  resource_group_name  = azurerm_resource_group.lzenrg2.name
  virtual_network_name = azurerm_virtual_network.lzenrg2[each.value.included_vnet_name].name
  address_prefixes     = [ each.value.address_prefixes ]
  enforce_private_link_endpoint_network_policies = each.value.private_link_endpoint_enabled

  dynamic delegation {
    for_each = each.value.delegation
    content {
      name = delegation.key
      service_delegation {
        name = delegation.value.service_name
        actions = delegation.value.actions
      }
    }
  }
}

resource "azurerm_public_ip" "lzenrg2" {
  provider = azurerm.lzensub1
  for_each = {
    for pip in flatten([
      for pip_key, pip_value in var.public_load_balancer__lzenrg2 : [
        for key, value in pip_value.public_lb_frontend_ip_config : [{
          name              = key
          sku               = value.pip_sku
          allocation_method = value.pip_allocation_method
        }
      ]
    ]]) : "${pip.name}" => pip
  }

  name                = "${each.value.name}-pip"
  resource_group_name = azurerm_resource_group.lzenrg2.name
  location            = azurerm_resource_group.lzenrg2.location
  sku                 = each.value.sku
  allocation_method   = each.value.allocation_method
}

resource "azurerm_lb" "lzenrg2" {
  provider = azurerm.lzensub1
  for_each            = var.public_load_balancer__lzenrg2
  name                = each.key
  resource_group_name = azurerm_resource_group.lzenrg2.name
  location            = azurerm_resource_group.lzenrg2.location
  sku                 = each.value.sku
  sku_tier            = "Regional"

  dynamic "frontend_ip_configuration" {
    for_each = each.value.public_lb_frontend_ip_config
    iterator = frontend
    content {
      name = frontend.key
      public_ip_address_id = azurerm_public_ip.lzenrg2[frontend.key].id
    }
  }
}

resource "azurerm_lb_backend_address_pool" "lzenrg2" {
  provider = azurerm.lzensub1
  for_each = {
    for backend_pool in flatten([
      for backend_key, backend_value in var.public_load_balancer__lzenrg2 : [
        for key, value in backend_value.backend_pool : {
          name    = value.backend_pool_name
          lb_name = backend_key
        }
    ]]) : "${backend_pool.name}" => backend_pool
  }

  loadbalancer_id = azurerm_lb.lzenrg2[each.value.lb_name].id
  name            = each.value.name
}

resource "azurerm_lb_backend_address_pool_address" "lzenrg2" {
  provider = azurerm.lzensub1
  for_each = {
    for backend_pool_address in flatten([
      for address_key, address_value in var.public_load_balancer__lzenrg2 : [
        for key, value in address_value.backend_pool: [
          for i in range(length(value.virtual_machine_names)) : [{
            backend_pool_name    = value.backend_pool_name
            virtual_network_name = value.linked_virtual_network_name
            virtual_machine_name = value.virtual_machine_names[i]
          }
        ]
      ]
    ]]) : "${backend_pool_address.virtual_machine_name}" => backend_pool_address
  }

  name                    = each.value.virtual_machine_name
  backend_address_pool_id = azurerm_lb_backend_address_pool.lzenrg2[each.value.backend_pool_name].id
  virtual_network_id      = azurerm_virtual_network.lzenrg2[each.value.virtual_network_name].id
  ip_address              = azurerm_linux_virtual_machine.lzenrg2[each.value.virtual_machine_name].private_ip_address
}

resource "azurerm_lb_probe" "lzenrg2" {
  provider = azurerm.lzensub1
  for_each = {
    for probe in flatten([
      for probe_key, probe_value in var.public_load_balancer__lzenrg2 : [
        for key, value in probe_value.rule : {
          name    = key
          port    = value.probe_port
          lb_name = probe_key
        }
      ]
    ]) : "${probe.name}" => probe
  }

  loadbalancer_id = azurerm_lb.lzenrg2[each.value.lb_name].id
  name            = "${each.value.name}-probe"
  port            = each.value.port
}

resource "azurerm_lb_rule" "lzenrg2" {
  provider = azurerm.lzensub1
  for_each = {
    for distribution_rule in flatten([
      for rule_key, rule_value in var.public_load_balancer__lzenrg2 : [
        for key, value in rule_value.rule : {
          lb_name                 = rule_key
          rule_name               = key
          protocol                = value.protocol
          frontend_port           = value.frontend_port
          backend_port            = value.backend_port
          disable_outbound_snat   = value.disable_outbound_snat
          frontend_ip_config_name = value.frontend_ip_config_name 
          backend_pool_name       = value.backend_pool_name
        }
      ]
    ]) : "${distribution_rule.rule_name}" => distribution_rule
  }

  loadbalancer_id                = azurerm_lb.lzenrg2[each.value.lb_name].id
  name                           = each.value.rule_name
  protocol                       = each.value.protocol
  frontend_port                  = each.value.frontend_port
  backend_port                   = each.value.backend_port
  disable_outbound_snat          = each.value.disable_outbound_snat
  frontend_ip_configuration_name = each.value.frontend_ip_config_name
  backend_address_pool_ids       = [ azurerm_lb_backend_address_pool.lzenrg2[each.value.backend_pool_name].id ]
}

resource "azurerm_lb_nat_rule" "lzenrg2" {
  provider = azurerm.lzensub1
  for_each = {
    for nat_rule in flatten([
      for nat_rule_key, nat_rule_value in var.public_load_balancer__lzenrg2 : [
        for key, value in nat_rule_value.nat_rule : {
          nat_rule_name           = key
          protocol                = value.protocol
          frontend_port           = value.frontend_port
          backend_port            = value.backend_port
          lb_name                 = nat_rule_key
          frontend_ip_config_name = value.frontend_ip_config_name 
        }
      ] 
    ]) : "${nat_rule.nat_rule_name}" => nat_rule
  }

  resource_group_name            = azurerm_resource_group.lzenrg2.name
  loadbalancer_id                = azurerm_lb.lzenrg2[each.value.lb_name].id
  name                           = each.value.nat_rule_name     
  protocol                       = each.value.protocol
  frontend_port                  = each.value.frontend_port
  backend_port                   = each.value.backend_port
  frontend_ip_configuration_name = each.value.frontend_ip_config_name
}

resource "azurerm_lb_outbound_rule" "lzenrg2" {
  provider = azurerm.lzensub1
  for_each = {
    for outbound_rule in flatten([
      for outbound_rule_key, outbound_rule_value in var.public_load_balancer__lzenrg2 : [
        for key, value in outbound_rule_value.outbound_rule : {
          lb_name                 = outbound_rule_key
          outbound_rule_name      = key
          protocol                = value.protocol
          frontend_ip_config_name = value.frontend_ip_config_name 
          backend_pool_name       = value.backend_pool_name
        }
      ] 
    ]) : "${outbound_rule.outbound_rule_name}" => outbound_rule
  }

  loadbalancer_id         = azurerm_lb.lzenrg2[each.value.lb_name].id
  name                    = each.value.outbound_rule_name
  protocol                = each.value.protocol
  backend_address_pool_id = azurerm_lb_backend_address_pool.lzenrg2[each.value.backend_pool_name].id
  
  frontend_ip_configuration {
    name = each.value.frontend_ip_config_name
  }
}

# destroy가 중간에 끊김 (depends_on 설정 필요)

resource "azurerm_key_vault" "lzenrg2" {
  provider = azurerm.lzensub1
  for_each                    = var.key_vault__lzenrg2
  name                        = each.key
  resource_group_name         = azurerm_resource_group.lzenrg2.name
  location                    = azurerm_resource_group.lzenrg2.location
  tenant_id                   = var.tenant_id__lzensub1
  sku_name                    = each.value.sku_name
  enabled_for_disk_encryption = each.value.enabled_for_disk_encryption
  soft_delete_retention_days  = each.value.soft_delete_retention_days
  purge_protection_enabled    = each.value.purge_protection_enabled

  # tfsec:ignore:azure-keyvault-specify-network-acl
  network_acls {
    bypass         = each.value.network_acl_bypass  
    default_action = each.value.network_acl_action
    ip_rules       = each.value.network_acl_ip_rules
  }

  dynamic "access_policy" {
    for_each = each.value.access_policies
    iterator = access_policy

    content {
      tenant_id = var.tenant_id__lzensub1 
      object_id = access_policy.value.object_id

      key_permissions         = access_policy.value.key_permissions
      secret_permissions      = access_policy.value.secret_permissions
      certificate_permissions = access_policy.value.certificate_permissions
    }
  }
}

resource "azurerm_key_vault_secret" "lzenrg2" {
  provider = azurerm.lzensub1
  for_each = {
    for secret in flatten([
      for vault_key, vault_value in var.key_vault__lzenrg2 : [
        for secret_key, secret_value in vault_value.key_vault_secret : {
          name                    = secret_value.name
          included_key_vault_name = vault_key
          expiration_date         = secret_value.expiration_date
        }
      ]
    ]) : "${secret.name}" => secret
  }

  name            = each.value.name
  value           = var.tenant_id__lzensub1
  key_vault_id    = azurerm_key_vault.lzenrg2[each.value.included_key_vault_name].id
  content_type    = "password"
  expiration_date = each.value.expiration_date
}

resource "azurerm_key_vault_key" "lzenrg2" {
  provider = azurerm.lzensub1
  for_each = {
    for key in flatten([
      for vault_key, vault_value in var.key_vault__lzenrg2 : [
        for key_key, key_value in vault_value.key_vault_key : {
          name                    = key_key
          type                    = key_value.type
          size                    = key_value.size
          curve                   = key_value.curve
          opts                    = key_value.opts
          expiration_date         = key_value.expiration_date
          included_key_vault_name = vault_key          
        }
      ]
    ]) : "${key.name}" => key
  }

  name            = each.value.name
  key_vault_id    = azurerm_key_vault.lzenrg2[each.value.included_key_vault_name].id
  key_type        = each.value.type
  curve           = contains(["EC", "EC-HSM"], each.value.type) ? each.value.curve : null
  key_size        = contains(["RSA", "RSA-HSM"], each.value.type) ? each.value.size : null
  key_opts        = each.value.opts
  expiration_date = each.value.expiration_date
}

resource "azurerm_key_vault_certificate" "lzenrg2" {
  provider = azurerm.lzensub1
  for_each = {
    for cert in flatten([
      for vault_key, vault_value in var.key_vault__lzenrg2 : [
        for cert_key, cert_value in vault_value.key_vault_certificate : {
          name  = cert_key
          import_existing_certificate = cert_value.import_existing_certificate
          contents     = cert_value.contents
          password     = cert_value.password
          issuer_name  = cert_value.issuer_name
          exportable   = cert_value.exportable
          key_size     = cert_value.key_size
          key_type     = cert_value.key_type
          reuse_key    = cert_value.reuse_key
          curve        = cert_value.curve
          content_type = cert_value.content_type
          key_usage    = cert_value.key_usage
          subject      = cert_value.subject
          validity_in_months      = cert_value.validity_in_months
          included_key_vault_name = vault_key          
        }
      ]
    ]) : "${cert.name}" => cert
  }

  name         = each.value.name
  key_vault_id = azurerm_key_vault.lzenrg2[each.value.included_key_vault_name].id

  dynamic "certificate" {
    for_each = each.value.import_existing_certificate == true ? [1] : []
    content {
      contents = filebase64(each.value.contents)
      password = each.value.password
    }
  }

  certificate_policy {
    issuer_parameters {
      name = each.value.issuer_name
    }

    key_properties {
      exportable = each.value.exportable
      key_size   = each.value.key_size
      key_type   = each.value.key_type
      reuse_key  = each.value.reuse_key
      curve      = each.value.key_type == "EC" ? each.value.curve : null
    }

    secret_properties {
      content_type = each.value.content_type
    }

    dynamic "x509_certificate_properties" {
      for_each = each.value.import_existing_certificate == false ? [1] : []
      content {
        key_usage          = each.value.key_usage
        subject            = each.value.subject
        validity_in_months = each.value.validity_in_months
      }  
    }
  }
}

resource "azurerm_log_analytics_workspace" "lzenrg2" {
  provider = azurerm.lzensub1
  for_each                   = var.log_analytics_workspace__lzenrg2
  name                       = each.key
  location                   = azurerm_resource_group.lzenrg2.location
  resource_group_name        = azurerm_resource_group.lzenrg2.name
  sku                        = "PerGB2018"  
  retention_in_days          = each.value.retention_in_days          
  internet_query_enabled     = each.value.internet_query_enabled     
  internet_ingestion_enabled = each.value.internet_ingestion_enabled 
}

resource "azurerm_log_analytics_linked_service" "lzenrg2" {
  provider = azurerm.lzensub1
  for_each = {
    for service in flatten([
      for workspace_key, workspace_value in var.log_analytics_workspace__lzenrg2 : [
        for i in range(length(workspace_value.linked_automation_account_names)) : {
          workspace_name = workspace_key
          service_name   = workspace_value.linked_automation_account_names[i]
        }
      ]
    ]) : "${service.service_name}" => service
  }

  resource_group_name = azurerm_resource_group.lzenrg2.name
  workspace_id        = azurerm_log_analytics_workspace.lzenrg2[each.value.workspace_name].id
  read_access_id      = azurerm_automation_account.lzenrg2[each.value.service_name].id
}

resource "azurerm_recovery_services_vault" "lzenrg2" {
  provider = azurerm.lzensub1
  for_each            = var.backup__lzenrg2
  name                = each.key
  location            = azurerm_resource_group.lzenrg2.location
  resource_group_name = azurerm_resource_group.lzenrg2.name
  sku                 = each.value.sku
  soft_delete_enabled = each.value.soft_delete_enabled

  identity {
    type = "SystemAssigned"
  }
}

resource "azurerm_backup_policy_vm" "lzenrg2" {
  provider = azurerm.lzensub1
  for_each = {
    for policy in flatten([
      for vault_key, vault_value in var.backup__lzenrg2 : [
        for key, value in vault_value.backup_policy_vm : {
          name                = key
          recovery_vault_name = vault_key
          backup_frequency    = value.backup_frequency
          backup_time         = value.backup_time
          backup_weekdays     = value.backup_weekdays
          retention_count     = value.retention_count
        }
      ]
    ]) : "${policy.name}" => policy
  }

  name                = each.value.name
  resource_group_name = azurerm_resource_group.lzenrg2.name
  recovery_vault_name = azurerm_recovery_services_vault.lzenrg2[each.value.recovery_vault_name].name
  timezone            = "Korea Standard Time"

  backup {
    frequency = each.value.backup_frequency
    time      = each.value.backup_time
    weekdays  = each.value.backup_frequency == "Weekly" ? each.value.backup_weekdays : null
  }

  dynamic "retention_daily" {
    for_each = each.value.backup_frequency == "Daily" ? [1] : []
    content {
      count = each.value.retention_count
    }
  }

  dynamic "retention_weekly" {
    for_each = each.value.backup_frequency == "Weekly" ? [1] : []
    content {
      count    = each.value.retention_count
      weekdays = each.value.backup_weekdays
    }
  }
}

resource "azurerm_backup_protected_vm" "lzenrg2" {
  provider = azurerm.lzensub1
  for_each = {
    for backup in flatten([
      for backup_key, backup_value in var.backup__lzenrg2 : [
        for key, value in backup_value.backup_protected_vm : {
          source_vm_name      = split(":", value.source_vm_name)[0]
          backup_policy_name  = value.backup_policy_name
          recovery_vault_name = backup_key
        }
      ]
    ]) : "${backup.recovery_vault_name}" => backup
  }

  resource_group_name = azurerm_resource_group.lzenrg2.name
  recovery_vault_name = azurerm_recovery_services_vault.lzenrg2[each.value.recovery_vault_name].name
  source_vm_id        = azurerm_linux_virtual_machine.lzenrg2[each.value.source_vm_name].id
  backup_policy_id    = azurerm_backup_policy_vm.lzenrg2[each.value.backup_policy_name].id
}


resource "azurerm_backup_container_storage_account" "lzenrg2" {
  provider = azurerm.lzensub1
  for_each = {
    for backup in flatten([
      for backup_key, backup_value in var.backup__lzenrg2 : [
        for key, value in backup_value.protected_share : {
          name                 = key
          storage_account_name = value.source_storage_account_name
          backup_policy_name   = value.backup_policy_name
          recovery_vault_name  = backup_key
        }
      ]
    ]) : "${backup.name}" => backup
  }

  resource_group_name = azurerm_resource_group.lzenrg2.name
  recovery_vault_name = azurerm_recovery_services_vault.lzenrg2[each.value.recovery_vault_name].name
  storage_account_id  = azurerm_storage_account.lzenrg2[each.value.storage_account_name].id
}

resource "azurerm_backup_policy_file_share" "lzenrg2" {
  provider = azurerm.lzensub1
  for_each = {
    for policy in flatten([
      for backup_key, backup_value in var.backup__lzenrg2 : [
        for key, value in backup_value.backup_policy_share : {
          name                = key
          recovery_vault_name = backup_key
          backup_frequency    = value.backup_frequency
          backup_time         = value.backup_time
          backup_weekdays     = value.backup_weekdays
          retention_count     = value.retention_count
        }
      ]
    ]) : "${policy.name}" => policy
  }

  name                = each.value.name
  resource_group_name = azurerm_resource_group.lzenrg2.name
  recovery_vault_name = azurerm_recovery_services_vault.lzenrg2[each.value.recovery_vault_name].name

  timezone = "Korea Standard Time"

  backup {
    frequency = each.value.backup_frequency
    time      = each.value.backup_time 
  }

  retention_daily {
    count = each.value.retention_count
  }

  dynamic "retention_weekly" {
    for_each = each.value.backup_frequency == "Weekly" ? [1] : []
    content {
      count    = each.value.retention_count
      weekdays = each.value.backup_weekdays
    }
  }

  depends_on = [
    azurerm_backup_container_storage_account.lzenrg2,
  ]
}

resource "azurerm_backup_protected_file_share" "lzenrg2" {
  provider = azurerm.lzensub1
  for_each = {
    for backup in flatten([
      for backup_key, backup_value in var.backup__lzenrg2 : [
        for key, value in backup_value.protected_share : {
          storage_account_name = value.source_storage_account_name
          source_share_name    = value.source_share_name
          backup_policy_name   = value.backup_policy_name
          recovery_vault_name  = backup_key
        }
      ]
    ]) : "${backup.recovery_vault_name}" => backup
  }

  resource_group_name       = azurerm_resource_group.lzenrg2.name
  recovery_vault_name       = azurerm_recovery_services_vault.lzenrg2[each.value.recovery_vault_name].name
  source_storage_account_id = azurerm_storage_account.lzenrg2[each.value.storage_account_name].id
  source_file_share_name    = each.value.source_share_name
  backup_policy_id          = azurerm_backup_policy_file_share.lzenrg2[each.value.backup_policy_name].id
}

resource "azurerm_storage_account" "lzenrg2" {
  provider = azurerm.lzensub1
  for_each                  = var.storage_account__lzenrg2
  name                      = each.key
  resource_group_name       = azurerm_resource_group.lzenrg2.name
  location                  = azurerm_resource_group.lzenrg2.location
  account_kind              = each.value.account_kind
  account_tier              = each.value.account_tier
  account_replication_type  = each.value.account_replication_type
  access_tier               = each.value.access_tier
  min_tls_version           = each.value.min_tls_version
  enable_https_traffic_only = each.value.enable_https_traffic_only

  # tfsec:ignore:azure-storage-default-action-deny
  dynamic "network_rules" {
    for_each = each.value.network_rules
    iterator = rule
    content {
      default_action = rule.value.default_action
      bypass = rule.value.bypass
      ip_rules = rule.value.ip_rules
    }
  }
}

resource "azurerm_resource_group_template_deployment" "container1__lzenrg2" {
  provider = azurerm.lzensub1
  for_each = {
    for container in flatten([
      for sa_key, sa_value in var.storage_account__lzenrg2 : [
        for container_key, container_value in sa_value.storage_container : {
          name = container_key
          storage_account_name = sa_key
          container_access_type = container_value.container_access_type
        }
      ]
    ]) : "${container.name}" => container
  }

  name                = each.value.name
  resource_group_name = azurerm_resource_group.lzenrg2.name
  deployment_mode     = "Incremental"
  template_content = <<TEMPLATE
{
    "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
    "contentVersion": "1.0.0.0",
    "parameters": {},
    "variables": {
      "storageAccounts_name": "${each.value.storage_account_name}",
      "container_name": "${each.value.name}",
      "container_type": "${each.value.container_access_type}"
    },
    "resources": [
        {
            "type": "Microsoft.Storage/storageAccounts/blobServices/containers",
            "apiVersion": "2021-09-01",
            "name": "[concat(variables('storageAccounts_name'), '/default/', concat(variables('container_name')))]",
            "properties": {
                "immutableStorageWithVersioning": {
                    "enabled": false
                },
                "defaultEncryptionScope": "$account-encryption-key",
                "denyEncryptionScopeOverride": false,
                "publicAccess": "[variables('container_type')]"
            }
        }
    ],
    "outputs": {
        "containerId": {
            "type": "string",
            "value": "[resourceId('Microsoft.Storage/storageAccounts/blobServices/containers', variables('storageAccounts_name'), 'default', variables('container_name'))]"
        }
    }
}
TEMPLATE
  depends_on = [azurerm_storage_account.lzenrg2]
}

resource "azurerm_resource_group_template_deployment" "queue1__lzenrg2" {
  provider = azurerm.lzensub1
  for_each = {
    for queue in flatten([
      for sa_key, sa_value in var.storage_account__lzenrg2 : [
        for queue_key, queue_value in sa_value.storage_queue : {
          name = queue_key
          storage_account_name = sa_key
        }
      ]
    ]) : "${queue.name}" => queue
  }

  name                = each.value.name
  resource_group_name = azurerm_resource_group.lzenrg2.name
  deployment_mode     = "Incremental"
  template_content = <<TEMPLATE
{
    "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
    "contentVersion": "1.0.0.0",
    "parameters": {},
    "variables": {
      "storageAccounts_name": "${each.value.storage_account_name}",
      "queue_name": "${each.value.name}"
    },
    "resources": [
        {
            "type": "Microsoft.Storage/storageAccounts/queueServices/queues",
            "apiVersion": "2021-09-01",
            "name": "[concat(variables('storageAccounts_name'), '/default/', concat(variables('queue_name')))]",
            "properties": {
                "metadata": {}
            }
        }
    ],
    "outputs": {
        "queueId": {
            "type": "string",
            "value": "[resourceId('Microsoft.Storage/storageAccounts/queueServices/queues', variables('storageAccounts_name'), 'default', variables('queue_name'))]"
        }
    }
}
TEMPLATE
  depends_on = [azurerm_storage_account.lzenrg2]
}

resource "azurerm_resource_group_template_deployment" "share1__lzenrg2" {
  provider = azurerm.lzensub1
  for_each = {
    for share in flatten([
      for sa_key, sa_value in var.storage_account__lzenrg2 : [
        for share_key, share_value in sa_value.storage_share : {
          name = share_key
          storage_account_name = sa_key
          share_quota = share_value.quota
        }
      ]
    ]) : "${share.name}" => share
  }

  name                = each.value.name
  resource_group_name = azurerm_resource_group.lzenrg2.name
  deployment_mode     = "Incremental"
  template_content = <<TEMPLATE
{
    "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
    "contentVersion": "1.0.0.0",
    "parameters": {},
    "variables": {
        "storageAccounts_name": "${each.value.storage_account_name}",
        "share_name": "${each.value.name}",
        "share_quota": "${each.value.share_quota}"
    },
    "resources": [
        {
            "type": "Microsoft.Storage/storageAccounts/fileServices/shares",
            "apiVersion": "2021-09-01",
            "name": "[concat(variables('storageAccounts_name'), '/default/', concat(variables('share_name')))]",
            "properties": {
                "accessTier": "TransactionOptimized",
                "enabledProtocols": "SMB",
                "shareQuota": "[variables('share_quota')]"
            }
        }
    ],
    "outputs": {
        "shareId": {
            "type": "string",
            "value": "[resourceId('Microsoft.Storage/storageAccounts/fileServices/shares', variables('storageAccounts_name'), 'default', variables('share_name'))]"
        }
    }
}
TEMPLATE
  depends_on = [azurerm_storage_account.lzenrg2]
}

resource "azurerm_resource_group_template_deployment" "table1__lzenrg2" {
  provider = azurerm.lzensub1
  for_each = {
    for table in flatten([
      for sa_key, sa_value in var.storage_account__lzenrg2 : [
        for table_key, table_value in sa_value.storage_table : {
          name = table_key
          storage_account_name = sa_key
        }
      ]
    ]) : "${table.name}" => table
  }

  name                = each.value.name
  resource_group_name = azurerm_resource_group.lzenrg2.name
  deployment_mode     = "Incremental"
  template_content = <<TEMPLATE
{
    "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
    "contentVersion": "1.0.0.0",
    "parameters": {},
    "variables": {
      "storageAccounts_name": "${each.value.storage_account_name}",
      "table_name": "${each.value.name}"
    },
    "resources": [
        {
            "type": "Microsoft.Storage/storageAccounts/tableServices/tables",
            "apiVersion": "2021-09-01",
            "name": "[concat(variables('storageAccounts_name'), '/default/', concat(variables('table_name')))]",
            "properties": {}
        }
    ],
    "outputs": {
        "tableId": {
            "type": "string",
            "value": "[resourceId('Microsoft.Storage/storageAccounts/tableServices/tables', variables('storageAccounts_name'), 'default', variables('table_name'))]"
        }
    }
}
TEMPLATE
  depends_on = [azurerm_storage_account.lzenrg2]
}

resource "azurerm_automation_account" "lzenrg2" {
  provider = azurerm.lzensub1
  for_each            = var.automation_account__lzenrg2
  name                = each.key
  location            = azurerm_resource_group.lzenrg2.location
  resource_group_name = azurerm_resource_group.lzenrg2.name
  sku_name            = each.value.sku_name
}

resource "azurerm_automation_credential" "lzenrg2" {
  provider = azurerm.lzensub1
  for_each = {
    for credential in flatten([
      for credential_key, credential_value in var.automation_account__lzenrg2 : [
        for key, value in credential_value.credential : {
          credential_name         = key
          username                = value.username
          password                = value.password
          automation_account_name = credential_key
        }
      ] 
    ]) : "${credential.credential_name}" => credential
  }

  name                    = each.value.credential_name
  resource_group_name     = azurerm_resource_group.lzenrg2.name
  automation_account_name = azurerm_automation_account.lzenrg2[each.value.automation_account_name].name
  username                = each.value.username
  password                = each.value.password
}

resource "azurerm_automation_runbook" "lzenrg2" {
  provider = azurerm.lzensub1
  for_each = {
    for runbook in flatten([
      for runbook_key, runbook_value in var.automation_account__lzenrg2 : [
        for key, value in runbook_value.runbook : {
          runbook_name            = key
          log_verbose             = value.log_verbose
          log_progress            = value.log_progress
          runbook_type            = value.runbook_type
          content                 = value.content
          uri                     = value.uri
          automation_account_name = runbook_key
        }
      ] 
    ]) : "${runbook.runbook_name}" => runbook
  }

  name                    = each.value.runbook_name
  location                = azurerm_resource_group.lzenrg2.location
  resource_group_name     = azurerm_resource_group.lzenrg2.name
  automation_account_name = azurerm_automation_account.lzenrg2[each.value.automation_account_name].name
  log_verbose             = each.value.log_verbose
  log_progress            = each.value.log_progress
  runbook_type            = each.value.runbook_type 

  content = each.value.content == "" ? null : each.value.content
  
  dynamic "publish_content_link" {
    for_each = each.value.content != "" ? {} : {uri = each.value.uri}
    iterator = link
    content {
      uri = link.value
    }
  }
}

resource "azurerm_automation_schedule" "lzenrg2" {
  provider = azurerm.lzensub1
  for_each = {
    for schedule in flatten([
      for schedule_key, schedule_value in var.automation_account__lzenrg2 : [
        for key, value in schedule_value.schedule : {
          schedule_name           = key
          frequency               = value.frequency
          interval                = value.interval
          start_time              = value.start_time
          week_days               = value.week_days
          automation_account_name = schedule_key
        }
      ] 
    ]) : "${schedule.schedule_name}" => schedule
  }

  name                    = each.value.schedule_name
  resource_group_name     = azurerm_resource_group.lzenrg2.name
  automation_account_name = azurerm_automation_account.lzenrg2[each.value.automation_account_name].name
  frequency               = each.value.frequency
  interval                = each.value.frequency == "OneTime" ? null : each.value.interval
  timezone                = "Asia/Seoul"
  start_time              = each.value.start_time
  week_days               = each.value.frequency == "Week" ? each.value.week_days : null
}

resource "azurerm_automation_job_schedule" "lzenrg2" {
  provider = azurerm.lzensub1
  for_each = {
    for job_schedule in flatten([
      for job_schedule_key, job_schedule_value in var.automation_account__lzenrg2 : [
        for key, value in job_schedule_value.schedule : {
          schedule_name           = key
          runbok_name             = value.runbook_name
          automation_account_name = job_schedule_key
        }
      ] 
    ]) : "${job_schedule.schedule_name}" => job_schedule
  }

  resource_group_name     = azurerm_resource_group.lzenrg2.name
  automation_account_name = each.value.automation_account_name
  schedule_name           = each.value.schedule_name
  runbook_name            = each.value.runbok_name

  depends_on = [
    azurerm_automation_account.lzenrg2,
    azurerm_automation_runbook.lzenrg2,
    azurerm_automation_schedule.lzenrg2,
  ]
}

resource "azurerm_automation_variable_bool" "lzenrg2" {
  provider = azurerm.lzensub1
  for_each = {
    for variable_bool in flatten([
      for variable_key, variable_value in var.automation_account__lzenrg2 : [
        for key, value in variable_value.variables : {
          variable_name           = key
          variable_type           = value.variable_type
          variable_value          = value.value
          automation_account_name = variable_key
        }
      ] 
    ]) : "${variable_bool.variable_name}" => variable_bool if variable_bool.variable_type == "bool"
  }

  name                    = each.value.variable_name
  resource_group_name     = azurerm_resource_group.lzenrg2.name
  automation_account_name = azurerm_automation_account.lzenrg2[each.value.automation_account_name].name
  value                   = each.value.variable_value
}

resource "azurerm_automation_variable_int" "lzenrg2" {
  provider = azurerm.lzensub1
  for_each = {
    for variable_bool in flatten([
      for variable_key, variable_value in var.automation_account__lzenrg2 : [
        for key, value in variable_value.variables : {
          variable_name           = key
          variable_type           = value.variable_type
          variable_value          = value.value
          automation_account_name = variable_key
        }
      ] 
    ]) : "${variable_bool.variable_name}" => variable_bool if variable_bool.variable_type == "int"
  }

  name                    = each.value.variable_name
  resource_group_name     = azurerm_resource_group.lzenrg2.name
  automation_account_name = azurerm_automation_account.lzenrg2[each.value.automation_account_name].name
  value                   = each.value.variable_value
}

resource "azurerm_automation_variable_string" "lzenrg2" {
  provider = azurerm.lzensub1
  for_each = {
    for variable_bool in flatten([
      for variable_key, variable_value in var.automation_account__lzenrg2 : [
        for key, value in variable_value.variables : {
          variable_name           = key
          variable_type           = value.variable_type
          variable_value          = value.value
          automation_account_name = variable_key
        }
      ]
    ]) : "${variable_bool.variable_name}" => variable_bool if variable_bool.variable_type == "string"
  }

  name                    = each.value.variable_name
  resource_group_name     = azurerm_resource_group.lzenrg2.name
  automation_account_name = azurerm_automation_account.lzenrg2[each.value.automation_account_name].name
  value                   = each.value.variable_value
}

resource "azurerm_automation_variable_datetime" "lzenrg2" {
  provider = azurerm.lzensub1
  for_each = {
    for variable_bool in flatten([
      for variable_key, variable_value in var.automation_account__lzenrg2 : [
        for key, value in variable_value.variables : {
          variable_name           = key
          variable_type           = value.variable_type
          variable_value          = value.value
          automation_account_name = variable_key
        }
      ] 
    ]) : "${variable_bool.variable_name}" => variable_bool if variable_bool.variable_type == "datetime"
  }

  name                    = each.value.variable_name
  resource_group_name     = azurerm_resource_group.lzenrg2.name
  automation_account_name = azurerm_automation_account.lzenrg2[each.value.automation_account_name].name
  value                   = each.value.variable_value
}

resource "azurerm_automation_dsc_configuration" "lzenrg2" {
  provider = azurerm.lzensub1
  for_each = {
    for configuration in flatten([
      for configuration_key, configuration_value in var.automation_account__lzenrg2 : [
        for key, value in configuration_value.configuration : {
          configuration_name      = key
          content_embedded        = value.content_embedded
          automation_account_name = configuration_key
        }
      ] 
    ]) : "${configuration.configuration_name}" => configuration
  }

  name                    = each.value.configuration_name
  resource_group_name     = azurerm_resource_group.lzenrg2.name
  automation_account_name = azurerm_automation_account.lzenrg2[each.value.automation_account_name].name
  location                = azurerm_resource_group.lzenrg2.location
  content_embedded        = each.value.content_embedded
}

resource "azurerm_automation_dsc_nodeconfiguration" "lzenrg2" {
  provider = azurerm.lzensub1
  for_each = {
    for nodeconfiguration in flatten([
      for nodeconfiguration_key, nodeconfiguration_value in var.automation_account__lzenrg2 : [
        for key, value in nodeconfiguration_value.nodeconfiguration : {
          nodeconfiguration_name  = key
          content_embedded        = value.content_embedded
          automation_account_name = nodeconfiguration_key
        }
      ] 
    ]) : "${nodeconfiguration.nodeconfiguration_name}" => nodeconfiguration
  }

  name                    = each.value.nodeconfiguration_name
  resource_group_name     = azurerm_resource_group.lzenrg2.name
  automation_account_name = azurerm_automation_account.lzenrg2[each.value.automation_account_name].name
  depends_on              = [
    azurerm_automation_dsc_configuration.lzenrg2
  ]

  content_embedded = <<mofcontent
instance of MSFT_FileDirectoryConfiguration as $MSFT_FileDirectoryConfiguration1ref
{
  ResourceID = "[File]bla";
  Ensure = "Present";
  Contents = "bogus Content";
  DestinationPath = "c:\\bogus.txt";
  ModuleName = "PSDesiredStateConfiguration";
  SourceInfo = "::3::9::file";
  ModuleVersion = "1.0";
  ConfigurationName = "bla";
};
instance of OMI_ConfigurationDocument
{
  Version="2.0.0";
  MinimumCompatibleVersion = "1.0.0";
  CompatibleVersionAdditionalProperties= {"Omi_BaseResource:ConfigurationName"};
  Author="bogusAuthor";
  GenerationDate="06/15/2018 14:06:24";
  GenerationHost="bogusComputer";
  Name="default";
};
mofcontent
}


resource "azurerm_linux_virtual_machine" "lzenrg2" {
  provider = azurerm.lzensub1
  for_each            = var.ubuntu_virtual_machine__lzenrg2
  name                = each.key
  resource_group_name = azurerm_resource_group.lzenrg2.name
  location            = azurerm_resource_group.lzenrg2.location
  size                = each.value.size

  network_interface_ids           = [ azurerm_network_interface.lzenrg2[each.key].id ]
  disable_password_authentication = each.value.disable_password_authentication
  admin_username                  = each.value.admin_username
  admin_password                  = each.value.disable_password_authentication == false ? each.value.admin_password : null

  dynamic "admin_ssh_key" {
    for_each = each.value.enable_ssh_key_authentication == true ? [1] : []
    content {
      username   = each.value.admin_username
      public_key = file("~/.ssh/id_rsa.pub")
    }
  }

  os_disk {
    caching              = each.value.os_disk_caching
    storage_account_type = each.value.storage_account_type
    disk_size_gb         = each.value.disk_size_gb
  }

  source_image_reference {
    publisher = "Canonical"          
    offer     = "UbuntuServer"     
    sku       = each.value.image_sku  
    version   = "latest"
  }
}

resource "azurerm_public_ip" "lzenrg21" {
  provider = azurerm.lzensub1
  for_each            = { for key, value in var.ubuntu_virtual_machine__lzenrg2 : key => value if value.pip_enable == true }
  name                = "${each.key}-pip"
  resource_group_name = azurerm_resource_group.lzenrg2.name
  location            = azurerm_resource_group.lzenrg2.location
  sku                 = each.value.pip_sku
  allocation_method   = each.value.pip_sku == "Standard" ? "Static" : each.value.pip_allocation_method
}

resource "azurerm_network_interface" "lzenrg2" {
  provider = azurerm.lzensub1
  for_each = var.ubuntu_virtual_machine__lzenrg2
  name                = each.value.network_interface_name
  location            = azurerm_resource_group.lzenrg2.location
  resource_group_name = azurerm_resource_group.lzenrg2.name

  ip_configuration {
    name                          = "${each.key}-ipconfig"
    subnet_id                     = azurerm_subnet.lzenrg2[each.value.included_subnet_name].id
    private_ip_address_allocation = each.value.private_ip_address == "" ? "Dynamic" : "Static"
    private_ip_address            = each.value.private_ip_address == "" ? null : each.value.private_ip_address
    public_ip_address_id          = each.value.pip_enable == true ? azurerm_public_ip.lzenrg21[each.key].id : null
  }
}


resource "azurerm_resource_group" "lzenrg2" {
  provider = azurerm.lzensub1
  name     = var.name__lzenrg2
  location = var.location__lzenrg2
}

