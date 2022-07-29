terraform {
  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = ">=3.20.0"
    }
  }
}

provider "azurerm" {
  tenant_id       = var.tenant_id__msaenters1
  subscription_id = var.subscription_id__msaenters1
  client_id       = var.serviceprincipal_id__msaenters1
  client_secret   = var.serviceprincipal_key__msaenters1
  features {}
}


# Create App Service Plan
resource "azurerm_service_plan" "msaenterrg" {
  for_each            = var.linux_app_service__msaenterrg
  name                = each.key
  resource_group_name = azurerm_resource_group.msaenterrg.name
  location            = azurerm_resource_group.msaenterrg.location
  os_type             = each.value.kind
  sku_name            = each.value.sku_tier
}

resource "azurerm_linux_web_app" "msaenterrg" {
  for_each = {
    for web_app in flatten([
      for app_key, app_value in var.linux_app_service__msaenterrg : [
        for key, value in app_value.app_service : {
          app_service_name                = key
          app_service_plan_name           = app_key
          client_cert_enabled             = value.client_cert_enabled
          auth_settings_enabled           = value.auth_settings_enabled
          detailed_error_messages_enabled = value.detailed_error_messages_enabled
          failed_request_tracing_enabled  = value.failed_request_tracing_enabled
          retention_in_days               = value.retention_in_days
          retention_in_mb                 = value.retention_in_mb
          ftps_state                      = value.ftps_state
          http2_enabled                   = value.http2_enabled
        }
      ] 
    ]) : "${web_app.app_service_name}" => web_app
  }

  name                       = each.key
  resource_group_name        = azurerm_resource_group.msaenterrg.name
  location                   = azurerm_resource_group.msaenterrg.location
  service_plan_id            = azurerm_service_plan.msaenterrg[each.value.app_service_plan_name].id
  client_certificate_enabled = each.value.client_cert_enabled

  auth_settings {
    enabled = each.value.auth_settings_enabled
  }

  logs {
    detailed_error_messages = each.value.detailed_error_messages_enabled
    failed_request_tracing  = each.value.failed_request_tracing_enabled
    http_logs {
      file_system {
        retention_in_days = each.value.retention_in_days
        retention_in_mb   = each.value.retention_in_mb
      }
    }
  }

  site_config {
    minimum_tls_version = 1.2
    ftps_state          = each.value.ftps_state
    http2_enabled       = each.value.http2_enabled
  }

  identity {
    type = "SystemAssigned"
  }
}


resource "azurerm_container_registry" "msaenterrg" {
  for_each                      = var.container_registry__msaenterrg
  name                          = each.key
  resource_group_name           = azurerm_resource_group.msaenterrg.name
  location                      = azurerm_resource_group.msaenterrg.location
  sku                           = each.value.sku
  admin_enabled                 = each.value.admin_enabled
  public_network_access_enabled = each.value.public_network_access_enabled

  dynamic "network_rule_set" {
    for_each = each.value.sku != "Premium" ? {} : each.value.network_rule_set
    iterator = network_rule
    content {
      default_action = network_rule.value.default_action
   
      ip_rule {
        action   = network_rule.value.action
        ip_range = network_rule.value.ip_range
      }
    }
  }
}

# Create MySQL Server
resource "azurerm_mysql_server" "msaenterrg" {
  for_each              = var.mysql__msaenterrg
  name                  = each.key
  location              = azurerm_resource_group.msaenterrg.location
  resource_group_name   = azurerm_resource_group.msaenterrg.name

  version                          = each.value.version
  sku_name                         = each.value.sku_name
  storage_mb                       = each.value.storage_mb
  administrator_login              = each.value.admin_login
  administrator_login_password     = each.value.admin_login_password
  public_network_access_enabled    = each.value.public_network_access_enabled
  ssl_enforcement_enabled          = each.value.ssl_enforcement_enabled
  ssl_minimal_tls_version_enforced = each.value.minimal_tls_version

  threat_detection_policy {
    enabled = each.value.threat_detection_enabled
  }
}

# Create Mysql DB
resource "azurerm_mysql_database" "msaenterrg" {
  for_each = {
    for mysql_database in flatten([
      for database_key, database_value in var.mysql__msaenterrg : [
        for key, value in database_value.database : {
          database_name = key
          charset       = value.charset
          collation     = value.collation
          server_name   = database_key
        }
      ] 
    ]) : "${mysql_database.database_name}" => mysql_database
  } 
  name                = each.value.database_name
  resource_group_name = azurerm_resource_group.msaenterrg.name
  server_name         = azurerm_mysql_server.msaenterrg[each.value.server_name].name
  charset             = each.value.charset
  collation           = each.value.collation
}

# Create Mysql DB Friewall

resource "azurerm_key_vault" "msaenterrg" {
  for_each                    = var.key_vault__msaenterrg
  name                        = each.key
  resource_group_name         = azurerm_resource_group.msaenterrg.name
  location                    = azurerm_resource_group.msaenterrg.location
  tenant_id                   = var.tenant_id__msaenters1
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
      tenant_id = var.tenant_id__msaenters1 
      object_id = access_policy.value.object_id

      key_permissions         = access_policy.value.key_permissions
      secret_permissions      = access_policy.value.secret_permissions
      certificate_permissions = access_policy.value.certificate_permissions
    }
  }
}

resource "azurerm_key_vault_secret" "msaenterrg" {
  for_each = {
    for secret in flatten([
      for vault_key, vault_value in var.key_vault__msaenterrg : [
        for secret_key, secret_value in vault_value.key_vault_secret : {
          name                    = secret_value.name
          included_key_vault_name = vault_key
          expiration_date         = secret_value.expiration_date
        }
      ]
    ]) : "${secret.name}" => secret
  }

  name            = each.value.name
  value           = var.tenant_id__msaenters1
  key_vault_id    = azurerm_key_vault.msaenterrg[each.value.included_key_vault_name].id
  content_type    = "password"
  expiration_date = each.value.expiration_date
}

resource "azurerm_key_vault_key" "msaenterrg" {
  for_each = {
    for key in flatten([
      for vault_key, vault_value in var.key_vault__msaenterrg : [
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
  key_vault_id    = azurerm_key_vault.msaenterrg[each.value.included_key_vault_name].id
  key_type        = each.value.type
  curve           = contains(["EC", "EC-HSM"], each.value.type) ? each.value.curve : null
  key_size        = contains(["RSA", "RSA-HSM"], each.value.type) ? each.value.size : null
  key_opts        = each.value.opts
  expiration_date = each.value.expiration_date
}

resource "azurerm_key_vault_certificate" "msaenterrg" {
  for_each = {
    for cert in flatten([
      for vault_key, vault_value in var.key_vault__msaenterrg : [
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
  key_vault_id = azurerm_key_vault.msaenterrg[each.value.included_key_vault_name].id

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

# Create Application Insights
resource "azurerm_application_insights" "msaenterrg" {
  for_each            = var.application_insights__msaenterrg
  name                = each.key
  location            = azurerm_resource_group.msaenterrg.location
  resource_group_name = azurerm_resource_group.msaenterrg.name
  application_type    = each.value.type
  retention_in_days   = each.value.retention_in_days
  workspace_id        = azurerm_log_analytics_workspace.msaenterrg[each.value.linked_workspace_name].id
}

resource "azurerm_log_analytics_workspace" "msaenterrg" {
  for_each                   = var.log_analytics_workspace__msaenterrg
  name                       = each.key
  location                   = azurerm_resource_group.msaenterrg.location
  resource_group_name        = azurerm_resource_group.msaenterrg.name
  sku                        = "PerGB2018"  
  retention_in_days          = each.value.retention_in_days          
  internet_query_enabled     = each.value.internet_query_enabled     
  internet_ingestion_enabled = each.value.internet_ingestion_enabled 
}


resource "azurerm_storage_account" "msaenterrg" {
  for_each                  = var.storage_account__msaenterrg
  name                      = each.key
  resource_group_name       = azurerm_resource_group.msaenterrg.name
  location                  = azurerm_resource_group.msaenterrg.location
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

resource "azurerm_resource_group_template_deployment" "container1__msaenterrg" {
  for_each = {
    for container in flatten([
      for sa_key, sa_value in var.storage_account__msaenterrg : [
        for container_key, container_value in sa_value.storage_container : {
          name = container_key
          storage_account_name = sa_key
          container_access_type = container_value.container_access_type
        }
      ]
    ]) : "${container.name}" => container
  }

  name                = each.value.name
  resource_group_name = azurerm_resource_group.msaenterrg.name
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
  depends_on = [azurerm_storage_account.msaenterrg]
}

resource "azurerm_resource_group_template_deployment" "queue1__msaenterrg" {
  for_each = {
    for queue in flatten([
      for sa_key, sa_value in var.storage_account__msaenterrg : [
        for queue_key, queue_value in sa_value.storage_queue : {
          name = queue_key
          storage_account_name = sa_key
        }
      ]
    ]) : "${queue.name}" => queue
  }

  name                = each.value.name
  resource_group_name = azurerm_resource_group.msaenterrg.name
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
  depends_on = [azurerm_storage_account.msaenterrg]
}

resource "azurerm_resource_group_template_deployment" "share1__msaenterrg" {
  for_each = {
    for share in flatten([
      for sa_key, sa_value in var.storage_account__msaenterrg : [
        for share_key, share_value in sa_value.storage_share : {
          name = share_key
          storage_account_name = sa_key
          share_quota = share_value.quota
        }
      ]
    ]) : "${share.name}" => share
  }

  name                = each.value.name
  resource_group_name = azurerm_resource_group.msaenterrg.name
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
  depends_on = [azurerm_storage_account.msaenterrg]
}

resource "azurerm_resource_group_template_deployment" "table1__msaenterrg" {
  for_each = {
    for table in flatten([
      for sa_key, sa_value in var.storage_account__msaenterrg : [
        for table_key, table_value in sa_value.storage_table : {
          name = table_key
          storage_account_name = sa_key
        }
      ]
    ]) : "${table.name}" => table
  }

  name                = each.value.name
  resource_group_name = azurerm_resource_group.msaenterrg.name
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
  depends_on = [azurerm_storage_account.msaenterrg]
}

resource "azurerm_virtual_network" "msaenterrg" {
  for_each            = {for key, value in var.kubernetes_cluster__msaenterrg : key => value if value.vnet_address_space != "" }
  name                = "${each.key}-vnet"
  location            = azurerm_resource_group.msaenterrg.location
  resource_group_name = azurerm_resource_group.msaenterrg.name
  address_space       = [ each.value.vnet_address_space ]
}

resource "azurerm_subnet" "msaenterrg" {
  for_each             = {for key, value in var.kubernetes_cluster__msaenterrg : key => value if value.vnet_address_space != "" }
  name                 = "${each.key}-subnet"
  resource_group_name  = azurerm_resource_group.msaenterrg.name
  virtual_network_name = azurerm_virtual_network.msaenterrg[each.key].name
  address_prefixes     = [ cidrsubnet(each.value.vnet_address_space, 8, 240) ]
  enforce_private_link_endpoint_network_policies = true
}

# Create Kubernetes Cluster
resource "azurerm_kubernetes_cluster" "msaenterrg" {
  for_each            = var.kubernetes_cluster__msaenterrg
  name                = each.key
  location            = azurerm_resource_group.msaenterrg.location
  resource_group_name = azurerm_resource_group.msaenterrg.name
  dns_prefix          = each.value.dns_prefix
  sku_tier            = each.value.sku_tier
  api_server_authorized_ip_ranges = each.value.enable_node_public_ip == false ? each.value.api_server_authorized_ip_ranges : null

  default_node_pool {
    name                  = each.value.node_pool_name
    node_count            = each.value.node_count
    vm_size               = each.value.default_node_vm_size
    os_disk_size_gb       = each.value.os_disk_size_gb
    max_pods              = each.value.max_pods
    enable_auto_scaling   = each.value.enable_auto_scaling
    enable_node_public_ip = each.value.enable_node_public_ip
    vnet_subnet_id        = each.value.vnet_address_space != "" ? azurerm_subnet.msaenterrg[each.key].id : null
  }

  service_principal {
    client_id     = var.serviceprincipal_id__msaenters1
    client_secret = var.serviceprincipal_key__msaenters1
  }

  dynamic "azure_active_directory_role_based_access_control" {
    for_each = each.value.aad_rbac_enabled == true ? [1] : []
    content {
      tenant_id = var.tenant_id__msaenters1
      managed   = true
    }
  }

  # tfsec:ignore:azure-container-logging
  network_profile {
    network_policy     = each.value.network_policy
    network_plugin     = each.value.network_plugin
    load_balancer_sku  = each.value.load_balancer_sku      
    pod_cidr           = each.value.network_plugin == "kubenet" ? each.value.pod_cidr : null
    service_cidr       = each.value.service_cidr
    dns_service_ip     = each.value.dns_service_ip
    docker_bridge_cidr = each.value.docker_bridge_cidr
    outbound_type      = each.value.outbound_type 
  }
}

# Create Kubernetes Cluster Node Pool
resource "azurerm_kubernetes_cluster_node_pool" "msaenterrg" {
  for_each = {
    for node_pool in flatten([
      for aks_key, aks_value in var.kubernetes_cluster__msaenterrg : [
        for node_pool_key, node_pool_value in aks_value.cluster_node_pool : {
          node_pool_name        = node_pool_key
          node_mode             = node_pool_value.node_mode
          os_type               = node_pool_value.node_os_type
          node_count            = node_pool_value.node_count
          node_vm_size          = node_pool_value.node_vm_size
          node_os_disk_size_gb  = node_pool_value.node_os_disk_size_gb
          node_max_pods         = node_pool_value.node_max_pods
          enable_auto_scaling   = node_pool_value.node_enable_auto_scaling
          enable_node_public_ip = node_pool_value.node_enable_node_public_ip
          included_aks_name     = aks_key
        }
      ] 
    ]) : "${node_pool.node_pool_name}" => node_pool
  } 

  kubernetes_cluster_id = azurerm_kubernetes_cluster.msaenterrg[each.value.included_aks_name].id
  name                  = each.value.node_pool_name
  mode                  = each.value.node_mode
  os_type               = each.value.node_mode == "System" ? "Linux" : each.value.os_type
  node_count            = each.value.node_count
  vm_size               = each.value.node_vm_size
  os_disk_size_gb       = each.value.node_os_disk_size_gb
  max_pods              = each.value.node_max_pods
  enable_auto_scaling   = each.value.enable_auto_scaling
  enable_node_public_ip = each.value.enable_node_public_ip
  vnet_subnet_id        = azurerm_subnet.msaenterrg[each.value.included_aks_name].id
}

resource "azurerm_resource_group" "msaenterrg" {
  name     = var.name__msaenterrg
  location = var.location__msaenterrg
}

