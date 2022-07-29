variable "tenant_id__lzensub1" {
    type = string
    description = "[text] ServicePrincipal tenant_id"
}

variable "subscription_id__lzensub1" {
    type = string
    description = "[text] ServicePrincipal Subscription ID"
}

variable "serviceprincipal_id__lzensub1" {
    type = string
    description = "[text] Service Principal Application ID"
}

variable "serviceprincipal_key__lzensub1" {
    type = string
    description = "[text] Service Principal Secret"
}

variable "security_center__lzensub1" {
    type = map(object({
        linked_log_analytics_workspace = string,
        assessment_policy = map(object({
            display_name = string,
            severity = string,
            description = string
        })),
        assessment = map(object({
            policy_name = string,
            target_resource_name = string,
            status_code = string
        })),
        linked_advanced_threat_protection = map(object({
            type = string,
            target_resource_name = string,
            enabled = bool
        }))
}    ))
    description = "[text] linked_log_analytics_workspace; [map] assessment_policy {[text] display_name; [radio] severity - Medium, Low, High; [text] description}; [map] assessment {[text] policy_name; [text] target_resource_name; [radio] status_code - Healthy, Unhealthy, NotApplicable}; [map] linked_advanced_threat_protection {[drop_down] type - app_service/linux_app_service, app_service/windows_app_service, database/mssql, database/mysql, database/postgresql, storage/storage_account, key_vault/key_vault, dns/dns_zone; [text] target_resource_name; [radio] enabled - true, false}"
    default = {
        "lzensc11" = {
            "linked_log_analytics_workspace" = "lzenrg1:lzenlaw1",
            "assessment_policy" = {
                "default_assessment_policy" = {
                    "display_name" = "Log Analytics Workspace Assessment Policy",
                    "description" = "Assess Log Analytics Workspace Vulnerability",
                    "severity" = "Medium"
                }
            },
            "assessment" = {
                "default_assessment" = {
                    "policy_name" = "default_assessment_policy",
                    "target_resource_name" = "lzenrg1:lzenlaw1",
                    "status_code" = "Healthy"
                }
            },
            "linked_advanced_threat_protection" = {
                "1" = {
                    "type" = "storage/storage_account",
                    "target_resource_name" = "lzenrg1:lzensa11",
                    "enabled" = "true"
                }
            }
        }
    }
}

variable "virtual_network__lzenrg1" {
    type = map(object({
        vnet_address_space = list(string),
        enable_ddos_protection = bool
}    ))
    description = "[text_area] vnet_address_space; [radio] enable_ddos_protection - true, false"
    default = {
        "lzenvn1" = {
            "vnet_address_space" = [
                "10.0.0.0/16"
            ],
            "enable_ddos_protection" = "false"
        }
    }
}

variable "firewall__lzenrg1" {
    type = map(object({
        sku_tier = string,
        sku_name = string,
        ip_config_name = string,
        included_vnet_name = string,
        address_prefixes = string,
        network_rule_collection = map(object({
            priority = number,
            action = string
        })),
        network_rules = map(object({
            source_addresses = list(string),
            destination_ports = list(number),
            destination_addresses = list(string),
            protocols = list(string)
        })),
        application_rule_collection = map(object({
            priority = number,
            action = string
        })),
        application_rules = map(object({
            source_addresses = list(string),
            target_fqdns = list(string),
            protocol_port = string,
            protocol_type = string
        })),
        nat_rule_collection = map(object({
            priority = number,
            action = string
        })),
        nat_rules = map(object({
            source_addresses = list(string),
            destination_ports = list(number),
            translated_port = number,
            translated_address = string,
            protocols = list(string)
        }))
}    ))
    description = "[radio] sku_tier - Standard, Premium; [radio] sku_name - AZFW_VNet, AZFW_Hub; [text] ip_config_name; [text] included_vnet_name; [text] address_prefixes; [map] network_rule_collection {[text] priority; [radio] action - Allow, Deny}; [map] network_rules {[text_area] source_addresses; [text_area] destination_ports; [text_area] destination_addresses; [text_area_list] protocols - TCP, UDP, ICMP, Any}; [map] application_rule_collection {[text] priority; [radio] action - Allow, Deny}; [map] application_rules {[text_area] source_addresses; [text_area] target_fqdns; [text] protocol_port; [radio] protocol_type - HTTP, HTTPS, Mssql}; [map] nat_rule_collection {[text] priority; [radio] action - Allow, Deny}; [map] nat_rules {[text_area] source_addresses; [text_area] destination_ports; [text] translated_port; [text] translated_address; [text_area_list] protocols - TCP, UDP, ICMP, Any}"
    default = {
        "lzenfw" = {
            "sku_tier" = "Standard",
            "sku_name" = "AZFW_VNet",
            "ip_config_name" = "default_firewall_ip_config",
            "included_vnet_name" = "lzenvn1",
            "address_prefixes" = "10.0.3.0/24",
            "network_rule_collection" = {
                "default_network_rule_collection" = {
                    "priority" = 100,
                    "action" = "Allow"
                }
            },
            "network_rules" = {
                "default_network_rules" = {
                    "source_addresses" = [
                        "8.8.8.8"
                    ],
                    "destination_ports" = [
                        53
                    ],
                    "protocols" = [
                        "TCP",
                        "UDP"
                    ],
                    "ip_rules" = []
                }
            },
            "application_rule_collection" = {
                "default_app_rule_collection" = {
                    "priority" = 200,
                    "action" = "Allow"
                }
            },
            "application_rules" = {
                "default_app_rules" = {
                    "source_addresses" = [
                        "*"
                    ],
                    "target_fqdns" = [
                        "*.com"
                    ],
                    "protocol_port" = "80",
                    "protocol_type" = "Http"
                }
            },
            "nat_rule_collection" = {
                "default_nat_rule_collection" = {
                    "priority" = 200,
                    "action" = "Dnat"
                }
            },
            "nat_rules" = {
                "default_nat_rules" = {
                    "source_addresses" = [
                        "10.0.0.0/16"
                    ],
                    "destination_ports" = [
                        53
                    ],
                    "translated_port" = 53,
                    "translated_address" = "8.8.8.8",
                    "protocols" = [
                        "TCP",
                        "UDP"
                    ]
                }
            }
        }
    }
}

variable "ddos_protection_plan_name__lzenrg1" {
    type = string
    description = "[text] ddos_protection_plan_name"
    default = "default_ddos_protection"
}

variable "dns_zone__lzenrg1" {
    type = map(object({
        dns_a_record = map(object({
            ttl = number,
            records = list(string)
        })),
        dns_ns_record = map(object({
            ttl = number,
            records = list(string)
        })),
        dns_cname_record = map(object({
            ttl = number,
            record = string
        })),
        dns_ptr_record = map(object({
            ttl = number,
            records = list(string)
        }))
}    ))
    description = "[map] dns_a_record {[text] ttl; [text_area] records}; [map] dns_ns_record {[text] ttl; [text_area] records}; [map] dns_cname_record {[text] ttl; [text] record}; [map] dns_ptr_record {[text] ttl; [text_area] records}"
    default = {
        "lzendz1.com" = {
            "dns_a_record" = {},
            "dns_cname_record" = {},
            "dns_ns_record" = {},
            "dns_ptr_record" = {}
        }
    }
}

variable "cost_management_export__lzenrg1" {
    type = map(object({
        recurrence_type = string,
        recurrence_period_start_date = string,
        recurrence_period_end_date = string,
        root_folder_path = string,
        export_type = string,
        export_time_frame = string,
        linked_storage_account_name = string,
        storage_container_name = string
}    ))
    description = "[drop_down] recurrence_type - Monthly, Annually, Daily, Weekly; [date] recurrence_period_start_date; [date] recurrence_period_end_date; [text] root_folder_path; [radio] export_type - Usage, AmortizedCost, ActualCost; [drop_down] export_time_frame - WeekToDate, TheLastWeek, Custom, etc; [text] linked_storage_account_name; [text] storage_container_name"
    default = {
        "lzencme11" = {
            "recurrence_type" = "Monthly",
            "recurrence_period_start_date" = "2022-06-30T17:22:22+00:00",
            "recurrence_period_end_date" = "2022-09-12T03:20:26+00:00",
            "root_folder_path" = "/root/updated",
            "export_type" = "Usage",
            "export_time_frame" = "WeekToDate",
            "linked_storage_account_name" = "lzensa11",
            "storage_container_name" = "kismicontainer"
        }
    }
}

variable "virtual_network_peering" {
    type = map(object({
        linked_vnet_name_01 = string,
        linked_vnet_name_02 = string
}    ))
    description = "[text] linked_vnet_name_01; [text] linked_vnet_name_02"
    default = {
        "lzenvnp" = {
            "linked_vnet_name_01" = "lzenvn1",
            "linked_vnet_name_02" = "lzenvn2"
        }
    }
}

variable "log_analytics_workspace__lzenrg1" {
    type = map(object({
        retention_in_days = string,
        internet_query_enabled = string,
        internet_ingestion_enabled = string,
        linked_automation_account_names = list(string)
}    ))
    description = "[text] retention_in_days; [radio] internet_query_enabled - true, false; [radio] internet_ingestion_enabled - true, false; [text_area] linked_automation_account_names"
    default = {
        "lzenlaw1" = {
            "retention_in_days" = 30,
            "internet_query_enabled" = "true",
            "internet_ingestion_enabled" = "true",
            "linked_automation_account_names" = []
        },
        "lzenlaw2" = {
            "retention_in_days" = 30,
            "internet_query_enabled" = "true",
            "internet_ingestion_enabled" = "true",
            "linked_automation_account_names" = []
        }
    }
}

variable "storage_account__lzenrg1" {
    type = map(object({
        account_kind = string,
        account_tier = string,
        account_replication_type = string,
        access_tier = string,
        min_tls_version = string,
        enable_https_traffic_only = string,
        network_rules = map(object({
            default_action = string,
            bypass = list(string),
            ip_rules = list(string)
        })),
        storage_container = map(object({
            container_access_type = string
        })),
        storage_queue = map(object({
            name = string
        })),
        storage_share = map(object({
            quota = number
        })),
        storage_table = map(object({
            name = string
        }))
}    ))
    description = "[drop_down] account_kind - StorageV2, Storage; [radio] account_tier - Standrd, Premium; [drop_down] account_replication_type - LRS, GRS, RAFRS, ZRS, GZRS, RAGZRS; [radio] access_tier - Hot, Cool; [radio] min_tls_version - TLS1_2, TLS1_1, TLS1_0; [radio] enable_https_traffic_only - true, false; [map] network_rules {[radio] default_action - Deny, Allow; [text_area_list] bypass - AzureServices, Logging, Metrics, None; [text_area] ip_rules}; [map] storage_container {[radio] container_access_type - None, Blob, Container}; [map] storage_queue {[text] name}; [map] storage_share {[text] quota}; [map] storage_table {[text] name}"
    default = {
        "lzensa11" = {
            "account_kind" = "StorageV2",
            "account_tier" = "Standard",
            "account_replication_type" = "LRS",
            "access_tier" = "Hot",
            "min_tls_version" = "TLS1_2",
            "enable_https_traffic_only" = "true",
            "network_rules" = {},
            "storage_container" = {
                "defualt-container" = {
                    "container_access_type" = "None",
                    "name" = "defualt-container"
                }
            },
            "storage_queue" = {},
            "storage_share" = {
                "default-share" = {
                    "quota" = "5",
                    "name" = "default-share"
                }
            },
            "storage_table" = {}
        }
    }
}

variable "name__lzenrg1" {
    type = string
    default = "lzenrg1"
    description = "[text] resource group name"
}

variable "location__lzenrg1" {
    type = string
    default = "koreacentral"
    description = "[drop_down] location - eastus, eastus2, southcentralus, westus2, westus3, australiaeast, southeastasia, northeurope, swedencentral, uksouth, westeurope, centralus, northcentralus, westus, southafricanorth, centralindia, eastasia, japaneast, jioindiawest, koreacentral, canadacentral, francecentral, germanywestcentral, norwayeast, switzerlandnorth, uaenorth, brazilsouth, centralusstage, eastusstage, eastus2stage, northcentralusstage, southcentralusstage, westusstage, westus2stage, asia, asiapacific, australia, brazil, canada, europe, france, germany, global, india, japan, korea, norway, southafrica, switzerland, uae, uk, unitedstates, eastasiastage, southeastasiastage, centraluseuap, eastus2euap, westcentralus, southafricawest, australiacentral, australiacentral2, australiasoutheast, japanwest, jioindiacentral, koreasouth, southindia, westindia, canadaeast, francesouth, germanynorth, norwaywest, switzerlandwest, ukwest, uaecentral, brazilsoutheast"
}

variable "network_security_group__lzenrg2" {
    type = map(object({
        security_rules = map(object({
            name = string,
            priority = number,
            direction = string,
            access = string,
            protocol = string,
            source_port_ranges = string,
            destination_port_ranges = string,
            source_address_prefixes = string,
            destination_address_prefixes = string,
            description = string
        })),
        linked_subnet = list(string),
        linked_network_interface = list(string)
}    ))
    description = "[map] security_rules {[text] name; [text] priority; [radio] direction - Inbound, Outbound; [radio] access - Allow, Deny; [drop_down] protocol - Tcp, Udp, Icmp, Esp, Ah, *; [text] source_port_ranges; [text] destination_port_ranges; [text] source_address_prefixes; [text] destination_address_prefixes; [text] description}; [text_area] linked_subnet; [text_area] linked_network_interface"
    default = {
        "lzennsg" = {
            "security_rules" = {
                "http" = {
                    "name" = "port_80",
                    "priority" = 200,
                    "direction" = "Inbound",
                    "access" = "Allow",
                    "protocol" = "Tcp",
                    "source_port_ranges" = "*",
                    "destination_port_ranges" = "80",
                    "source_address_prefixes" = "*",
                    "destination_address_prefixes" = "*",
                    "description" = "HTTP"
                },
                "https" = {
                    "name" = "port_443",
                    "priority" = 201,
                    "direction" = "Inbound",
                    "access" = "Allow",
                    "protocol" = "Tcp",
                    "source_port_ranges" = "*",
                    "destination_port_ranges" = "443",
                    "source_address_prefixes" = "*",
                    "destination_address_prefixes" = "*",
                    "description" = "HTTPS"
                }
            },
            "linked_subnet" = [
                "lzensn1"
            ],
            "linked_network_interface" = []
        }
    }
}

variable "virtual_network__lzenrg2" {
    type = map(object({
        vnet_address_space = list(string),
        enable_ddos_protection = bool
}    ))
    description = "[text_area] vnet_address_space; [radio] enable_ddos_protection - true, false"
    default = {
        "lzenvn2" = {
            "vnet_address_space" = [
                "10.1.0.0/16"
            ],
            "enable_ddos_protection" = "false"
        }
    }
}

variable "ddos_protection_plan_name__lzenrg2" {
    type = string
    description = "[text] ddos_protection_plan_name"
    default = "default_ddos_protection"
}

variable "dns_zone__lzenrg2" {
    type = map(object({
        dns_a_record = map(object({
            ttl = number,
            records = list(string)
        })),
        dns_ns_record = map(object({
            ttl = number,
            records = list(string)
        })),
        dns_cname_record = map(object({
            ttl = number,
            record = string
        })),
        dns_ptr_record = map(object({
            ttl = number,
            records = list(string)
        }))
}    ))
    description = "[map] dns_a_record {[text] ttl; [text_area] records}; [map] dns_ns_record {[text] ttl; [text_area] records}; [map] dns_cname_record {[text] ttl; [text] record}; [map] dns_ptr_record {[text] ttl; [text_area] records}"
    default = {
        "lzendz2.com" = {
            "dns_a_record" = {},
            "dns_cname_record" = {},
            "dns_ns_record" = {},
            "dns_ptr_record" = {}
        }
    }
}

variable "subnet__lzenrg2" {
    type = map(object({
        included_vnet_name = string,
        address_prefixes = string,
        private_link_endpoint_enabled = bool,
        delegation = map(object({
            service_name = string,
            actions = list(string)
        }))
}    ))
    description = "[text] included_vnet_name; [text] address_prefixes; [radio] private_link_endpoint_enabled - true, false; [map] delegation {[drop_down] service_name - Microsoft.ApiManagement/service, Microsoft.AzureCosmosDB/clusters, Microsoft.BareMetal/AzureVMware, Microsoft.BareMetal/CrayServers, Microsoft.Batch/batchAccounts, Microsoft.ContainerInstance/containerGroups, Microsoft.ContainerService/managedClusters, Microsoft.Databricks/workspaces, Microsoft.DBforMySQL/flexibleServers, Microsoft.DBforMySQL/serversv2, Microsoft.DBforPostgreSQL/flexibleServers, Microsoft.DBforPostgreSQL/serversv2, Microsoft.DBforPostgreSQL/singleServers, Microsoft.HardwareSecurityModules/dedicatedHSMs, Microsoft.Kusto/clusters, Microsoft.Logic/integrationServiceEnvironments, Microsoft.MachineLearningServices/workspaces, Microsoft.Netapp/volumes, Microsoft.Network/managedResolvers, Microsoft.PowerPlatform/vnetaccesslinks, Microsoft.ServiceFabricMesh/networks, Microsoft.Sql/managedInstances, Microsoft.Sql/servers, Microsoft.StoragePool/diskPools, Microsoft.StreamAnalytics/streamingJobs, Microsoft.Synapse/workspaces, Microsoft.Web/hostingEnvironments, Microsoft.Web/serverFarms; [text_area_list] actions - Microsoft.Network/networkinterfaces/*, Microsoft.Network/virtualNetworks/subnets/action, Microsoft.Network/virtualNetworks/subnets/join/action, Microsoft.Network/virtualNetworks/subnets/prepareNetworkPolicies/action, Microsoft.Network/virtualNetworks/subnets/unprepareNetworkPolicies/action}"
    default = {
        "lzensn1" = {
            "included_vnet_name" = "lzenvn2",
            "address_prefixes" = "10.1.0.0/24",
            "private_link_endpoint_enabled" = "true",
            "delegation" = {}
        }
    }
}

variable "public_load_balancer__lzenrg2" {
    type = map(object({
        sku = string,
        public_lb_frontend_ip_config = map(object({
            pip_sku = string,
            pip_allocation_method = string
        })),
        backend_pool = map(object({
            backend_pool_name = string,
            linked_virtual_network_name = string,
            virtual_machine_names = list(string)
        })),
        rule = map(object({
            protocol = string,
            frontend_port = number,
            backend_port = number,
            disable_outbound_snat = bool,
            frontend_ip_config_name = string,
            backend_pool_name = string,
            probe_port = number
        })),
        nat_rule = map(object({
            protocol = string,
            frontend_port = number,
            backend_port = number,
            frontend_ip_config_name = string
        })),
        outbound_rule = map(object({
            protocol = string,
            frontend_ip_config_name = string,
            backend_pool_name = string
        }))
}    ))
    description = "[radio] sku - Standard, Basic; [map] public_lb_frontend_ip_config {[radio] pip_sku - Standard, Basic; [radio] pip_allocation_method - Static, Dynamic}; [map] backend_pool {[text] backend_pool_name; [text] linked_virtual_network_name; [text_area_list] virtual_machine_names}; [map] rule {[radio] protocol - Tcp, Udp, All; [text] frontend_port; [text] backend_port; [radio] disable_outbound_snat - true, false; [text] frontend_ip_config_name; [text] backend_pool_name; [text] probe_port}; [map] nat_rule {[radio] protocol - Tcp, Udp, All; [text] frontend_port; [text] backend_port; [text] frontend_ip_config_name}; [map] outbound_rule {[radio] protocol - Tcp, Udp, All; [text] frontend_ip_config_name; [text] backend_pool_name}"
    default = {
        "lzenplb" = {
            "sku" = "Standard",
            "public_lb_frontend_ip_config" = {
                "frontendipconfig" = {
                    "pip_sku" = "Standard",
                    "pip_allocation_method" = "Static",
                    "name" = "frontendipconfig"
                }
            },
            "backend_pool" = {
                "lzenbackendpool" = {
                    "backend_pool_name" = "lzenbackendpool",
                    "linked_virtual_network_name" = "lzenvn2",
                    "virtual_machine_names" = [
                        "lzenuvm"
                    ],
                    "name" = "lzenbackendpool"
                }
            },
            "rule" = {},
            "nat_rule" = {},
            "outbound_rule" = {}
        }
    }
}

variable "key_vault__lzenrg2" {
    type = map(object({
        sku_name = string,
        enabled_for_disk_encryption = bool,
        soft_delete_retention_days = number,
        purge_protection_enabled = bool,
        network_acl_bypass = string,
        network_acl_action = string,
        network_acl_ip_rules = list(string),
        access_policies = map(object({
            object_id = string,
            key_permissions = list(string),
            secret_permissions = list(string),
            certificate_permissions = list(string)
        })),
        key_vault_secret = map(object({
            name = string,
            expiration_date = string
        })),
        key_vault_key = map(object({
            type = string,
            size = number,
            curve = string,
            expiration_date = string,
            opts = list(string)
        })),
        key_vault_certificate = map(object({
            import_existing_certificate = bool,
            contents = string,
            password = string,
            issuer_name = string,
            exportable = string,
            key_type = string,
            key_size = number,
            reuse_key = bool,
            curve = string,
            content_type = string,
            key_usage = list(string),
            subject = string,
            validity_in_months = number
        }))
}    ))
    description = "[radio] sku_name - standard, premium; [radio] enabled_for_disk_encryption - true, false; [text] soft_delete_retention_days; [radio] purge_protection_enabled - true, false; [radio] network_acl_bypass - AzureServices, None; [radio] network_acl_action - Deny, Allow; [text_area] network_acl_ip_rules; [map] access_policies {[password] object_id; [text_area_list] key_permissions - Backup, Create, Decrypt, Delete, Encrypt, Get, Import, List, Purge, Recover, Restore, Sign, UnwrapKey, Update, Verify, WrapKey; [text_area_list] secret_permissions - Backup, Delete, Get, List, Purge, Recover, Restore, Set; [text_area_list] certificate_permissions - Backup, Create, Delete, DeleteIssuers, Get, GetIssuers, Import, List, ListIssuers, ManageContacts, ManageIssuers, Purge, Recover, Restore, SetIssuers, Update}; [map] key_vault_secret {[text] name; [date] expiration_date}; [map] key_vault_key {[drop_down] type - EC, EC-HSM, RSA, RSA-HSM; [radio] size - 2048, 3072, 4096; [radio] curve - P-256, P-256K, P-384, P-521; [date] expiration_date; [text_area_list] opts - decrypt, encrypt, sign, unwrapKey, verify, wrapKey}; [map] key_vault_certificate {[radio] import_existing_certificate - false, true; [text] contents; [password] password; [radio] issuer_name - Self, Unknown; [radio] exportable - true, false; [radio] key_type - RSA, EC; [drop_down] key_size - 2048, 3072, 4096, 256, 384, 521; [drop_down] curve - P-256, P-256K, P-384, P-521; [radio] reuse_key - true, false; [radio] content_type - application/x-pkcs12, application/x-pem-file; [text_are_list] key_usage - cRLSign, dataEncipherment, decipherOnly, digitalSignature, encipherOnly, keyAgreement, keyCertSign, keyEncipherment, nonRepudiation; [text] subject; [text] validity_in_months}"
    default = {
        "lzenkv" = {
            "sku_name" = "standard",
            "enabled_for_disk_encryption" = "true",
            "soft_delete_retention_days" = 7,
            "purge_protection_enabled" = "false",
            "network_acl_bypass" = "AzureServices",
            "network_acl_action" = "Allow",
            "network_acl_ip_rules" = [],
            "access_policies" = {},
            "key_vault_secret" = {},
            "key_vault_key" = {},
            "key_vault_certificate" = {}
        }
    }
}

variable "log_analytics_workspace__lzenrg2" {
    type = map(object({
        retention_in_days = string,
        internet_query_enabled = string,
        internet_ingestion_enabled = string,
        linked_automation_account_names = list(string)
}    ))
    description = "[text] retention_in_days; [radio] internet_query_enabled - true, false; [radio] internet_ingestion_enabled - true, false; [text_area] linked_automation_account_names"
    default = {
        "lzenlaw3" = {
            "retention_in_days" = 30,
            "internet_query_enabled" = "true",
            "internet_ingestion_enabled" = "true",
            "linked_automation_account_names" = []
        },
        "lzenlaw4" = {
            "retention_in_days" = 30,
            "internet_query_enabled" = "true",
            "internet_ingestion_enabled" = "true",
            "linked_automation_account_names" = []
        }
    }
}

variable "backup__lzenrg2" {
    type = map(object({
        sku = string,
        soft_delete_enabled = string,
        backup_policy_vm = map(object({
            backup_frequency = string,
            backup_time = string,
            backup_weekdays = list(string),
            retention_count = number
        })),
        backup_protected_vm = map(object({
            backup_policy_name = string,
            source_vm_name = string
        })),
        backup_policy_share = map(object({
            backup_frequency = string,
            backup_time = string,
            backup_weekdays = list(string),
            retention_count = number
        })),
        protected_share = map(object({
            source_storage_account_name = string,
            source_share_name = string,
            backup_policy_name = string
        }))
}    ))
    description = "[radio] sku - Standard, RS0; [radio] soft_delete_enabled - false, true; [map] backup_policy_vm {[radio] backup_frequency - Daily, Weekly; [text] backup_time; [text_area_list] backup_weekdays - Sunday, Monday, Tuesday, Wednesday, Thursday, Friday, Saturday; [text] retention_count}; [map] backup_protected_vm {[text] backup_policy_name; [text] source_vm_name}; [map] backup_policy_share {[radio] backup_frequency - Daily, Weekly; [text] backup_time; [text_area_list] backup_weekdays - Sunday, Monday, Tuesday, Wednesday, Thursday, Friday, Saturday; [text] retention_count}; [map] protected_share {[text] source_storage_account_name; [text] source_share_name; [text] backup_policy_name}"
    default = {
        "lzenbackup" = {
            "sku" = "Standard",
            "soft_delete_enabled" = "false",
            "backup_policy_vm" = {
                "defaultvmbackuppolicy" = {
                    "backup_frequency" = "Weekly",
                    "backup_time" = "10:00",
                    "backup_weekdays" = [
                        "Sunday"
                    ],
                    "retention_count" = 52
                }
            },
            "backup_protected_vm" = {
                "backup_protected_vm1" = {
                    "backup_policy_name" = "defaultvmbackuppolicy",
                    "source_vm_name" = "lzenuvm:ubuntu_virtual_machine",
                    "name" = "backup_protected_vm1"
                }
            },
            "backup_policy_share" = {
                "defaultsharebackuppolicy" = {
                    "backup_frequency" = "Daily",
                    "backup_time" = "23:00",
                    "backup_weekdays" = [
                        "Sunday"
                    ],
                    "retention_count" = 52
                }
            },
            "protected_share" = {
                "protected_share1" = {
                    "source_storage_account_name" = "lzensa2",
                    "source_share_name" = "kismishare",
                    "backup_policy_name" = "defaultsharebackuppolicy"
                }
            }
        }
    }
}

variable "storage_account__lzenrg2" {
    type = map(object({
        account_kind = string,
        account_tier = string,
        account_replication_type = string,
        access_tier = string,
        min_tls_version = string,
        enable_https_traffic_only = string,
        network_rules = map(object({
            default_action = string,
            bypass = list(string),
            ip_rules = list(string)
        })),
        storage_container = map(object({
            container_access_type = string
        })),
        storage_queue = map(object({
            name = string
        })),
        storage_share = map(object({
            quota = number
        })),
        storage_table = map(object({
            name = string
        }))
}    ))
    description = "[drop_down] account_kind - StorageV2, Storage; [radio] account_tier - Standrd, Premium; [drop_down] account_replication_type - LRS, GRS, RAFRS, ZRS, GZRS, RAGZRS; [radio] access_tier - Hot, Cool; [radio] min_tls_version - TLS1_2, TLS1_1, TLS1_0; [radio] enable_https_traffic_only - true, false; [map] network_rules {[radio] default_action - Deny, Allow; [text_area_list] bypass - AzureServices, Logging, Metrics, None; [text_area] ip_rules}; [map] storage_container {[radio] container_access_type - None, Blob, Container}; [map] storage_queue {[text] name}; [map] storage_share {[text] quota}; [map] storage_table {[text] name}"
    default = {
        "lzensa2" = {
            "account_kind" = "StorageV2",
            "account_tier" = "Standard",
            "account_replication_type" = "LRS",
            "access_tier" = "Hot",
            "min_tls_version" = "TLS1_2",
            "enable_https_traffic_only" = "false",
            "network_rules" = {
                "default_rule" = {
                    "default_action" = "Deny",
                    "bypass" = [
                        "AzureServices"
                    ],
                    "ip_rules" = [
                        "20.194.25.110",
                        "1.227.58.2"
                    ]
                }
            },
            "storage_container" = {
                "default-container" = {
                    "container_access_type" = "None",
                    "name" = "default-container"
                }
            },
            "storage_queue" = {},
            "storage_share" = {
                "default-share" = {
                    "quota" = "5",
                    "name" = "default-share"
                }
            },
            "storage_table" = {}
        }
    }
}

variable "automation_account__lzenrg2" {
    type = map(object({
        sku_name = string,
        credential = map(object({
            username = string,
            password = string
        })),
        runbook = map(object({
            log_verbose = bool,
            log_progress = bool,
            runbook_type = string,
            content = string,
            uri = string
        })),
        schedule = map(object({
            frequency = string,
            interval = number,
            start_time = string,
            week_days = list(string),
            runbook_name = string
        })),
        variables = map(object({
            variable_type = string,
            value = any
        })),
        configuration = map(object({
            content_embedded = string
        })),
        nodeconfiguration = map(object({
            content_embedded = string
        }))
}    ))
    description = "[text] sku_name; [map] credential{[text] username; [text] password}; [map] runbook {[bool] log_verbose - true, false; [bool] log_progress - true, false; [drop_down] runbook_type - Script, Graph, GraphPowerShell, GraphPowerShellWorkflow, PowerShellWorkflow, PowerShell; [text] content; [text] uri}; [map] schedule {[drop_down] frequency - OneTime, Day, Hour, Week, Month; [text] interval; [date] start_time; [text_area_list] week_days - Monday, Tueseday, Wednesday, Thursday, Friday, Saturday, Sunday; [text] runbook_name}; [map] variables {[radio] variable_type - int, string, bool, datetime; [text] value}; [map] configuration {[text] content_embedded}; [map] nodeconfiguration {[text] content_embedded}"
    default = {
        "lzenaa1" = {
            "sku_name" = "Basic",
            "credential" = {
                "defaultCredentail" = {
                    "username" = "example_user",
                    "password" = "example_pwd"
                }
            },
            "runbook" = {},
            "schedule" = {},
            "variables" = {},
            "configuration" = {},
            "nodeconfiguration" = {}
        }
    }
}

variable "ubuntu_virtual_machine__lzenrg2" {
    type = map(object({
        size = string,
        disable_password_authentication = bool,
        enable_ssh_key_authentication = bool,
        admin_username = string,
        admin_password = string,
        os_disk_caching = string,
        storage_account_type = string,
        disk_size_gb = number,
        image_sku = string,
        network_interface_name = string,
        included_subnet_name = string,
        pip_enable = bool,
        pip_sku = string,
        pip_allocation_method = string,
        private_ip_address = string
}    ))
    description = "[drop_down] size - Standard_F2, Standard_DS1_v2, Standard_E2s_v3, etc; [radio] disable_password_authentication - false, true; [radio] enable_ssh_key_authentication - false, true; [text] admin_username; [password] admin_password; [radio] os_disk_caching - ReadWrite, ReadOnly, None; [radio] storage_account_type - Standard_LRS, StandardSSD_LRS, Premium_LRS; [text] disk_size_gb; [radio] image_sku - 18.04-LTS, 16.04-LTS; [text] network_interface_name; [text] included_subnet_name; [radio] pip_enable - true, false; [radio] pip_sku - Basic, Standard; [radio] pip_allocation_method - Static, Dynamic; [text] private_ip_address}"
    default = {
        "lzenuvm" = {
            "size" = "Standard_D2s_v3",
            "disable_password_authentication" = "false",
            "enable_ssh_key_authentication" = "false",
            "admin_username" = "admin",
            "admin_password" = "Pa$$w0rd",
            "os_disk_caching" = "ReadWrite",
            "storage_account_type" = "Standard_LRS",
            "disk_size_gb" = 128,
            "image_sku" = "18.04-LTS",
            "network_interface_name" = "lzenuvm-nic",
            "included_subnet_name" = "lzensn1",
            "pip_enable" = "false",
            "pip_sku" = "Basic",
            "pip_allocation_method" = "Static",
            "private_ip_address" = "10.1.0.4"
        }
    }
}

variable "name__lzenrg2" {
    type = string
    default = "lzenrg2"
    description = "[text] resource group name"
}

variable "location__lzenrg2" {
    type = string
    default = "southeastasia"
    description = "[drop_down] location - eastus, eastus2, southcentralus, westus2, westus3, australiaeast, southeastasia, northeurope, swedencentral, uksouth, westeurope, centralus, northcentralus, westus, southafricanorth, centralindia, eastasia, japaneast, jioindiawest, koreacentral, canadacentral, francecentral, germanywestcentral, norwayeast, switzerlandnorth, uaenorth, brazilsouth, centralusstage, eastusstage, eastus2stage, northcentralusstage, southcentralusstage, westusstage, westus2stage, asia, asiapacific, australia, brazil, canada, europe, france, germany, global, india, japan, korea, norway, southafrica, switzerland, uae, uk, unitedstates, eastasiastage, southeastasiastage, centraluseuap, eastus2euap, westcentralus, southafricawest, australiacentral, australiacentral2, australiasoutheast, japanwest, jioindiacentral, koreasouth, southindia, westindia, canadaeast, francesouth, germanynorth, norwaywest, switzerlandwest, ukwest, uaecentral, brazilsoutheast"
}


