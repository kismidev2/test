variable "tenant_id__msaenters1" {
    type = string
    description = "[text] ServicePrincipal tenant_id"
    default = "78289cd7-5dd9-459e-8ef1-74e21786df15"
}

variable "subscription_id__msaenters1" {
    type = string
    description = "[text] ServicePrincipal Subscription ID"
    default = "c2a094b9-add2-40f6-8427-7e6431127be1"
}

variable "serviceprincipal_id__msaenters1" {
    type = string
    description = "[text] Service Principal Application ID"
    default = "edb972f5-9139-4db0-b95b-a5c496aaa63e"
}

variable "serviceprincipal_key__msaenters1" {
    type = string
    description = "[text] Service Principal Secret"
    default = "FkS8Q~9tBxaK.k2Y.uqIJP8kvWXrk3XwFVeG6bgK"
}

variable "linux_app_service__msaenterrg" {
    type = map(object({
        kind = string,
        sku_tier = string,
        linked_subnet_name = string,
        app_service = map(object({
            client_cert_enabled = bool,
            auth_settings_enabled = bool,
            detailed_error_messages_enabled = bool,
            failed_request_tracing_enabled = bool,
            retention_in_days = number,
            retention_in_mb = number,
            ftps_state = string,
            http2_enabled = bool
        }))
}    ))
    description = "[radio] kind - Linux, Windows, WindowsContainer; [drop_down] sku_tier - B1, B2, B3, D1, F1, FREE, I1, I2, I3, I1v2, I2v2, I3v2, P1v2, P2v2, P3v2, P1v3, P2v3, P3v3, S1, S2, S3, SHARED, EP1, EP2, EP3, WS1, WS2, WS3; [text] linked_subnet_name; [map] app_service {[radio] client_cert_enabled - true, false; [radio] auth_settings_enabled - true, false; [radio] detailed_error_messages_enabled - true, false; [radio] failed_request_tracing_enabled - true, false; [text] retention_in_days; [text] retention_in_mb; [radio] ftps_state - Disabled, FtpsOnly, AllAllowed; [radio] http2_enabled - true, false}"
    default = {
        "msaenterlas" = {
            "kind" = "Linux",
            "sku_tier" = "B1",
            "linked_subnet_name" = "",
            "app_service" = {
                "default-appservice" = {
                    "client_cert_enabled" = "true",
                    "auth_settings_enabled" = "true",
                    "detailed_error_messages_enabled" = "true",
                    "failed_request_tracing_enabled" = "true",
                    "retention_in_days" = "5",
                    "retention_in_mb" = 25,
                    "ftps_state" = "Disabled",
                    "http2_enabled" = "true",
                    "name" = "default-appservice"
                }
            }
        }
    }
}

variable "container_registry__msaenterrg" {
    type = map(object({
        sku = string,
        admin_enabled = bool,
        public_network_access_enabled = bool,
        network_rule_set = map(object({
            default_action = string,
            action = string,
            ip_range = string
        }))
}    ))
    description = "[radio] sku - Basic, Standard, Premium; [radio] admin_enabled - false, true; [radio] public_network_access_enabled - true, false; [map] network_rule_set {[radio] default_action- Deny, Allow; [radio] action - Deny, Allow; [text] ip_range}"
    default = {
        "msaentercr" = {
            "sku" = "Premium",
            "admin_enabled" = "false",
            "public_network_access_enabled" = "true",
            "network_rule_set" = {}
        }
    }
}

variable "mysql__msaenterrg" {
    type = map(object({
        version = string,
        sku_name = string,
        storage_mb = number,
        admin_login = string,
        admin_login_password = string,
        public_network_access_enabled = bool,
        ssl_enforcement_enabled = bool,
        minimal_tls_version = string,
        threat_detection_enabled = bool,
        database = map(object({
            charset = string,
            collation = string
        })),
        firewall_rule = map(object({
            start_ip_address = string,
            end_ip_address = string
        }))
}    ))
    description = "[radio] version - 5.7, 5.6, 8.0; [drop_down] sku_name - B_Gen5_2, GP_Gen5_4, etc; [text] storage_mb; [text] admin_login; [password] admin_login_password; [radio] public_network_access_enabled - false, true; [radio] ssl_enforcement_enabled - true, false; [radio] minimal_tls_version - TLS1_2, TLS1_1, TLS1_0, TLSEnforcementDisabled; [radio] threat_detection_enabled - true, false; [map] database {[drop_down] charset - utf8; [drop_down] collation - utf8_unicode_ci}; [map] firewall_rule {[text] start_ip_address; [text] end_ip_address}"
    default = {
        "msaenterm" = {
            "version" = "5.7",
            "sku_name" = "GP_Gen5_4",
            "storage_mb" = 5120,
            "admin_login" = "admin",
            "admin_login_password" = "Pa$$w0rd",
            "public_network_access_enabled" = "false",
            "ssl_enforcement_enabled" = "true",
            "minimal_tls_version" = "TLS1_2",
            "threat_detection_enabled" = "true",
            "database" = {
                "defaultdatabase" = {
                    "charset" = "utf8",
                    "collation" = "utf8_unicode_ci"
                }
            },
            "firewall_rule" = {
                "defaultfirewall" = {
                    "start_ip_address" = "0.0.0.0",
                    "end_ip_address" = "0.0.0.0"
                }
            }
        }
    }
}

variable "key_vault__msaenterrg" {
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
        "msaenterkv" = {
            "sku_name" = "standard",
            "enabled_for_disk_encryption" = "true",
            "soft_delete_retention_days" = 7,
            "purge_protection_enabled" = "true",
            "network_acl_bypass" = "AzureServices",
            "network_acl_action" = "Deny",
            "network_acl_ip_rules" = [],
            "access_policies" = {},
            "key_vault_secret" = {},
            "key_vault_key" = {},
            "key_vault_certificate" = {}
        }
    }
}

variable "application_insights__msaenterrg" {
    type = map(object({
        type = string,
        retention_in_days = number,
        linked_workspace_name = string
}    ))
    description = "[drop_down] type - ios, java, Node.JS, other, MobileCenter, phone, store, web; [drop_down] retention_in_days - 30, 60, 90, 120, 180, 270, 365, 550, 730; [text] linked_workspace_name"
    default = {
        "msaenterai" = {
            "type" = "web",
            "retention_in_days" = "30",
            "linked_workspace_name" = "msaenterlaw"
        }
    }
}

variable "log_analytics_workspace__msaenterrg" {
    type = map(object({
        retention_in_days = string,
        internet_query_enabled = string,
        internet_ingestion_enabled = string,
        linked_automation_account_names = list(string)
}    ))
    description = "[text] retention_in_days; [radio] internet_query_enabled - true, false; [radio] internet_ingestion_enabled - true, false; [text_area] linked_automation_account_names"
    default = {
        "msaenterlaw" = {
            "retention_in_days" = 30,
            "internet_query_enabled" = "true",
            "internet_ingestion_enabled" = "true",
            "linked_automation_account_names" = []
        }
    }
}

variable "storage_account__msaenterrg" {
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
        "msaentersa" = {
            "account_kind" = "StorageV2",
            "account_tier" = "Standard",
            "account_replication_type" = "LRS",
            "access_tier" = "Hot",
            "min_tls_version" = "TLS1_2",
            "enable_https_traffic_only" = "true",
            "network_rules" = {
                "default-rule" = {
                    "default_action" = "Deny",
                    "bypass" = [],
                    "ip_rules" = [],
                    "name" = "default-rule"
                }
            },
            "storage_container" = {},
            "storage_queue" = {},
            "storage_share" = {},
            "storage_table" = {}
        }
    }
}

variable "kubernetes_cluster__msaenterrg" {
    type = map(object({
        vnet_address_space = string,
        dns_prefix = string,
        sku_tier = string,
        api_server_authorized_ip_ranges = list(string),
        node_pool_name = string,
        node_count = number,
        default_node_vm_size = string,
        os_disk_size_gb = number,
        max_pods = number,
        enable_auto_scaling = bool,
        enable_node_public_ip = bool,
        aad_rbac_enabled = bool,
        network_policy = string,
        network_plugin = string,
        load_balancer_sku = string,
        pod_cidr = string,
        service_cidr = string,
        dns_service_ip = string,
        docker_bridge_cidr = string,
        outbound_type = string,
        cluster_node_pool = map(object({
            node_mode = string,
            node_os_type = string,
            node_count = number,
            node_vm_size = string,
            node_os_disk_size_gb = number,
            node_max_pods = number,
            node_enable_auto_scaling = bool,
            node_enable_node_public_ip = bool
        }))
}    ))
    description = "[text] vnet_address_space; [text] dns_prefix; [radio] sku_tier - Free, Paid; [text_area] api_server_authorized_ip_ranges; [text] node_pool_name; [text] node_count; [drop_down] default_node_vm_size - Standard_DS2_v2, Standard_D2_v3, etc; [text] os_disk_size_gb; [text] max_pods; [radio] enable_auto_scaling - false, true; [radio] enable_node_public_ip - true, false; [radio] aad_rbac_enabled - true, false; [radio] network_policy - calico, azure; [radio] network_plugin - kubenet, azure; [radio] load_balancer_sku - standard, basic; [text] pod_cidr; [text] service_cidr; [text] dns_service_ip; [text] docker_bridge_cidr; [radio] outbound_type - loadBalancer, userDefinedRouting; [map] cluster_node_pool {[radio] node_mode - User, System; [radio] node_os_type - Linux, Windows; [text] node_count; [drop_down] node_vm_size - Standard_DS2_v2, Standard_D2_v3, etc; [text] node_os_disk_size_gb; [text] node_max_pods; [radio] node_enable_auto_scaling - false, true; [radio] node_enable_node_public_ip - true, false}"
    default = {
        "msaenterkc" = {
            "vnet_address_space" = "10.0.0.0/8",
            "dns_prefix" = "defaultAks",
            "sku_tier" = "Free",
            "api_server_authorized_ip_ranges" = [],
            "node_pool_name" = "defaultn01",
            "node_count" = 2,
            "default_node_vm_size" = "Standard_DS2_v2",
            "os_disk_size_gb" = 128,
            "max_pods" = 110,
            "enable_auto_scaling" = "false",
            "enable_node_public_ip" = "false",
            "aad_rbac_enabled" = "true",
            "network_policy" = "calico",
            "network_plugin" = "kubenet",
            "load_balancer_sku" = "standard",
            "pod_cidr" = "10.244.0.0/16",
            "service_cidr" = "10.0.0.0/16",
            "dns_service_ip" = "10.0.0.4",
            "docker_bridge_cidr" = "172.17.0.1/16",
            "outbound_type" = "loadBalancer",
            "cluster_node_pool" = {}
        }
    }
}

variable "name__msaenterrg" {
    type = string
    default = "msaenterrg"
    description = "[text] resource group name"
}

variable "location__msaenterrg" {
    type = string
    default = "koreacentral"
    description = "[drop_down] location - eastus, eastus2, southcentralus, westus2, westus3, australiaeast, southeastasia, northeurope, swedencentral, uksouth, westeurope, centralus, northcentralus, westus, southafricanorth, centralindia, eastasia, japaneast, jioindiawest, koreacentral, canadacentral, francecentral, germanywestcentral, norwayeast, switzerlandnorth, uaenorth, brazilsouth, centralusstage, eastusstage, eastus2stage, northcentralusstage, southcentralusstage, westusstage, westus2stage, asia, asiapacific, australia, brazil, canada, europe, france, germany, global, india, japan, korea, norway, southafrica, switzerland, uae, uk, unitedstates, eastasiastage, southeastasiastage, centraluseuap, eastus2euap, westcentralus, southafricawest, australiacentral, australiacentral2, australiasoutheast, japanwest, jioindiacentral, koreasouth, southindia, westindia, canadaeast, francesouth, germanynorth, norwaywest, switzerlandwest, ukwest, uaecentral, brazilsoutheast"
}


