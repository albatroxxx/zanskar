variable "region" { default = "eu-west-2" }
variable "profile" { default = "Yukta" }
variable "owner" { default = "zanskar" }
variable "name" { default = "zanskar-test" }

# Only this CIDR may reach the gateway's HTTPS (and SSH for bootstrap).
variable "admin_cidr" { description = "Your public IP as a /32" }

variable "gateway_instance_type" { default = "t3.small" }
variable "linux_instance_type" { default = "t3.micro" }
variable "windows_instance_type" { default = "t3.medium" }
variable "asg_instance_type" { default = "t3.micro" }
variable "asg_size" { default = 2 }

# Hostname for TLS. Empty = <eip>.sslip.io (Let's Encrypt via Caddy).
variable "hostname" { default = "" }
