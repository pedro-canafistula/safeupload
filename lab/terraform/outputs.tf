output "domain" {
  value = libvirt_domain.debuggee.name
}

output "admin_user" {
  value = var.admin_user
}

output "admin_password" {
  value     = local.admin_password
  sensitive = true
}

output "connect" {
  value       = "virsh -c ${var.libvirt_uri} domifaddr ${libvirt_domain.debuggee.name}   # then: ssh ${var.admin_user}@<address>"
  description = "The VM takes a DHCP address from the libvirt network; SSH works once first boot has applied your key and restarted (several minutes)."
}
