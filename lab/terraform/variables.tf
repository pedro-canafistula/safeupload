variable "libvirt_uri" {
  type    = string
  default = "qemu:///system"
}

variable "name" {
  type        = string
  default     = "su-lab-debuggee"
  description = "libvirt domain name. Never reuse the name of a qualified lab VM (win10-debug3)."
}

variable "hostname" {
  type        = string
  default     = "SU-LAB-DEBUG"
  description = "Windows computer name applied at first boot. The qualified harness identity (WIN10-DEBUGGED) is deliberately not the default."
}

variable "image_path" {
  type        = string
  description = "Generalized qcow2 from lab/build-debuggee.sh (safeupload-debuggee-19045.2965.qcow2)."
}

variable "pool_path" {
  type        = string
  default     = "/var/lib/libvirt/images/safeupload-lab"
  description = "Directory of the storage pool that holds the base image and the VM's overlay disk."
}

variable "memory_mib" {
  type    = number
  default = 4096
}

variable "vcpus" {
  type    = number
  default = 4
}

variable "disk_gib" {
  type    = number
  default = 64
}

variable "network_name" {
  type    = string
  default = "default"
}

variable "ssh_public_keys" {
  type        = list(string)
  description = "Public keys allowed to sign in over SSH as the admin user (for example the contents of ~/.ssh/id_ed25519.pub)."
}

variable "admin_user" {
  type    = string
  default = "vika"
}

variable "admin_password" {
  type        = string
  default     = null
  sensitive   = true
  description = "Admin password set at first boot. Null generates a random one (terraform output -raw admin_password)."
}

variable "time_zone" {
  type        = string
  default     = "UTC"
  description = "Windows time zone id. The domain clock is UTC, so leave UTC unless you also change the RTC handling."
}

variable "trusted_certificate_files" {
  type        = list(string)
  default     = []
  description = "Public .cer/.crt files (DER or PEM) for your own test-signing certificate. They are imported into LocalMachine Root and TrustedPublisher at first boot. Never pass a private key."
}

variable "ovmf_code" {
  type    = string
  default = "/usr/share/edk2/x64/OVMF_CODE.4m.fd"
}

variable "ovmf_vars" {
  type    = string
  default = "/usr/share/edk2/x64/OVMF_VARS.4m.fd"
}
