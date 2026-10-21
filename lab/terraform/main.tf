# One lab debuggee VM from the generalized image. This module only creates and destroys the VM it names; the qualified
# win10-debug3 domain, its base disk and the run-disk.sh overlays are never referenced, imported or managed here.

resource "random_password" "admin" {
  length           = 24
  special          = true
  override_special = "!@#%^*-_=+"
}

locals {
  admin_password = coalesce(var.admin_password, random_password.admin.result)
  # PEM or DER public certificate files, base64 of their bytes; the seed script writes them out and runs Import-Certificate.
  trusted_certificates = [for f in var.trusted_certificate_files : filebase64(f)]
}

resource "libvirt_pool" "lab" {
  name = "safeupload-lab"
  type = "dir"
  target {
    path = var.pool_path
  }
}

resource "libvirt_volume" "base" {
  name   = "safeupload-debuggee-base.qcow2"
  pool   = libvirt_pool.lab.name
  source = var.image_path
  format = "qcow2"
}

resource "libvirt_volume" "disk" {
  name           = "${var.name}.qcow2"
  pool           = libvirt_pool.lab.name
  base_volume_id = libvirt_volume.base.id
  format         = "qcow2"
  size           = var.disk_gib * 1024 * 1024 * 1024
}

# The seed disk (volume label "cidata", file "user-data" as JSON) is read by C:\ProgramData\SafeUploadLab\lab-seed.ps1.
resource "libvirt_cloudinit_disk" "seed" {
  name = "${var.name}-seed.iso"
  pool = libvirt_pool.lab.name
  user_data = jsonencode({
    hostname             = var.hostname
    admin_user           = var.admin_user
    admin_password       = local.admin_password
    authorized_keys      = var.ssh_public_keys
    time_zone            = var.time_zone
    trusted_certificates = local.trusted_certificates
  })
  meta_data = jsonencode({ "instance-id" = var.name, "local-hostname" = var.hostname })
}

resource "libvirt_domain" "debuggee" {
  name    = var.name
  memory  = var.memory_mib
  vcpu    = var.vcpus
  machine = "q35"

  # UEFI without Secure Boot or enrolled keys, no TPM: the lab's firmware definition.
  firmware = var.ovmf_code
  nvram {
    file     = "/var/lib/libvirt/qemu/nvram/${var.name}_VARS.fd"
    template = var.ovmf_vars
  }

  cpu {
    mode = "host-passthrough"
  }

  disk {
    volume_id = libvirt_volume.disk.id
  }

  disk {
    volume_id = libvirt_cloudinit_disk.seed.id
  }

  network_interface {
    network_name   = var.network_name
    wait_for_lease = false
  }

  graphics {
    type        = "spice"
    listen_type = "address"
  }

  # The image has no NetKVM or display drivers: e1000e (inbox driver) and a standard VGA adapter, as on win10-debug3.
  xml {
    xslt = file("${path.module}/hardware.xsl")
  }
}
