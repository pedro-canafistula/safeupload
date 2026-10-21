# SafeUpload lab debuggee image: Windows 10 22H2 Pro, build 19045.2965, with the virtual hardware of win10-debug3
# (q35, UEFI without Secure Boot or enrolled keys, no TPM, virtio disk, e1000e). Build with ../build-debuggee.sh,
# which renders the throwaway build key and checks every input hash first. Output: a generalized qcow2 with no
# account secrets, SSH keys or host keys; first boot takes them from the seed disk that Terraform attaches.

packer {
  required_version = ">= 1.11.0"
  required_plugins {
    qemu = {
      source  = "github.com/hashicorp/qemu"
      version = "~> 1.1"
    }
    ansible = {
      source  = "github.com/hashicorp/ansible"
      version = "~> 1.1"
    }
  }
}

variable "iso_path" {
  type        = string
  description = "Win10_22H2_EnglishInternational_x64v1.iso (Microsoft download, May 2023 media)."
}
variable "iso_sha256" {
  type    = string
  default = "edc53c5c5fe6926dea23fc3e884fbcf78cc2b9e76364be968f806fc6d42b59d2"
}
variable "config_dir" {
  type        = string
  description = "Prepared by build-debuggee.sh: viostor driver, build_key.pub."
}
variable "build_private_key" {
  type      = string
  sensitive = true
}
variable "output_dir" {
  type    = string
  default = "output/debuggee"
}
variable "image_name" {
  type    = string
  default = "Windows 10 Pro"
}
variable "product_key" {
  # Microsoft's public generic installation key for Windows 10 Pro: selects the edition, does not activate.
  type    = string
  default = "VK7JG-NPHTM-C97JM-9MPGT-3V66T"
}
variable "locale" {
  type    = string
  default = "en-GB"
}
variable "disk_size" {
  type    = string
  default = "65536M"
}
variable "ovmf_code" {
  type    = string
  default = "/usr/share/edk2/x64/OVMF_CODE.4m.fd"
}
variable "ovmf_vars" {
  type    = string
  default = "/usr/share/edk2/x64/OVMF_VARS.4m.fd"
}

locals {
  # Never stored in the image: the sanitize role removes autologon, sysprep keeps only the account, and first boot
  # sets the real password from the seed disk.
  build_password = "B${substr(replace(uuidv4(), "-", ""), 0, 20)}!a"
  admin_user     = "vika"
}

source "qemu" "debuggee" {
  iso_url      = var.iso_path
  iso_checksum = "sha256:${var.iso_sha256}"

  output_directory = var.output_dir
  vm_name          = "safeupload-debuggee-19045.2965.qcow2"
  format           = "qcow2"
  disk_size        = var.disk_size
  disk_interface   = "virtio"
  disk_discard     = "unmap"
  disk_compression = true
  net_device       = "e1000e"
  machine_type     = "q35"
  accelerator      = "kvm"
  cpus             = 4
  memory           = 4096
  cpu_model        = "host"

  efi_boot          = true
  efi_firmware_code = var.ovmf_code
  efi_firmware_vars = var.ovmf_vars

  cd_label = "SULABCFG"
  cd_files = ["${var.config_dir}/drivers", "${var.config_dir}/build_key.pub", "answer/enable-openssh.ps1"]
  cd_content = {
    "autounattend.xml" = templatefile("answer/autounattend.pkrtpl.xml", {
      ui_language    = var.locale
      input_locale   = var.locale
      system_locale  = var.locale
      user_locale    = var.locale
      time_zone      = "UTC"
      image_name     = var.image_name
      product_key    = var.product_key
      admin_user     = local.admin_user
      build_password = local.build_password
    })
  }

  # UEFI shows "Press any key to boot from CD or DVD" for a few seconds.
  boot_wait    = "3s"
  boot_command = ["<spacebar><wait1><spacebar><wait1><spacebar><wait1><spacebar>"]

  headless         = true
  vnc_bind_address = "127.0.0.1"

  communicator         = "ssh"
  ssh_username         = local.admin_user
  ssh_private_key_file = var.build_private_key
  ssh_timeout          = "2h"

  # The playbook stages C:\Windows\Temp\safeupload-finalize.ps1. Run over the last SSH session, it removes the build
  # key and the SSH host keys, then starts sysprep /generalize /oobe /shutdown; Packer waits for the power-off.
  shutdown_command = "powershell.exe -NoProfile -ExecutionPolicy Bypass -File C:\\Windows\\Temp\\safeupload-finalize.ps1"
  shutdown_timeout = "45m"
}

build {
  sources = ["source.qemu.debuggee"]

  provisioner "ansible" {
    playbook_file = "../ansible/image-debuggee.yml"
    user          = local.admin_user
    use_proxy     = false
    extra_arguments = [
      "-e", "ansible_connection=ssh",
      "-e", "ansible_shell_type=cmd",
      "-e", "ansible_ssh_private_key_file=${var.build_private_key}",
      "-e", "ansible_ssh_common_args='-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null'",
    ]
    ansible_env_vars = ["ANSIBLE_CONFIG=../ansible/ansible.cfg"]
  }

  post-processor "manifest" {
    output     = "${var.output_dir}/packer-manifest.json"
    strip_path = true
    custom_data = {
      windows_build = "19045.2965"
      iso_sha256    = var.iso_sha256
      edition       = var.image_name
      locale        = var.locale
    }
  }
}
