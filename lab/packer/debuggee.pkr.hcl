# SafeUpload lab debuggee image: Windows 10 22H2 Pro, build 19045.2965, with the virtual hardware of win10-debug3
# (q35, UEFI without Secure Boot or enrolled keys, no TPM, virtio disk, e1000e). Build with ../build-debuggee.sh,
# which renders the throwaway build key and checks every input hash first. Output: a generalized qcow2 with no
# account secrets, SSH keys or host keys; first boot takes them from the seed disk that Terraform attaches.

packer {
  required_version = ">= 1.11.0"
  required_plugins {
    qemu = {
      source  = "github.com/hashicorp/qemu"
      version = "= 1.1.7"
    }
    ansible = {
      source  = "github.com/hashicorp/ansible"
      version = "= 1.1.6"
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
variable "build_password" {
  type      = string
  sensitive = true
}
variable "build_uuid" {
  type = string
}
variable "winrm_host_port" {
  type = number
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
  admin_user = "vika"
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
  # Windows client supports only two sockets; QEMU's default can hide half the CPUs.
  qemuargs = [
    ["-smp", "4,sockets=1,cores=4,threads=1"],
    ["-uuid", var.build_uuid],
    ["-netdev", "user,id=user.0,hostfwd=tcp:127.0.0.1:{{ .SSHHostPort }}-:22,hostfwd=tcp:127.0.0.1:${var.winrm_host_port}-:5986"],
  ]

  efi_boot          = true
  efi_firmware_code = var.ovmf_code
  efi_firmware_vars = var.ovmf_vars

  cd_label = "SULABCFG"
  cd_files = ["${var.config_dir}/drivers", "${var.config_dir}/build_key.pub", "answer/enable-openssh.ps1", "answer/enable-winrm.ps1"]
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
      build_password = var.build_password
    })
  }

  # OVMF/CD startup latency varies with host load. Cover the prompt instead of assuming it appears in 3 seconds.
  boot_wait    = "1s"
  boot_command = [for i in range(30) : "<spacebar><wait1>"]

  headless         = true
  vnc_bind_address = "127.0.0.1"

  communicator             = "ssh"
  ssh_username             = local.admin_user
  ssh_private_key_file     = var.build_private_key
  ssh_timeout              = "2h"
  ssh_file_transfer_method = "sftp"

  # The playbook stages C:\Windows\Temp\safeupload-finalize.ps1. Run over the last SSH session, it removes the build
  # key and the SSH host keys, then starts sysprep /generalize /oobe /shutdown; Packer waits for the power-off.
  shutdown_command = "powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File C:\\Windows\\Temp\\safeupload-finalize.ps1"
  shutdown_timeout = "45m"
}

build {
  sources = ["source.qemu.debuggee"]

  provisioner "file" {
    direction   = "download"
    source      = "C:/ProgramData/SafeUploadLabBootstrap/winrm.pem"
    destination = "${var.config_dir}/winrm.pem"
  }

  provisioner "ansible" {
    playbook_file = "../ansible/image-debuggee.yml"
    user          = local.admin_user
    use_proxy     = false
    # Credentials stay in a private file, never in process arguments. HTTPS certificate validation is enabled.
    extra_arguments  = ["-e", "@${var.config_dir}/ansible-vars.json"]
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
