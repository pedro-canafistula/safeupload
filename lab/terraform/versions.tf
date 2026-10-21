terraform {
  required_version = ">= 1.9.0"
  required_providers {
    libvirt = {
      source  = "dmacvicar/libvirt"
      version = "~> 0.8.3"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.6"
    }
  }
}

provider "libvirt" {
  # Local system libvirt; use qemu+ssh://user@host/system to manage a remote host.
  uri = var.libvirt_uri
}
