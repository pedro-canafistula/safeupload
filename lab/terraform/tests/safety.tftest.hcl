# Offline module controls: no libvirt connection or resources are created.
mock_provider "libvirt" {}
mock_provider "random" {}
mock_provider "external" {
  mock_data "external" {
    defaults = { result = { uid = "1000", gid = "1000" } }
  }
}

variables {
  image_path      = "terraform.tfvars.example"
  image_sha256    = filesha256("terraform.tfvars.example")
  ssh_public_keys = ["ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITestFixture colleague@test"]
}

run "candidate_wiring" {
  # Resolve the mock resource ids to exercise their wiring. All providers above are mocked.
  command = apply
  assert {
    condition     = libvirt_pool.lab.name == var.name && libvirt_pool.lab.target[0].path == "${var.pool_path}/${var.name}"
    error_message = "Each candidate must own its own pool directory."
  }
  assert {
    condition     = length(libvirt_domain.debuggee.disk) == 1 && libvirt_domain.debuggee.cloudinit == libvirt_cloudinit_disk.seed.id
    error_message = "The seed must use the provider's CD-ROM attachment, not a virtio data disk/composite volume id."
  }
}

run "refuse_qualified_identity" {
  command = plan
  variables { name = "win10-debug3" }
  expect_failures = [var.name]
}

run "refuse_qualified_hostname" {
  command = plan
  variables { hostname = "WIN10-DEBUGGED" }
  expect_failures = [var.hostname]
}

run "refuse_missing_keys" {
  command = plan
  variables { ssh_public_keys = [] }
  expect_failures = [var.ssh_public_keys]
}

run "refuse_unimplemented_account" {
  command = plan
  variables { admin_user = "colleague" }
  expect_failures = [var.admin_user]
}

run "refuse_wrong_image_hash" {
  command = plan
  variables { image_sha256 = "0000000000000000000000000000000000000000000000000000000000000000" }
  expect_failures = [libvirt_volume.base]
}

run "refuse_short_password" {
  command = plan
  variables { admin_password = "short" }
  expect_failures = [var.admin_password]
}
