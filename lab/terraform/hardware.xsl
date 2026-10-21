<?xml version="1.0"?>
<!-- Hardware tweaks the libvirt provider cannot express: e1000e NIC and a standard VGA adapter, because the lab image
     ships no NetKVM or display driver (win10-debug3 uses the same two devices). -->
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
  <xsl:output method="xml" indent="yes"/>

  <xsl:template match="@*|node()">
    <xsl:copy><xsl:apply-templates select="@*|node()"/></xsl:copy>
  </xsl:template>

  <xsl:template match="interface[@type='network']/model"/>
  <xsl:template match="interface[@type='network']">
    <xsl:copy>
      <xsl:apply-templates select="@*|node()"/>
      <model type="e1000e"/>
    </xsl:copy>
  </xsl:template>

  <xsl:template match="devices/video"/>
  <!-- The pinned provider attaches cloudinit media as IDE. Q35 uses SATA/AHCI for optical media. -->
  <xsl:template match="devices/controller[@type='ide']"/>
  <xsl:template match="devices/disk[@device='cdrom']/address"/>
  <xsl:template match="devices/disk[@device='cdrom']/target">
    <target dev="sda" bus="sata"/>
  </xsl:template>
  <xsl:template match="devices">
    <xsl:copy>
      <xsl:apply-templates select="@*|node()"/>
      <video><model type="vga" vram="16384" heads="1" primary="yes"/></video>
    </xsl:copy>
  </xsl:template>

  <!-- Windows client supports at most two sockets; expose all vCPUs as cores in one socket. -->
  <xsl:template match="cpu/topology"/>
  <xsl:template match="cpu">
    <xsl:copy>
      <xsl:apply-templates select="@*|node()"/>
      <topology sockets="1" cores="{../vcpu}" threads="1"/>
    </xsl:copy>
  </xsl:template>
</xsl:stylesheet>
