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
  <xsl:template match="devices">
    <xsl:copy>
      <xsl:apply-templates select="@*|node()"/>
      <video><model type="vga" vram="16384" heads="1" primary="yes"/></video>
    </xsl:copy>
  </xsl:template>
</xsl:stylesheet>
