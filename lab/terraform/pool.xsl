<?xml version="1.0"?>
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
  <xsl:output method="xml" omit-xml-declaration="yes"/>
  <xsl:template match="@*|node()">
    <xsl:copy><xsl:apply-templates select="@*|node()"/></xsl:copy>
  </xsl:template>
  <xsl:template match="/pool/target">
    <xsl:copy>
      <xsl:apply-templates select="@*|node()[not(self::permissions)]"/>
      <permissions><mode>0700</mode><owner>${uid}</owner><group>${gid}</group></permissions>
    </xsl:copy>
  </xsl:template>
</xsl:stylesheet>
