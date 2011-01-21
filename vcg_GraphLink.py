import string
class vcgGraphLink:
  """A class that represents the internal Graphlink used for dealing with .vcg's
  
  Some longer documentation will be put here in the future
  
  """      
  def __init__(self, source, target, attributes = { 'color':'black' }):
    self.sourcename = source
    self.targetname = target
    self.attributes = {}
    for k, v in attributes.items():
      self.attributes[ k ] = v
  
  def get_sourcename( self ):
    return self.sourcename
  
  def get_targetname( self ):
    return self.targetname
  
  def set_attribute( self, attrib_name, attrib_string ):
    self.attributes[ attrib_name ] = attrib_string
    
  def get_attribute( self, attrib_name ):
    return self.attributes[ attrib_name ]
    
  def add_attributes( self, attributes ):
    for k, v in attributes.items():
      self.attributes[ k ] = v
    
  def make_vcg_output( self ):
    output = 'edge: { sourcename: "' + self.sourcename + '" targetname: "' + self.targetname +'" \n\t'
    for k, v in self.attributes.items():
      output = output + k + ": " + v + "\n\t"
    output = output + '}\n'
    return output
    
  def parse_vcg_output( self, vcg_string ):
    print "Not implemented yet !"

  def make_daVinci_output( self ):
    Unique_ID = self.sourcename+"_"+self.targetname
    davinci_string = 'l("edge_' + Unique_ID + '", e("",[], r("node_'+ self.targetname +'")))'
    return davinci_string
    
  def make_GML_output( self ):
    GMLstring = '\tedge\n\t[\n\t\tsource "' + self.sourcename + '"\n'
    GMLstring += '\t\ttarget "' + self.targetname + '"\n'
    colorstring = '#000000'
    for k, v in self.attributes.items():
      if k == "label":
        GMLstring += '\t\tlabel '+ self.attributes[ "label" ] + '\n'
      if k == "color" and v == "red":
        colorstring = '#CC0000'
      if k == "color" and v == "green":
        colorstring = '#00CC00'
      if k == "color" and v == "blue":
        colorstring = '#0000CC'
    GMLstring += '\t\tgraphics\n\t\t[\n\t\t\tfill "'+ colorstring + '"\n\t\t\ttargetArrow "standard"\n\t\t]\n\t]\n'
    return GMLstring