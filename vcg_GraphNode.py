"""A class hat represents the internal Graphnode used for dealing with .vcg's  

Some longer documentation will be put here in the future
"""
import string, vcg_parse
class vcgGraphNode:
  """A class that represents the internal Graphnode used for dealing with .vcg's
  
  Some longer documentation will be put here in the future
  
  """  
  def __init__(self, name_A, attributes_A = { 'color':'white' }):
    self.name = name_A
    self.attributes = {}
    self.visited = 0
    for k, v in attributes_A.items():
      self.attributes[ k ] = v
    
  def get_name( self ):
    return self.name
    
  def set_attribute( self, attrib_name, attrib_string ):
    self.attributes[ attrib_name ] = attrib_string
    
  def get_attribute( self, attrib_name ):
    return self.attributes[ attrib_name ]
    
  def add_attributes( self, attributes ):
    for k, v in attributes.items():
      self.attributes[ k ] = v
  
  def make_vcg_output( self ):
    output = 'node:\t{\n\ttitle: "' + self.name + '"\n\t'
    for k, v in self.attributes.items():
      output = output + k + ": " + v + "\n"
    output = output + '}\n'
    return output
    
  def parse_vcg_output( self, vcg_string ):
#    print "--->"+ vcg_string 
# first off, retrieve the label and remove it (only multi-line attribute there is
#    self.attributes[ "label" ] = vcg_parse.vcg_get_enclosed_attribute( vcg_string, "label" )
#    print self.attributes[ "label" ]
#    if self.attributes[ "label" ] == 0:
#     self.attributes[ "label" ] = '" "'
#      print "NO label found, weird !"
#    else:
#      vcg_string = string.replace( vcg_string, 'label: '+ self.attributes[ "label" ], "" )
    tokens = string.split( vcg_string )
    for k in tokens:
      if k[-1] == ':':
        # an attribute -- find the value
        i = 0;
        while i != len( tokens ):
          if (tokens[ i ] == k) and (tokens[ i ] != "title:" ) and (tokens[ i ] != "node:"):# and (tokens[ i ] != "label:"):
#            print "Setting attribute "+k+" to value "+ tokens[i + 1]+"\n"
            self.attributes[ k[0:-1] ] = tokens[ i + 1 ]
          i = 1+i

  def make_daVinci_output( self, graph ):
    davinci_string = 'l("node_'+self.name+'", n("", [ a("OBJECT","'+ self.attributes[ "label" ][1:-1] + '")], [ '
    # now add all the links
    linkset = graph.Get_Downlinks_From( self.name )
    if linkset != 0:
      for k in linkset:
        davinci_string += k.make_daVinci_output()
        davinci_string += ','
    davinci_string2 = davinci_string[:-1] + ']))\n'
    return davinci_string2
    
  def make_GML_output( self, graph ):
    gml_output = '\tnode\n\t[\n\t\tid "' + self.name + '"\n'
    gml_output += '\t\tlabel '+ self.attributes[ "label" ] + '\n'
    gml_output += '\t\tgraphics\n\t\t[\n\t\t\ttype "rectangle"\n\t\t\t'
    if self.attributes["color"] == "red":
        gml_output += 'fill "#FF2020"'
    else:
        gml_output += 'fill "#CCCCFF"'
    gml_output += '\n\t\t\toutline "#000000"\n\t\t]\n\t]\n'
    return gml_output