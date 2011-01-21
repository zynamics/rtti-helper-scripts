import string
import vcg_Graph

def vcg_get_item( input_string, itemtype ):
  """
  Gets an item
  """
  index = string.find( input_string, itemtype+":" )
  if index == -1:
    return 0
  count = 1
  idx = index
  while input_string[ idx ] != "{":
    idx = idx + 1
    if idx > len( input_string ):
      return 0
  idx = idx + 1
  while count != 0:
    if input_string[ idx ] == "{":
      count = count + 1
    if input_string[ idx ] == "}":
      count = count - 1
    if idx > len( input_string ):
      idx = -1
      break
    idx = idx + 1
  if idx == -1:
    return 0
  return input_string[ index:idx ]

def get_enclosed( input_string, enclosechar ):
  """
  gets a string enclosed in enclosechar
  """
  index = 0
  while index <= len( input_string ):
    if input_string[ index ] == enclosechar[ 0 ]:
      break
    index = index + 1
  
  index2 = index + 1
  while index2 <= len( input_string ):
    if input_string[ index2 ] == enclosechar[ 0 ]:
      break
    index2 = index2 + 1
  
  return input_string[ index : index2+1 ]

def vcg_get_enclosed_attribute( input_string, attrib_name ):
#  print "Searching for " + attrib_name
#  print "Searching in " + input_string
  index = input_string.find(attrib_name + ":")
  if index == -1:
    return 0
  string = get_enclosed( input_string[index :], '"' )
  return string

def vcg_get_attribute( input_string, attrib_name ):
  index = input_string.find(attrib_name + ":")
  if index == -1:
    return 0
  string = input_string[ index + len(attrib_name) + 2 : ]
  string = string[ : string.find(" ")]
  return string

def vcg_node_attributes():
  attriblist = [ "color" ]
  return

def vcg_graph_attributes():
  fp = file( "graph_attributes.txt", "rt" )
  return fp.readlines()

def vcg_link_attributes():
  fp = file( "edge_attributes.txt", "rt" )
  return fp.readlines()
  
def vcg_node_attributes():
  fp = file( "node_attributes.txt", "rt" )
  return fp.readlines()

def vcg_string_to_graphs( input_string ):
  """
  Parses a VCG File to a list of graphs
  """
  graphlist = []
  graphstring = vcg_get_item( input_string, "graph" )   # get the first graph as a string
  
  while graphstring != 0:
    input_string.replace( graphstring, "" )     # remove the graph string from input
                                                # get the title of the graph
    newgraph = vcg_Graph.vcgGraph( vcg_get_enclosed_attribute( graphstring, "title" ))   
                                                # get the first node of the graph
    nodestring = vcg_get_item( graphstring, "node" )    
                                                # loop over nodes...
    while nodestring != 0:
      graphstring.replace( nodestring, "" )     # remove node string from input
                                                # get the name of the node
      newnode = newgraph.Add_Node( vcg_get_enclosed_attribute( nodestring, "title" ))
                                                # Iterate over all other attributes
      
      
      
    linkstring = vcg_get_item( graphstring, "link" )
    while linkstring != 0:
      graphstring.replace( linkstring, "" )
    graphlist.append( newgraph )
    graphstring = vcg_get_item( input_string, "graph" )
    