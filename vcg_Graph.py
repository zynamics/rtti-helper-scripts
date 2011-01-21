"""A generic file to manipulate graph description files (GDL)

(Put some longer documentation here in the future)
"""
import vcg_GraphNode
import vcg_GraphLink
import vcg_parse
import string


class vcgGraph:
	"""A class for manipulating .vcg Graph files (as used by Wingraph32 or AiSee)
	
	Some longer documentation will be put here in the future
	
	"""	
	def __init__(self, attributes = {"title":'"Graph"', "manhattan_edges":"no", "layoutalgorithm":"maxdepth"}):
		self.nodes = {}
		self.links = []
		self.attributes = {}
		for k, v in attributes.items():
			self.attributes[ k ] = v
	
	def add_attributes( self, attributes ):
		for k, v in self.attributes.items():
			self.attributes[ k ] = v

	def has_node( self, name ):
		if self.nodes.has_key( name ):
			return 1
		else:
			return 0

	def get_nodes( self ):
		return self.nodes
		
	def get_links( self ):
		return self.links

	def set_attribute( self, attrib_name, attrib_string ):
		self.attributes[ attrib_name ] = attrib_string
		
	def get_attribute( self, attrib_name ):
		return self.attributes[ attrib_name ]

	def gen_VCG_string(self):
		output = "graph: { \n\t"
		for k, v in self.attributes.items():
			output = output + k + ": " + v + "\n\t"
		for k, v in self.nodes.items():
			output = output + v.make_vcg_output()
		for k in self.links:
			output = output + k.make_vcg_output()
		output = output + "}\n"
		return output
		
	def write_VCG_File(self, filename):
		f = open( filename, 'w' )
		s = self.gen_VCG_string()
		f.write( s )
		f.close()
		
	def load_VCG_File(self, filename):
		file = open( filename, "r" )
		completestring = file.read()				# read the entire file
		# now start iterating through the file, first getting all nodes
		in_node = vcg_parse.vcg_get_item( completestring, "node" )
		while in_node != 0:
			nodetitle = vcg_parse.vcg_get_enclosed_attribute( in_node, "title" )
			print "Adding node with title: "+nodetitle[1:-1]
			newnode = self.Add_Node( nodetitle[1:-1] ) 
			newnode.parse_vcg_output( in_node )
			# cut the node away ... 
			chopstring = string.replace( completestring, in_node, "" )
			completestring = chopstring
			# get next one
			in_node = vcg_parse.vcg_get_item( completestring, "node" )
		in_link = vcg_parse.vcg_get_item( completestring, "edge" )		
		while in_link != 0:
			linksource = vcg_parse.vcg_get_enclosed_attribute( in_link, "sourcename" )
			linktarget = vcg_parse.vcg_get_enclosed_attribute( in_link, "targetname" )
			newlink = self.Add_Link( linksource[1:-1], linktarget[1:-1] )
			# cut the link away
			chopstring = string.replace( completestring, in_link, "" )
			srchidx = string.find( chopstring, in_link )
			completestring = chopstring
			# get next one
			in_link = vcg_parse.vcg_get_item( completestring, "edge" )
			
	def Add_Node(self, nodename):
		self.nodes[ nodename ] = vcg_GraphNode.vcgGraphNode( nodename )
		return self.nodes[ nodename ]
	
	def Add_Link(self, sourcename, targetname):
		link = vcg_GraphLink.vcgGraphLink( sourcename, targetname )
		self.links.append( link )
		return link
		
	def Del_Node(self, nodename):
		# Create a temporary copy of the list
		removelinks = []
		for x in self.links:												# remove the links to/from 
			if x.targetname == nodename:
				removelinks.append( x )
			if x.sourcename == nodename:							# this node
				removelinks.append( x )
		for x in removelinks:
			if x in self.links:
				self.links.remove( x )
		del self.nodes[nodename]
		return
			
	def Get_Links( self, sourcename, targetname ):
		linkset = []
		for x in self.links:												# remove the relevant link
			if x.sourcename == sourcename and x.targetname == targetname:
				linkset.append( x )
		return linkset
		
	def Del_Link2(self, sourcename, targetname):
		for x in self.links:												# remove the relevant link
			if x.sourcename == sourcename and x.targetname == targetname:
				self.links.remove( x )
	
	def Del_Link( self, link ):
		self.links.remove( link )
	
	def Get_Downlinks_To( self, nodename ):
		linkslist = []
		for x in self.links:
			if x.targetname == nodename:
				linkslist.append( x )
		return linkslist
		
	def Get_Downlinks_From( self, nodename ):
		linkslist = []
		for x in self.links:
			if x.sourcename == nodename:
				linkslist.append( x )
		return linkslist

	def Get_Parents( self, nodename ):
		parentnames = []
		linkslist = self.Get_Downlinks_To( nodename )
		for x in linkslist:
			parentnames.append( x.sourcename )
		return parentnames
		
	def Get_Children( self, nodename ):
		childnames = []
		linkslist = self.Get_Downlinks_From( nodename )
		for x in linkslist:
			childnames.append( x.targetname )
		return childnames
		
	def Get_Node( self, nodename ):
		is_valid_name = 0
		for x in self.nodes.keys():
			if x == nodename:
				is_valid_name = 1
		if is_valid_name:
			return self.nodes[ nodename ]
		return 0

	def Get_Top_Nodes( self ):
		topnodes = []
		for x in self.nodes.keys():
			bLinkedTo = 0
			for y in self.links:
				if( x == y.targetname ):
					bLinkedTo = 1
					break
			if( bLinkedTo == 0 ):
				topnodes.append( x )
		return topnodes
		
	def Get_Bottom_Nodes( self ):
		bottom_nodes = []
		for x in self.nodes.keys():
			bLinkedFrom = 0
			for y in self.links:
				if( x == y.sourcename ):
					bLinkedFrom = 1
					break
			if( bLinkedFrom == 0 ):
				bottom_nodes.append( x )
		return bottom_nodes
	
	def Get_Nodes_Before( self, node ):
		for x in self.nodes.keys():
			self.nodes[ x ].visited = 0
		beforeset = []
		workset = []
		workset.append( node )
		print "Len(workset) is %d" % len( workset )
		while len( workset ) != 0:
			print beforeset
			nextnode = workset[ 0 ]
			workset = workset[1:]
			parentset = self.Get_Parents( nextnode )
			for x in parentset:
				if self.nodes[ x ].visited == 0:
					self.nodes[ x ].visited = 1
					beforeset.append( x )
					workset.append( x )
		print beforeset
		return beforeset

	def get_subgraph_to( self, node ):
		tmpgrph = vcgGraph()
		tmpgrph.Add_Node( node )
		worklist = [ node ]
		while len( worklist ) > 0:
			currnode = worklist.pop( 0 )
			children = self.Get_Parents( currnode )
			for parent in parents:
				tmpgrph.Add_Link( parent, currnode )
				if not tmpgrph.has_node( parent ):
					tmpgrph.Add_Node( parent )
					worklist.append( parent )
		return tmpgrph

	def get_subgraph_from( self, node ):
		tmpgrph = vcgGraph()
		tmpgrph.Add_Node( node )
		worklist = [ node ]
		while len( worklist ) > 0:
			currnode = worklist.pop( 0 )
			children = self.Get_Children( currnode )
			for child in children:
				tmpgrph.Add_Link( currnode, child )
				if not tmpgrph.has_node( child ):
					worklist.append( child )
					tmpgrph.Add_Node( child )
				
				
		return tmpgrph					

	def Get_Nodes_After( self, node ):
		for x in self.nodes.keys():
			self.nodes[ x ].visited = 0
		beforeset = []
		workset = []
		workset.append( node )
		#		print "Len(workset) is %d" % len( workset )
		while len( workset ) != 0:
			#			print "Beforeset: "
			#			print beforeset
			nextnode = workset[ 0 ]
			workset = workset[1:]
			#			print "Getting children of %s" % nextnode
			parentset = self.Get_Children( nextnode )
			#			print "Childrenset is:"
			#			print parentset
			for x in parentset:
				if self.nodes[ x ].visited == 0:
					self.nodes[ x ].visited = 1
					beforeset.append( x )
					workset.append( x )
		#		print beforeset
		return beforeset
		
	def Get_Path_From_To( self, nodeBegin, nodeEnd ):
		preset = self.Get_Nodes_Before( nodeEnd )
		postset = self.Get_Nodes_After( nodeBegin )
		#		print "Preset is: " 
		#		print preset
		#		print "Postset is: " 
		#		print postset
		intersect = []
		for x in preset:
			for y in postset:
				if x == y:
					intersect.append( x )
		return intersect
		
	def make_daVinci_output( self ):
		davinci_output = '['
		for key, node in self.nodes.items():
			davinci_output += node.make_daVinci_output( self ) 
			davinci_output += ','
		return davinci_output[:-1] + ']'

	def make_GML_output( self ):
		output = 'Creator: "vcgGraph.py"\nVersion 2.2\ngraph\n['
		output += "\thierarchic 1\n"
		# output += "\tlabel "+self.attributes[ "label" ]+"\n"
		for key, node in self.nodes.items():
			output += node.make_GML_output( self )
		for link in self.links:
			output += link.make_GML_output()
		output += "]\n"
		return output