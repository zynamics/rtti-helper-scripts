import vcg_Graph, vcg_GraphLink, vcg_GraphNode, string, copy, sets
from idaapi import *
import idc

"""
	This file consists of a collection of utility functions that were written during various
	reverse engineering projects to facilitate the process
"""

#
#   A list of mnemonics that do not overwrite the first operand:
#

neutral_mnem = [ "cmp", "test", "push" ]
assign_mnem = [ "mov", "movzx", "movsx" ]
x86_registers = [ "eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp"]

#
#   Utility function
#

def idaline_to_string( idaline ):
	"""
		Takes an IDA Pro disassembly line and removes all the formatting info
		from it to make it a "regular" string.
	"""
	i = 0
	new = ""
	while i < len(idaline):
		if idaline[i] == '\x01' or idaline[i] == '\x02':
			i = i + 1
		else:
			new += idaline[i]
		i = i + 1
	return new

#
#   A function to get the name of the basic bloc a particular ea is in
#
def get_basic_block_begin( ea ):
	return get_basic_block_begin_from_ea( ea )

def get_basic_block_begin_from_ea( ea ):
	"""" Get basic block upper bound
	
	While the current instruction is not referenced from anywhere and the preceding instruction is not
	referencing anywhere else, step backwards. Return the first address at which the above conditions
	are no longer true.
	"""
	oldea = 0
	while get_first_fcref_to( ea ) == BADADDR and get_first_fcref_from( get_first_cref_to( ea ) ) == BADADDR and ea != BADADDR:
		oldea = ea
		ea = get_first_cref_to( ea )
	if ea == BADADDR:
		return oldea
	return ea


def get_basic_block_end( ea ):
	return get_basic_block_end_from_ea( ea )

#
#   A function to get the name of the basic bloc a particular ea is in
#

def get_basic_block_end_from_ea( ea ):
	""" Get basic block lower bound
	
	The same as get_basic_block_begin_from_ea(), just forwards.
	"""   
	lastea = ea
	while get_first_fcref_from( ea ) == BADADDR and ea != BADADDR and \
		get_first_fcref_to( get_first_cref_from(ea) ) == BADADDR:
		lastea = ea
		ea = get_first_cref_from( ea )
	if ea == BADADDR:
		return lastea
	return ea

#
#
#

VCG_COLOR_WHITE = 0
VCG_COLOR_BLUE = 1
VCG_COLOR_RED = 2
VCG_COLOR_GREEN = 3
VCG_COLOR_YELLOW = 4
VCG_COLOR_MAGENTA = 5
VCG_COLOR_CYAN = 6
VCG_COLOR_DARKGREY = 7
VCG_COLOR_DARKBLUE = 8
VCG_COLOR_DARKRED = 9
VCG_COLOR_DARKGREEN = 10
VCG_COLOR_DARKYELLOW = 11
VCG_COLOR_DARKMAGENTA = 12
VCG_COLOR_DARKCYAN = 13
VCG_COLOR_GOLD = 14
VCG_COLOR_LIGHTGREY = 15
VCG_COLOR_LIGHTBLUE = 16
VCG_COLOR_LIGHTRED = 17
VCG_COLOR_LIGHTGREEN = 18
VCG_COLOR_LIGHTYELLOW = 19
VCG_COLOR_LIGHTMAGENTA = 20
VCG_COLOR_LIGHTCYAN = 21
VCG_COLOR_LILAC = 22
VCG_COLOR_TURQUOISE = 23
VCG_COLOR_AQUAMARINE = 24
VCG_COLOR_KHAKI = 25
VCG_COLOR_PURPLE = 26
VCG_COLOR_YELLOWGREEN = 27
VCG_COLOR_PINK = 28
VCG_COLOR_ORANGE = 29
VCG_COLOR_ORCHID = 30
VCG_COLOR_BLACK = 31

colormap = [
	VCG_COLOR_WHITE,		#	IGNORE ! Just there to make array addressing nicer !
	VCG_COLOR_BLACK,		#	Default
	VCG_COLOR_RED,			# Regular comment
	VCG_COLOR_LIGHTBLUE,	# Repeatable comment (comment defined somewhere else)
	VCG_COLOR_LIGHTBLUE, 	# Automatic comment
	VCG_COLOR_DARKBLUE,	# Instruction
	VCG_COLOR_DARKGREEN,	# Dummy Data Name
	VCG_COLOR_DARKGREEN,	# Regular Data Name
	VCG_COLOR_MAGENTA,		# Demangled Name
	VCG_COLOR_BLUE,		# Punctuation
	VCG_COLOR_DARKCYAN,	# Char constant in instruction
	VCG_COLOR_DARKCYAN,	# String constant in instruction
	VCG_COLOR_DARKCYAN,	# Numeric constant in instruction
	VCG_COLOR_RED,			# Void operand
	VCG_COLOR_DARKGREY,	# Code reference
	VCG_COLOR_DARKGREY,	# Data reference
	VCG_COLOR_RED,			# Code reference to tail byte
	VCG_COLOR_RED,			# Data reference to tail byte
	VCG_COLOR_RED,			# Error or problem
	VCG_COLOR_DARKGREY,	# Line prefix
	VCG_COLOR_DARKGREY,	# Binary line prefix bytes
	VCG_COLOR_DARKGREY,	# Extra line
	VCG_COLOR_PINK,		# Alternative operand
	VCG_COLOR_PINK,		# Hidden name
	VCG_COLOR_MAGENTA,		# Library function name
	VCG_COLOR_GREEN,		# Local variable name
	VCG_COLOR_DARKGREY,	# Dummy code name
	VCG_COLOR_DARKBLUE,	# Assembler directive
	VCG_COLOR_DARKGREY,	# Macro
	VCG_COLOR_DARKCYAN,	# String constant in data directive
	VCG_COLOR_DARKCYAN,	# Char constant in data directive
	VCG_COLOR_DARKCYAN,	# Numeric constant in data directive
	VCG_COLOR_DARKBLUE,	# Keywords
	VCG_COLOR_LIGHTBLUE,	# Register name
	VCG_COLOR_MAGENTA,		# Imported name
	VCG_COLOR_DARKGREY,	# Segment name
	VCG_COLOR_DARKGREY,	# Dummy unknown name
	VCG_COLOR_DARKGREY,	# Regular code name
	VCG_COLOR_DARKGREY,	# Regular unknown name
	VCG_COLOR_DARKGREY,	# Collapsed line
	VCG_COLOR_LIGHTGREY	# hidden address marks
]

def basic_block_to_pretty_vcg( blk ):
	print "y1"
	allblk = "\x0C22%lx:\r\n\x0Cb" % blk[0][0]
	print "y2"
	for line in blk:
		print line
		colorstack = []
		idaline = generate_disasm_line( line[0] )
		newline = ""
		ignorenext = 0
		for i in range( len(idaline)-1):
			if ignorenext:
				ignorenext = ignorenext - 1
				continue
			if idaline[i] == COLOR_ON and ord(idaline[i+1]) < len( colormap ) and ord(idaline[i+1]) < 28:
				colorstack.append( idaline[i+1] )
				newline = newline + "\x0C%.02d" % colormap[ ord(idaline[i+1]) ]
				ignorenext = 1
			elif idaline[i] == COLOR_OFF:
				if len( colorstack ) == 0:
					newline = newline + "\x0C%.02d" %  VCG_COLOR_BLACK
				else:
					newline = newline + "\x0C%.02d" % colormap[ ord( colorstack.pop())]
				ignorenext = 1
			elif idaline[i] == '\x01':
				ignorenext = 1
				continue
			else:
				if idaline[i] != '"' and idaline[i] != '\\':
					newline = newline + idaline[i]
				elif idaline[i] == '"':
					newline = newline + "\x0C%.03d" % ord(idaline[i])
				elif idaline[i] == '\\':
					newline = newline + "\\\\"
		newline = newline + "\x0C%.02d\r\n" % VCG_COLOR_BLACK
		allblk = allblk + newline
	return allblk

#
#   Retrieves a list of xrefs from a particular location
#

def get_drefs_to( ea ):
	"""
		Retrieves a list of locations that are referring ea (data only)
	"""
	ret = []
	xrf = get_first_dref_to( ea )
	if xrf != BADADDR:
		ret.append( xrf )
	xrf = get_next_dref_to( ea, xrf )
	while xrf != BADADDR:
		ret.append( xrf )
		xrf = get_next_dref_to( ea, xrf )
	return ret

def get_drefs_from( ea ):
	"""
		Retrieves a list of locations that are referred to from ea (data only)
	"""
	ret = []
	xrf = get_first_dref_from( ea )
	if xrf != BADADDR:
		ret.append( xrf )
	xrf = get_next_dref_from( ea, xrf )
	while xrf != BADADDR:
		ret.append( xrf )
		xrf = get_next_dref_from( ea, xrf )
	return ret


def get_short_crefs_from( ea ):
	"""
		Retrieves a list of locations that 
	"""
	ret = []
	xrf = get_first_cref_from( ea )
	xrf2 = get_first_fcref_from( ea )
	if xrf != BADADDR and xrf != xrf2:
		ret.append( xrf )
	xrf = get_next_cref_from( ea, xrf )
	while xrf != BADADDR and xrf != xrf2:
		ret.append( xrf )
		xrf = get_next_cref_from( ea, xrf )
	return ret

def get_noncall_crefs_to( ea ):
	"""
		Retrieve a list of locations that branch to ea
	"""
	ret = []
	xrf = get_first_cref_to( ea )
	if xrf != BADADDR:
		if ua_mnem( xrf ) != "call":
			ret.append( xrf )
	else:
		if ea not in get_far_crefs_from( xrf ):
			ret.append( xrf )
	xrf = get_next_cref_to( ea, xrf )
	while xrf != BADADDR:
		if ua_mnem( xrf ) != "call":
			ret.append( xrf )
		xrf = get_next_cref_to( ea, xrf )
	return ret        

def get_short_crefs_to( ea ):
	"""
		Retrieve a list of locations that refer to ea using a non-call
	"""
	ret = []
	xrf = get_first_cref_to( ea )
	xrf2 = get_first_fcref_to( ea )
	if xrf != BADADDR and xrf != xrf2:
		ret.append( xrf )
	xrf = get_next_cref_to( ea, xrf )
	while xrf != BADADDR and xrf != xrf2:
		ret.append( xrf )
		xrf = get_next_cref_to( ea, xrf )
	return ret

def get_crefs_from( ea ):
	"""
		Retrieve a list of locations that ea branches to
	"""
	ret = []
	xrf = get_first_cref_from( ea )
	if xrf != BADADDR:
		ret.append( xrf )
	xrf = get_next_cref_from( ea, xrf )
	while xrf != BADADDR:
		ret.append( xrf )
		xrf = get_next_cref_from( ea, xrf )
	return ret
	
def get_crefs_to( ea ):
	"""
		Retrieve a list of locations that branch to ea
	"""
	ret = []
	xrf = get_first_cref_to( ea )
	if xrf != BADADDR:
		ret.append( xrf )
	xrf = get_next_cref_to( ea, xrf )
	while xrf != BADADDR:
		ret.append( xrf )
		xrf = get_next_cref_to( ea, xrf )
	return ret        

def get_far_crefs_from( ea ):
	"""
		Retrieve list of locations that ea branches to 
	"""
	ret = []
	xrf = get_first_fcref_from( ea )
	if xrf != BADADDR:
		ret.append( xrf )
	xrf = get_next_fcref_from( ea, xrf )
	while xrf != BADADDR:
		ret.append( xrf )
		xrf = get_next_fcref_from( ea, xrf )
	return ret
	
def get_far_crefs_to( ea ):
	ret = []
	xrf = get_first_fcref_to( ea )
	if xrf != BADADDR:
		ret.append( xrf )
	xrf = get_next_fcref_to( ea, xrf )
	while xrf != BADADDR:
		ret.append( xrf )
		xrf = get_next_fcref_to( ea, xrf )
	return ret        


#
#   Retrieves a line of disassembled code
#

def get_disasm_line( ea ):
	""" Returns a list [ int address, string mnem, string op1, string op2, string op3 ]
	
	"""
	op1 = ua_outop2( ea, 0, 0 )	
	op2 = ua_outop2( ea, 1, 0 )
	op3 = ua_outop2( ea, 2, 0 )
	if op1 == None:
		op1 = ""
	else:
		op1 = idaline_to_string( op1 )
	if op2 == None:
		op2 = ""
	else:
		op2 = idaline_to_string( op2 )
	if op3 == None:
		op3 = ""
	else:
		op3 = idaline_to_string( op3 )
	ret = [ ea, ua_mnem( ea ), op1, op2, op3 ]
	return ret

#
#  Retrieves a string from the IDB
#

def get_string( ea ):
	str = ""
	while get_byte( ea ) != 0:
		str = str + "%c" % get_byte( ea )
		ea = ea+1
	return str


#
#   Returns a string for a disasm line
#

def disasm_line_to_string( baseblock ):
	str = "%lx:   %s " % (baseblock[0], baseblock[1])
	if baseblock[2] != "":
		str = str + baseblock[2]
	if baseblock[3] != "":
		str = str + ", %s" % baseblock[3]
	if baseblock[4] != "":
		str = str + ", %s" % baseblock[4]
	return str


#
#   Returns all the instructions in a basic block
#

def get_basic_block( ea ):
	"""
		A basic block will be a list of lists that contain all the instructions
		in this particular basic block.
		[ 
			[ firstaddress, mnem, op1, op2, op3 ]
			...
			[ lastaddress, mnem, op1, op2, op3 ]
		]
	"""
	begin = get_basic_block_begin_from_ea( ea )
	realbegin = begin
	end = get_basic_block_end_from_ea( ea )
	ret = []
	while begin <= end and begin >= realbegin:
		ret.append( get_disasm_line( begin ) )
		if get_first_cref_from( begin ) <= begin:
			break
		begin = get_first_cref_from( begin )
	return ret

def get_basic_block_from( ea ):
	x = get_basic_block( ea )
	blk = []
	for line in x:
		if line[0] >= ea:
			blk.append( line )
	return blk
	"""begin = ea
	end = get_basic_block_end_from_ea( ea )
	ret = []
	#print "%lx: (end)" % end
	while begin <= end and begin != BADADDR:
		ret.append( get_disasm_line( begin ) )
		begin = get_first_cref_from( begin )
		if get_first_fcref_to( begin ) != BADADDR:
			break
		if begin == get_first_fcref_from( begin ):
			break
	return ret"""

def get_basic_block_to( ea ):
	x = get_basic_block( ea )
	blk = []
	for line in x:
		if line[0] <= ea:
			blk.append( line )
	return blk
	"""
	end = ea
	begin = get_basic_block_begin_from_ea( ea )
	ret = []
	while begin <= end and begin != BADADDR:
		ret.append( get_disasm_line( begin ) )
		begin = get_first_cref_from( begin )
		if get_first_fcref_to( begin ) != BADADDR:
			break
		if begin == get_first_fcref_from( begin ):
			break
	return ret"""



def might_be_immediate( str ):
	if str == "":
		return 0
	if str == None:
		return 0
	try:
		if str[-1] == 'h':
			string.atol( str[:-1], 16 )
		else:
			string.atol( str, 10 )
		return 1
	except ValueError:
		return 0

def print_basic_block( baseblock ):
	#print baseblock
	for line in baseblock:
		print disasm_line_to_string( line )

def basic_block_to_string( baseblock ):
	r = ""
	for line in baseblock:
		r = r + disasm_line_to_string(line) + "\n"
	return r

def slice_basic_block_for_reg( baseblock, reg ):
	retblk = []
	for line in baseblock:
		if reg == "eax" and line[1] == "call":
			retblk.append( line )            
		elif line[2].find( reg ) != -1 or line[3].find( reg ) != -1 or \
			line[4].find( reg ) != -1:
			retblk.append( line )
	return retblk 

class slice_node:
	def __init__( self, startea, endea, reg ):
		self.startea = startea
		self.endea = endea
		self.reg = reg
		#print "find_end!"
		if( startea == 0 ):
			self.find_begin()
		if( endea == 0 ):
			self.find_end()
	def to_name( self ):
		return "%lx-%lx-%s" % ( self.startea, self.endea, self.reg )
	def find_end( self ):
		bb = get_basic_block_from( self.startea )
		self.endea = bb[-1][0]
		bb2 = slice_basic_block_for_reg( bb, self.reg )
		bb3 = []
		for line in bb2:
			bb3.append( line )
			if self.reg == "eax" and line[1] == "call":
				self.endea = line[0]
				break
			if line[1] not in neutral_mnem and (line[2] == self.reg or line[3] == self.reg):
				self.endea = line[0]
				break
		self.lines = bb3
		return self.endea
	def find_begin( self ):
		bb = get_basic_block_to( self.endea )
		self.startea = bb[0][0]
		bb2 = slice_basic_block_for_reg( bb, self.reg )
		bb3 = []
		for i in range( len(bb2)-1, -1, -1):
			line = bb2[i]
			bb3.insert( 0, line )
			if self.reg == "eax" and line[1] == "call":
				self.startea = line[0]
				break
			if line[1] not in neutral_mnem and (line[2] == self.reg or line[3] == self.reg):
				self.startea = line[0]
				break
		self.lines = bb3
		return self.startea
	def get_target_reg_bwd( self ):
		"""		if len( self.lines ) > 0:
			if self.reg == "eax" and self.lines[0][1] == "call":
				# call is overwriting eax
				return ["END",0]
			if self.lines[0][1] == "xor" and self.lines[0][2] == self.reg and self.lines[0][3] == self.reg:
				return ["END",0]
			if self.lines[0][1] == "or" and self.lines[0][3] == "0FFFFFFFFh":
				return ["END", 0]
			if self.lines[0][1] == "or" and self.lines[0][3] == "-1":
				return ["END", 0]
			if self.lines[0][1] == "and" and self.lines[0][2] == self.reg and self.lines[0][3] == "0":
				return ["END",0]
			if self.lines[0][2] == self.reg and self.lines[0][1] not in neutral_mnem:
				if self.lines[0][3] in x86_registers and self.lines[0][1] == "mov":
					return [self.lines[0][3], 0 ]
			if self.lines[0][3] in x86_registers and self.lines[0][1] != "mov":
				return [ self.lines[0][3], 1]
			if might_be_immediate( self.lines[0][3]) and self.lines[0][1] != "mov":
				return [ self.lines[0][2], 0]
			else:
				return ["END",0]
		return ["",0]
		"""
		if len( self.lines ) > 0:
		    if self.reg == "eax" and self.lines[0][1] == "call":
			# call is overwriting eax
			return ["END",0]
		    if self.lines[0][1] == "xor" and self.lines[0][2] == self.reg and self.lines[0][3] == self.reg:
			return ["END",0]
		    if self.lines[0][1] == "or" and self.lines[0][3] == "0FFFFFFFFh":
			return ["END", 0]
		    if self.lines[0][1] == "or" and self.lines[0][3] == "-1":
			return ["END", 0]
		    if self.lines[0][1] == "and" and self.lines[0][2] == self.reg and self.lines[0][3] == "0":
			return ["END",0]
		    if self.lines[0][2] == self.reg and self.lines[0][1] not in neutral_mnem:
			if self.lines[0][3] in x86_registers and self.lines[0][1] == "mov":
			   return [self.lines[0][3], 0 ]
			if self.lines[0][3] in x86_registers and self.lines[0][1] != "mov":
			   return [ self.lines[0][3], 1]
			if might_be_immediate( self.lines[0][3]) and self.lines[0][1] != "mov":
			   return [ self.lines[0][2], 0]
			else:
			   return ["END",0]
		return ["",0]

	def get_target_reg( self ):
		"""	Returns either "END", "", or the new register to track at the end of this block
	
		This code returns eiter "END" if the register is fatally overwritten, "" if the register is dereferenced
		or the new register in other cases
		"""
		if len( self.lines ) > 0:
			if self.reg == "eax" and self.lines[-1][1] == "call":
		# We have a call that overwrites EAX
				return "END"
			if self.lines[-1][2] == self.reg and self.lines[-1][1] not in neutral_mnem:
		# We have a non-neutral instruction that writes to the register we're tracking
				return "END"
			elif self.lines[-1][2].find( self.reg ) != -1:
		# We have memory access to the location this register is pointing to or an operation on itself
				return ""
			else:
		# If the target is a register, return this register
				if self.lines[-1][2] in x86_registers:
					return self.lines[-1][2]
				else:
					return ""
		else:
			return ""
	def get_lines( self ):
		return self.lines
	def self_to_string( self ):
		str = "StartEA: %lx\nEndEA: %lx\nReg: %s\n" % (self.startea, self.endea\
			,self.reg)
		for line in self.lines:
			str = str + disasm_line_to_string( line ) + "\n"
		return str
	def print_self( self ):
		print self.self_to_string()

def add_data_to_slice_graph( graph, bib ):
	for name in bib.keys():
		node = graph.Get_Node( name )
		node.set_attribute( "label", '"'+bib[name].self_to_string()+'"')
	return

def slice_graph_bwd( endea, reg ):
	"""
		Creates a slice graph for this register from an EA (no recursion)
	""" 
	graph = vcg_Graph.vcgGraph({"title":'"Slice for %s"' % reg, \
		"manhattan_edges":"no", "layoutalgorithm":"maxdepth"})
	#
	#   Retrieve the name of the current basic block
	#    
	worklist = []
	data_bib = {}
	
	startnode = slice_node( 0, endea, reg )		# start at the end of the slice node
	rootnode = graph.Add_Node( startnode.to_name() )
	data_bib[ startnode.to_name() ] = startnode
	worklist.insert( 0, rootnode )
	while len( worklist ) > 0:
		currnode = worklist.pop()
		currslice = data_bib[ currnode.get_name() ]
		[tgt_reg, split] = currslice.get_target_reg_bwd()
		print tgt_reg
		print split
		if tgt_reg == "END":
			# Do not process this node any further
			pass
		elif tgt_reg == "" or (( len( currslice.get_lines()) > 0) and \
			currslice.startea != currslice.get_lines()[0][0]):
			# Do process this node further, nothing really going on 
			print "ZEZ"
			xrefs = get_crefs_to( currslice.startea )
			for ref in xrefs:
				newslice = slice_node(  0,ref, currslice.reg )
				if graph.Get_Node( newslice.to_name() ) == 0:
					newnode = graph.Add_Node( newslice.to_name() )
					worklist.insert( 0, newnode )
					data_bib[ newslice.to_name() ] = newslice
				graph.Add_Link( newslice.to_name(), currnode.get_name() )
		else:
			xrefs = get_crefs_to( currslice.startea )
			for ref in xrefs:
				newslice = slice_node( 0,ref, tgt_reg )
				if graph.Get_Node( newslice.to_name() ) == 0:
					newnode = graph.Add_Node( newslice.to_name() )
					worklist.insert( 0, newnode )
					data_bib[ newslice.to_name() ] = newslice
				graph.Add_Link( newslice.to_name(), currnode.get_name())
			xrefs = get_crefs_to( currslice.startea )
			if split:
				for ref in xrefs:
					newslice = slice_node( 0,ref, currslice.reg )
					if graph.Get_Node( newslice.to_name() ) == 0:
						newnode = graph.Add_Node( newslice.to_name() )
						worklist.insert( 0, newnode )
						data_bib[ newslice.to_name() ] = newslice
					graph.Add_Link( newslice.to_name(), currnode.get_name())
	return [ graph, data_bib ]

def slice_graph_fwd( startea, reg ):
	"""
		Creates a slice graph for this register from an EA (no recursion)
	""" 
	graph = vcg_Graph.vcgGraph({"title":'"Slice for %s"' % reg, \
		"manhattan_edges":"no", "layoutalgorithm":"maxdepth"})
	#
	#   Retrieve the name of the current basic block
	#    
	worklist = []
	data_bib = {}
	startnode = slice_node( startea, 0, reg )
	rootnode = graph.Add_Node( startnode.to_name() )
	data_bib[ startnode.to_name() ] = startnode
	worklist.insert( 0, rootnode )
	while len( worklist ) > 0:
		currnode = worklist.pop()
		currslice = data_bib[ currnode.get_name() ]
		tgt_reg = currslice.get_target_reg()
		if tgt_reg == "END":
		# Do not process this node any further
			pass
		elif tgt_reg == "" or (( len( currslice.get_lines()) > 0) and \
			currslice.endea != currslice.get_lines()[-1][0]):
			# Nothing much happening here, just proceed to parent bocks
			if ua_mnem( currslice.endea ) == "call":
				xrefs = get_short_crefs_from( currslice.endea )
			else:
				xrefs = get_crefs_from( currslice.endea )
			for ref in xrefs:
				newslice = slice_node( ref, 0, currslice.reg )
				if graph.Get_Node( newslice.to_name() ) == 0:
					newnode = graph.Add_Node( newslice.to_name() )
					worklist.insert( 0, newnode )
					data_bib[ newslice.to_name() ] = newslice
				graph.Add_Link( currnode.get_name(), newslice.to_name())
		else:
			# Register was modified, use new register
			xrefs = get_crefs_from( currslice.endea )
			for ref in xrefs:
				newslice = slice_node( ref, 0, tgt_reg )
				if graph.Get_Node( newslice.to_name() ) == 0:
					newnode = graph.Add_Node( newslice.to_name() )
					worklist.insert( 0, newnode )
					data_bib[ newslice.to_name() ] = newslice
				graph.Add_Link( currnode.get_name(), newslice.to_name())
			xrefs = get_crefs_from( currslice.endea )
			for ref in xrefs:
				newslice = slice_node( ref, 0, currslice.reg )
				if graph.Get_Node( newslice.to_name() ) == 0:
					newnode = graph.Add_Node( newslice.to_name() )
					worklist.insert( 0, newnode )
					data_bib[ newslice.to_name() ] = newslice
				graph.Add_Link( currnode.get_name(), newslice.to_name())
	return [ graph, data_bib ]

def write_slice_graph( intuple, fname ):
	newgraph = copy.deepcopy( intuple[0] )
	add_data_to_slice_graph( newgraph, intuple[1] )
	newgraph.write_VCG_File( fname )

def get_resolvable_calls( ea_func ):
	[graph, bib] = slice_graph_fwd( ea_func, "ecx" )
	# search for a node containing "[ecx]" in it's line
	vtable_loads = []
	calls = []
	for name in bib.keys():
		lines = bib[name].get_lines()
		for line in lines:
			if line[3] == "["+ bib[name].reg +"]":
				vtable_loads.append( [line[0], line[2]] )
	for load in vtable_loads:
		[graph, bib] = slice_graph_fwd( load[0] + get_item_size( load[0]) \
			, load[1] )
		for name in bib.keys():
			lines = bib[name].get_lines()
			for line in lines:
				if line[1] == "call":
					calls.append( [line[0], line[2]] )
	#for x in calls:
	#    print "%lx:" % x[0]
	return calls

def get_subfuncs_with_same_thisptr( ea_func ):
	[graph, bib] = slice_graph_fwd( ea_func, "ecx" )
	funcs = []
	#
	#   Now get all slice blocks which have "ecx" on them and look for subfunction
	#   calls in them
	#
	for slicename in bib.keys():
		slice = bib[ slicename ]
		if slice.reg == "ecx":
			begin = slice.startea
			while begin <= slice.endea:
				if ua_mnem( begin ) == "call":
					tgt = get_first_fcref_from( begin )
					if tgt != BADADDR:
						funcs.append( tgt )
				begin = begin + get_item_size( begin )
	return funcs

def get_subfuncs_with_same_thisptr_rec( ea_func ):
	funcdict = {}
	worklist = []
	worklist.append( ea_func )
	funcdict[ ea_func ] = 1
	while len( worklist ) > 0:
		ea = worklist.pop()
		funcs = get_subfuncs_with_same_thisptr( ea )
		for func in funcs:
			if not funcdict.has_key( func ):
				funcdict[ func ] = 1
				worklist.append( func )
	funcs = []
	for x in funcdict.keys():
		funcs.append( x )
	return funcs
			
def resolve_indirect_calls_in_vtable_recursive( vtable_begin, vtable_end ):
	targetdict = {}
	current = vtable_begin
	changed = 1
	newlist = []
	while changed:
		changed = 0
		current = vtable_begin
		while current <= vtable_end:
			tgts = get_subfuncs_with_same_thisptr_rec( get_first_dref_from( current ))
			for tgt in tgts:
				if targetdict.has_key( tgt ):
					pass
				else:
					targetdict[ tgt ] = tgt
					changed = 1
					newlist.append( tgt )
			current = current + 4
		# iterated over vtable once, now resolve one step
		if changed == 1:
			while len( newlist ) > 0:
				f = newlist.pop()
				#print "%lx" % f
				calls = get_resolvable_calls( f )
				for call in calls:
					#print "%lx: %s" % ( call[0], call[1])
					resolve_call( call, vtable_begin )
#
#   Excuse the erratic indentation
#
def resolve_call( call, vtable_begin ):
	if call[1].find( "dword" ) != -1:
		newcall = "0x" + call[1][ call[1].find('[')+5:-2]
		if newcall == "0x":
			newcall = "0"
		offset = string.atol( newcall, 16 )
		target = get_first_dref_from( vtable_begin + offset )
		if target == BADADDR:
			print "%lx: BADADDR as target from vtable at %lx, offset %lx\n" \
				% (call[0], vtable_begin, offset)
		else:
			xrefs = get_far_crefs_from( call[0] )
			if target not in xrefs:
				if get_cmt( call[0], 0 ) != None:
					newcmt = get_cmt( call[0], 0 ) + "target: 0x%lx\n" % target
				else:
					newcmt = "target: 0x%lx\n" % target
				set_cmt( call[0], newcmt, 0 )
				add_cref( call[0], target, fl_CN )
			print "%lx: --> %lx" % ( call[0], target )

def resolve_indirect_calls_in_vtable( vtable_begin, vtable_end):
	current = vtable_begin
	while current <= vtable_end:
		#print "%lx: getting graph..." % get_first_dref_from( current )
		calls = get_resolvable_calls( get_first_dref_from( current ) )
		for call in calls:
			#
			#   strip stuff from call
			#
			resolve_call( call, vtable_begin )
		current = current + 4

def find_vtables_aggressive( firstaddr = 0, lastaddr = 0x7FFFFFFF ):
	"""
		Returns list of begin/end tuples for vtables found in the executable
		A table is considered a vtable if:
			it consists of at least 1 pointers to functions
			it's offset is written to a register in the form [reg]
	"""
	valid_reg_strings = [ "[eax", "[ebx", "[ecx", "[edx", "[esi", "[edi",\
		"[ebp" ]
	if firstaddr == 0:
		startaddr = nextaddr( firstaddr)
	else:
		startaddr = firstaddr
	vtables = []
	while startaddr != BADADDR:
		#
		#   Check if the offset is written 
		#
		xrefs = get_drefs_to( startaddr )
		is_written_to_beginning = 0
		for xref in xrefs:
			line = get_disasm_line( xref )
			if len( line ) >= 3:
				for reg in valid_reg_strings:
					if line[2].find( reg ) != -1:
						is_written_to_beginning = 1
		#
		#   Check if 
		#
		i = 0
		if is_written_to_beginning == 1:
			while get_first_dref_from( startaddr + (4 * (i+1))) != BADADDR:
				ea = get_first_dref_from( startaddr + (4*i))
				func = get_func( ea )
				try:
					if func.startEA != ea:
						break
				except( AttributeError ):
					break;
				i = i + 1
				if len( get_drefs_to( startaddr + ( 4 * (i)))) != 0:
					break;
		if i > 0:
			vtables.append( [ startaddr, startaddr + (4*i) ] )
		if i > 0:
			startaddr = startaddr + i*4
		elif get_item_size( startaddr ) != 0:
			startaddr = startaddr + get_item_size( startaddr )
		else:
			startaddr = startaddr + 1
		if nextaddr( startaddr ) == BADADDR:
			break
		if startaddr >= lastaddr:
			break
	return vtables

def find_vtables( firstaddr = 0, lastaddr = 0x7FFFFFFF ):
	"""
		Returns list of begin/end tuples for vtables found in the executable
		A table is considered a vtable if:
			it consists of at least 2 pointers to functions
			it's offset is written to a register in the form [reg]
	"""
	valid_reg_strings = [ "[eax]", "[ebx]", "[ecx]", "[edx]", "[esi]", "[edi]",\
		"[ebp]" ]
	if firstaddr == 0:
		startaddr = nextaddr( firstaddr)
	else:
		startaddr = firstaddr
	vtables = []
	while startaddr != BADADDR:
		#
		#   Check if the offset is written 
		#
		xrefs = get_drefs_to( startaddr )
		is_written_to_beginning = 0
		for xref in xrefs:
			line = get_disasm_line( xref )
			if len( line ) >= 3:
				for reg in valid_reg_strings:
					if line[2].find( reg ) != -1:
						is_written_to_beginning = 1
		#
		#   Check if 
		#
		i = 0
		if is_written_to_beginning == 1:
			while get_first_dref_from( startaddr + (4 * (i+1))) != BADADDR:
				ea = get_first_dref_from( startaddr + (4*i))
				func = get_func( ea )
				try:
					if func.startEA != ea:
						break
				except( AttributeError ):
					break;
				i = i + 1
		if i > 2:
			vtables.append( [ startaddr, startaddr + (4*i) ] )
		if i > 0:
			startaddr = startaddr + i*4
		elif get_item_size( startaddr ) != 0:
			startaddr = startaddr + get_item_size( startaddr )
		else:
			startaddr = startaddr + 1
		if nextaddr( startaddr ) == BADADDR:
			break
		if startaddr >= lastaddr:
			break
	return vtables

def create_class_from_constructor( constr_addr, strucname ):
	liste = get_addr_ofs_list_from_func( constr_addr, 'ecx' )
	addr_ofs_list_to_IDC( liste, strucname, "c:\\makestruc.idc" )

def create_struct_from_ea( ea, reg, strucname):
	[graph, bib] = slice_graph_fwd( ea, reg )
	addr_ofs_list = []
	for key in bib.keys():
		slice = bib[ key ]
		for line in slice.get_lines():
			#   check if the register is in Op1
			if line[2].find( slice.reg ) != -1:
				op_parts = line[2].split()
				op = op_parts[-1]
				if op[-1] == ']':
					opoffset = op[4:-1]
					if opoffset == "":
						offset = 0
					else:
#                        print "%s" % opoffset
						if opoffset[-1] == 'h':
							try:
								offset = string.atol( opoffset[1:-1], 16 )
							except ValueError:
								op2 = opoffset[1:-1].split('+')[-1]
								try:
									offset = string.atol( op2, 16 )
								except ValueError:
									print op2
									offset = 0
						else:
							try:
								offset = string.atol( opoffset[1:], 16 )
							except ValueError:
								print opoffset[1:]
								offset = 0
					addr_ofs_list.append( (line[0], offset, 0) )
				# Work on operand 1
			if line[3].find( slice.reg ) != -1:
				# Work on operand 2
				op_parts = line[3].split()
				op = op_parts[-1]
				if op[-1] == ']':
					opoffset = op[4:-1]
					opoffset = op[4:-1]
					if opoffset == "":
						offset = 0
					else:
#                        print "%s" % opoffset
						if opoffset[-1] == 'h':
							if opoffset[1:-1].find("+") != -1:
								print opoffset
								opoffset = opoffset[1:-1].split("+")[-1]
							offset = string.atol( opoffset[1:-1], 16 )
						else:
							try:
								offset = string.atol( opoffset[1:], 16 )
							except ValueError:
								print opoffset[1:]
								offset = 0
					addr_ofs_list.append( (line[0], offset, 1) )
	#addr_ofs_list_to_IDC( addr_ofs_list, strucname, "c:\\makestruc.idc" )
	assign_structure_members( addr_ofs_list, strucname )

def assign_structure_members( results, structure_name ):
	strucid = idc.GetStrucIdByName( structure_name )
	if strucid == 0xFFFFFFFF:
		print "Adding structure %s" % structure_name
		strucid = idc.AddStrucEx( -1, structure_name, 0 )
	for ref in results:
		idc.AddStrucMember( strucid, "mem_%lx" % ref[1], ref[1], FF_BYTE, -1, 1 );
		#AddStrucMember( strucid, "mem_%lx" % ref[1], ref[1], FF_BYTE|FF_DATA, -1, 1 )
		idc.OpStroffEx( ref[0], ref[2], strucid, 0 )

def track_register( address, register ):
	return get_addr_ofs_list_from_addr( address, register )

def get_addr_ofs_list_from_func( funcea, register ):
	return get_addr_ofs_list_from_addr( funcea, register )

def get_addr_ofs_list_from_addr( funcea, register ):
	"""
		Since a lot of structure manipulation can't be done from IDAPython(yet),
		we have to create an external IDC :-(((((
	"""
	ea = funcea
	reg = register
	[graph, bib] = slice_graph_fwd( ea, reg )
	addr_ofs_list = []
	for key in bib.keys():
		slice = bib[ key ]
		for line in slice.get_lines():
			#   check if the register is in Op1
			if line[2].find( slice.reg ) != -1:
				op_parts = line[2].split()
				op = op_parts[-1]
				if op[-1] == ']':
					opoffset = op[4:-1]
					if opoffset == "":
						offset = 0
					else:
#                        print "%s" % opoffset
						if opoffset[-1] == 'h':
							try:
								offset = string.atol( opoffset[1:-1], 16 )
							except ValueError:
								op2 = opoffset[1:-1].split('+')[-1]
								try:
									offset = string.atol( op2, 16 )
								except ValueError:
									print op2
									offset = 0
						else:
							try:
								offset = string.atol( opoffset[1:], 16 )
							except ValueError:
								print opoffset[1:]
								offset = 0
					addr_ofs_list.append( (line[0], offset, 0) )
				# Work on operand 1
			if line[3].find( slice.reg ) != -1:
				# Work on operand 2
				op_parts = line[3].split()
				op = op_parts[-1]
				if op[-1] == ']':
					opoffset = op[4:-1]
					opoffset = op[4:-1]
					if opoffset == "":
						offset = 0
					else:
#                        print "%s" % opoffset
						if opoffset[-1] == 'h':
							if opoffset[1:-1].find("+") != -1:
								print opoffset
								opoffset = opoffset[1:-1].split("+")[-1]
								offset = string.atol( opoffset, 16 )
							else:
								offset = string.atol( opoffset[1:-1], 16 )
						else:
							try:
								offset = string.atol( opoffset[1:], 16 )
							except ValueError:
								print opoffset[1:]
								offset = 0
					addr_ofs_list.append( (line[0], offset, 1) )
	return addr_ofs_list

def track_register_back( funcea, register ):
	"""
		Since a lot of structure manipulation can't be done from IDAPython(yet),
		we have to create an external IDC :-(((((
	"""
	ea = funcea
	reg = register
	[graph, bib] = slice_graph_bwd( ea, reg )
	addr_ofs_list = []
	for key in bib.keys():
		slice = bib[ key ]
		for line in slice.get_lines():
			#   check if the register is in Op1
			if line[2].find( slice.reg ) != -1:
				op_parts = line[2].split()
				op = op_parts[-1]
				if op[-1] == ']':
					opoffset = op[4:-1]
					if opoffset == "":
						offset = 0
					else:
#                        print "%s" % opoffset
						if opoffset[-1] == 'h':
							offset = string.atol( opoffset[1:-1], 16 )
						else:
							try:
								offset = string.atol( opoffset[1:], 16 )
							except ValueError:
								print opoffset[1:]
								offset = 0
					addr_ofs_list.append( (line[0], offset, 0) )
				# Work on operand 1
			if line[3].find( slice.reg ) != -1:
				# Work on operand 2
				op_parts = line[3].split()
				op = op_parts[-1]
				if op[-1] == ']':
					opoffset = op[4:-1]
					opoffset = op[4:-1]
					if opoffset == "":
						offset = 0
					else:
#                        print "%s" % opoffset
						if opoffset[-1] == 'h':
							if opoffset[1:-1].find("+") != -1:
								print opoffset
								opoffset = opoffset[1:-1].split("+")[-1]
							offset = string.atol( opoffset[1:-1], 16 )
						else:
							try:
								offset = string.atol( opoffset[1:], 16 )
							except ValueError:
								print opoffset[1:]
								offset = 0
					addr_ofs_list.append( (line[0], offset, 1) )
	return addr_ofs_list

def reconstruct_class_from_vtable( classname, vtable_begin, vtable_end ):
	current = vtable_begin
	whole_list = []
	while current <= vtable_end:
		tgts = get_drefs_from( current )
		for x in tgts:
			list = get_addr_ofs_list_from_func( x, "ecx")
			for y in list:
				whole_list.append( y )
		current = current+4
	addr_ofs_list_to_IDC( whole_list, classname, "c:\\makestruc.idc" )

def addr_ofs_list_to_IDC( addr_ofs_list, strucname, idcname = "makestruc.idc" ):
	idc_intro = '#include <idc.idc>\n'
	idc_intro = idc_intro+'static main(){\n'
	idc_intro = idc_intro+'\tauto strucid;\n'
	idc_intro = idc_intro+'\tstrucid = GetStrucIdByName("%s");\n'
	idc_intro = idc_intro+'\tif( strucid == -1 )\n'
	idc_intro = idc_intro+'\t\tstrucid = AddStruc( 0, "%s" );\n'
	idc_intro = idc_intro % (strucname, strucname)
	outidc = file( idcname, "wt" )
	outidc.write(idc_intro)
	offset_dict = {}
	for add_ofs in addr_ofs_list:
		if offset_dict.has_key( add_ofs[1] ):
			outidc.write( "\tOpStroffEx( 0x%lx, %d, strucid, 0 );\n" % (add_ofs[0], add_ofs[2] ))
		else:
			offset_dict[add_ofs[1]] = add_ofs[0]
			outidc.write( '\tAddStrucMember( strucid, "mem_%lx", %d, FF_BYTE, -1, 1 );\n' % (add_ofs[1], add_ofs[1]) )
			outidc.write( "\tOpStroffEx( 0x%lx, %d, strucid, 0 );\n" % (add_ofs[0], add_ofs[2] ))
	outidc.write( "}" )
	outidc.close()
	
def count_indirect_calls():
	startaddr = nextaddr( 0 )
	pass

def oop_indirect_call_resolver():
	print "============================================"
	print " SABRE OOP IDAPython Scripts       (c) 2005 "
	print " [!] Counting unresolved indirect calls ... "
	
	print " [!] Detecting vtables ... "
	vtbls = find_vtables()
	print " [!] Resolving indirect calls ... "
	for table in vtbls:
		resolve_indirect_calls_in_vtable_recursive( table[0], table[1] )
	print " [!] Counting unresolved calls again ... "


def create_cluster_graph():
	i = 0
	cluster_graph = vcg_Graph.vcgGraph()
	while i < get_func_qty():
		current_func = getn_func( i )
		print "Processing function at %lx" % current_func.startEA
		start_ea = current_func.startEA
		subfuncs = get_subfuncs_with_same_thisptr( start_ea )
		if len( subfuncs ) > 0:
			sourcename = get_name( BADADDR, start_ea )
			if sourcename == None:
				sourcename = "%lx" % start_ea
			node = cluster_graph.Get_Node( sourcename )
			if node == 0:
				node = cluster_graph.Add_Node( sourcename )
				node.set_attribute( "label", '"' + sourcename + '"')
			for targetea in subfuncs:
				targetname = get_name( BADADDR, targetea )
				if targetname == None:
					targetname = "%lx" % targetea 
				targetnode = cluster_graph.Get_Node( targetname )
				if targetnode == 0:
					targetnode = cluster_graph.Add_Node( targetname )
					targetnode.set_attribute( "label", '"' + targetname + '"')
			cluster_graph.Add_Link( sourcename, targetname )
		i = i + 1
	cluster_graph.write_VCG_File( "c:\\cluster.vcg" )
	foo = cluster_graph.make_GML_output()
	outfile = file("c:\\cluster.gml", "wt" )
	outfile.write( foo )
	outfile.close()
	return cluster_graph

def merge_flowgraphs_no_link( graphlist ):
	merged_graph = vcg_Graph.vcgGraph()
	for graph in graphlist:
		nodes = graph.get_nodes()
		for nodename in nodes.keys():
			merged_graph.Add_Node( nodename )
	# Done adding all nodes. Now add all edges
	for graph in graphlist:
		links = graph.get_links()
		for link in links:
			merged_graph.Add_Link( link.get_sourcename(), link.get_targetname())
	return merged_graph
	
def merge_flowgraphs( graphlist ):
	merged_graph = vcg_Graph.vcgGraph()
	for graph in graphlist:
		nodes = graph.get_nodes()
		for nodename in nodes.keys():
			merged_graph.Add_Node( nodename )
	# Done adding all nodes. Now add all edges
	for graph in graphlist:
		links = graph.get_links()
		for link in links:
			merged_graph.Add_Link( link.get_sourcename(), link.get_targetname())
	merged_graph.write_VCG_File( "c:\\merged.vcg" )
	# Now add edges to link the graphs together
	i = len( graphlist )-1
	while i != 0:
		parentg = graphlist[i-1]
		childg = graphlist[i]
		child_topnode = childg.Get_Top_Nodes()[0]
		parent_topnode = parentg.Get_Top_Nodes()[0]
		parent_calls = get_calls_in_function( string.atol( parent_topnode, 16) )
		print "processing parent %s, child %s" % (parent_topnode, child_topnode)
		for call in parent_calls:
			# check and link
			targetlist = get_far_crefs_from( call[0] )
			for target in targetlist:
				if "%x" % target == child_topnode:
					block = get_basic_block( call[0] )
					print "Adding link from %x to %s" % (block[0][0], child_topnode)
					merged_graph.Get_Node( "%x" % target ).set_attribute("color", "red")
					merged_graph.Add_Link( "%x" % block[0][0], child_topnode )
		i = i - 1
	return merged_graph

def inline_subfuncs_special( flowgraph ):
	newedgelist = []
	mergelist = [ flowgraph ]
	for address in flowgraph.get_nodes().keys():
		block = get_basic_block( string.atol( address, 16 ))
		if block[ -1 ][1] == "call":
			print "%lx: %s" % ( block[-1][0], block[-1][1])
			xrefs_from = get_far_crefs_from( block[-1][0] )	
			print xrefs_from
			for target in xrefs_from:
				if flowgraph.Get_Node( "%x" % target ) == 0:
					reroute_edge_source = "%x" % block[0][0]
					callchild = flowgraph.Get_Children( "%x" % block[0][0] )
					if len( callchild ) > 0:
						reroute_edge_target = callchild[ 0 ] 
					else:
						print "Could not find children of '%x'!\n" % block[0][0]
						add_disasm_lines_to_flowgraph( flowgraph )
						flowgraph.write_VCG_File("c:\\foo.vcg")
						reroute_edge_target = ""
						#print callchild[1]
					# Get the flowgraph and merge it in
					newgraph = create_flowgraph_from( target )
					mergelist.append( newgraph )
					print "inlining %lx between nodes %s and %s" % (target, reroute_edge_source, reroute_edge_target)
					newedgelist.append( ( reroute_edge_source, reroute_edge_target, newgraph ) )
	# allright, now merge stuff
	print mergelist
	mergedgraph = merge_flowgraphs_no_link( mergelist )
	#mergedgraph.write_VCG_File("C:\\murged.vcg")
	for triplet in newedgelist:
		topnode = triplet[2].Get_Top_Nodes()[0]
		bottomnodes = triplet[2].Get_Bottom_Nodes()
		mergedgraph.Add_Link( triplet[0], topnode )
		reroute_edge_target = triplet[1]
		if reroute_edge_target != "":
			for node in bottomnodes:
				mergedgraph.Add_Link( node, reroute_edge_target )
			mergedgraph.Del_Link2( reroute_edge_source, reroute_edge_target )
	for address in flowgraph.get_nodes().keys():
		mergedgraph.Get_Node( address ).set_attribute( "color", "lightblue" )
	return mergedgraph

def inline_subfuncs_into( flowgraph ):
	newedgelist = []
	mergelist = [ flowgraph ]
	for address in flowgraph.get_nodes().keys():
		block = get_basic_block( string.atol( address, 16 ))
		if block[ -1 ][1] == "call":
			print "%lx: %s" % ( block[-1][0], block[-1][1])
			xrefs_from = get_far_crefs_from( block[-1][0] )	
			callchild = flowgraph.Get_Children( "%x" % block[0][0] )
			if len( callchild ) > 0:
				childaddr = string.atol( callchild[0], 16 )
				if childaddr in xrefs_from:
					continue
			for target in xrefs_from:
				if flowgraph.Get_Node( "%x" % target ) == 0:
					reroute_edge_source = "%x" % block[0][0]
					callchild = flowgraph.Get_Children( "%x" % block[0][0] )
					if len( callchild ) > 0:
						reroute_edge_target = callchild[ 0 ] 
					else:
						print "Could not find children of '%x'!\n" % block[0][0]
						add_disasm_lines_to_flowgraph( flowgraph )
						flowgraph.write_VCG_File("c:\\foo.vcg")
						reroute_edge_target = ""
						#print callchild[1]
					# Get the flowgraph and merge it in
					newgraph = create_flowgraph_from( target )
					mergelist.append( newgraph )	
					newedgelist.append( ( reroute_edge_source, reroute_edge_target, newgraph ) )
	# allright, now merge stuff
	print mergelist
	mergedgraph = merge_flowgraphs_no_link( mergelist )
	#mergedgraph.write_VCG_File("C:\\murged.vcg")
	for triplet in newedgelist:
		topnode = triplet[2].Get_Top_Nodes()[0]
		bottomnodes = triplet[2].Get_Bottom_Nodes()
		mergedgraph.Add_Link( triplet[0], topnode )
		reroute_edge_target = triplet[1]
		if reroute_edge_target != "":
			for node in bottomnodes:
				mergedgraph.Add_Link( node, reroute_edge_target )
			mergedgraph.Del_Link2( reroute_edge_source, reroute_edge_target )
	for address in flowgraph.get_nodes().keys():
		mergedgraph.Get_Node( address ).set_attribute( "color", "lightblue" )
	return mergedgraph
	
def create_flowgraph_from( address ):
	"""
		Simple function to generate a flowgraph from an address (forwards)
	"""
	flowgraph = vcg_Graph.vcgGraph()
	worklist = [ get_basic_block( address ) ]
	flowgraph.Add_Node( "%x" % worklist[0][0][0] )	
	while len( worklist ) != 0:
		current_block = worklist.pop(0)
		if current_block[-1][1] != "call":
			nextblocks = get_crefs_from( current_block[-1][0] )
		else:
			nextblocks = get_short_crefs_from( current_block[-1][0] )
		for blockaddr in nextblocks:
			block = get_basic_block( blockaddr )
			if not flowgraph.has_node( "%x" % block[0][0] ):
				newnode = flowgraph.Add_Node( "%x" % block[0][0] )
				worklist.append( block )
			flowgraph.Add_Link( "%x" % current_block[0][0], "%x" % block[0][0] )
	return flowgraph

def remove_nodes_below( flowgraph, list_of_eas ):
	# initialize the begin list
	preservedict = {}
	worklist = []
	for node in flowgraph.get_nodes().keys():
		preservedict[ node ] = 0
	for addr in list_of_eas:
		block = get_basic_block( addr )
		worklist.append(  "%x" % block[0][0] )
	while len( worklist ) != 0:
		if preservedict[ worklist[0] ] == 0:
			preservedict[ worklist[0] ] = 1
			newlist = flowgraph.Get_Parents( worklist[0] )
			worklist = worklist[1:] + newlist
		else:
			worklist = worklist[1:]
	for (node,val) in preservedict.items():
		if val == 0:
			flowgraph.Del_Node( node )
	return flowgraph

def write_flowgraph( flowgraph, fname ):
	newgraph = copy.deepcopy( flowgraph )
	add_disasm_lines_to_flowgraph( newgraph )
	newgraph.write_VCG_File( fname )

#def write_flowgraph_syntax_highlighted( flowgraph, fname ):
#	newgraph = copy.deepcopy( flowgraph )
#	add_disasm_lines_to_flowgraph( flowgraph )
#	flowgraph.write_VCG_File( fname )

def add_disasm_lines_to_flowgraph( flowgraph ):
	for nodetup in flowgraph.nodes.items():
		node = nodetup[1]
		block = get_basic_block_from( string.atol( node.get_name(), 16 ))
		insn_string = ""
		for instruction in block:
			insn_string = insn_string + ( "%x: %s %s %s\n" % 
				(instruction[0], instruction[1], instruction[2], instruction[3]))
			insn_string = idaline_to_string( insn_string )
		node.set_attribute("label", '"'+insn_string+'"')

def get_calls_in_function( ea ):
	"""
		Returns a list with call instructions in a given function
	"""
	callist = []
	flowgraph = create_flowgraph_from( ea )
	for x in flowgraph.nodes.items():
		name = x[0]
		block = get_basic_block( string.atol( name, 16 ))
		for instruction in block:
			if instruction[ 1 ] == "call":
				callist.append( instruction )
	return callist

def get_calls_in_function_ext( ea ):
	"""
		Like get_calls_in_function, but returns list with instructions prepended by function EA in which they are
	"""
	calls = get_calls_in_function( ea )
	for call in calls:
		call.insert(0, ea)
	return calls

def create_reachgraph_from_delta_graph( deltagraph, distance ):
	"""
		Returns a graph of "reachable's with a given stack delta"
	"""
	reachgraph = vcg_Graph.vcgGraph()
	reachgraph.set_attribute("manhattan_edges", "no" )
	print "Creating Reachgraph"
	original_node_dict = {}
	delta_node_dict = {}
	
	rootlist = deltagraph.Get_Top_Nodes()
	new_node_str = rootlist[0] + "::0"
	original_node_dict[ new_node_str ] = rootlist[0]
	delta_node_dict[ new_node_str ] = 0
	
	worklist = [ reachgraph.Add_Node( new_node_str ) ]
	worklist[0].set_attribute( "label", '"%s(%d)(%d)-%s"' % (get_name( 0, string.atol( rootlist[0] ,16 )),0,get_real_frame_size(string.atol(rootlist[0],16)), rootlist[0]))
	while len( worklist ) != 0:
		current_node = worklist.pop(0)
		#	Retrieve the delta and original node of this node 
		orig_node = original_node_dict[ current_node.get_name() ]
		curr_delta = delta_node_dict[ current_node.get_name() ]
		#	Get the outgoing edges of the original node
		down_links = deltagraph.Get_Downlinks_From( orig_node )
		for link in down_links:
			#	Get the delta associated with this edge
			link_delta_str = link.get_attribute("label")[1:-1]
			link_delta = string.atol( link_delta_str, 10 )
			#	Calculate the target's new delta
			target_delta = curr_delta + link_delta - 4	# - 4 is for the size of EIP on the stack
			#	Construct the name for the new node to be added
			new_node_str = link.get_targetname() + "::" + "%d" % target_delta 
			newaddr = string.atol( link.get_targetname(), 16)
			framesize = get_real_frame_size(  newaddr )
				
			original_node_dict[ new_node_str ] = link.get_targetname()
			delta_node_dict[ new_node_str ] = target_delta
			
			if not reachgraph.has_node( new_node_str ):
				new_node = reachgraph.Add_Node( new_node_str )
				new_node.set_attribute( "target_delta", "%d" % target_delta )
				new_node.set_attribute( "function_framesize", "%d" % framesize )
				newlabel = '"%s(%d)' % ( get_name( 0, newaddr), abs(target_delta))
				newlabel = newlabel + '(%d)' % framesize
				newlabel = newlabel + '-%s"' % link.get_targetname()
				
				print newlabel
				
				new_node.set_attribute( "label", newlabel )
				if target_delta - framesize <= distance:
					currlabel = new_node.get_attribute( "label" )
					if currlabel.find( "fin_" ) == -1:
						newlabel = currlabel [0] + "fin_" + currlabel[1:]
					else:
						newlabel = currlabel
					new_node.set_attribute("label", newlabel )
				else:
					worklist.append( new_node )
			new_link = reachgraph.Add_Link( current_node.get_name(), new_node_str )
			if target_delta <= distance:
				new_link.set_attribute( "label", "%d" % target_delta )
	#reachgraph.write_VCG_File("c:\\reach.vcg")
	return reachgraph
	
def create_stack_delta_graph_from_function( ea, recursion_depth ):
	"""
		Returns a graph and a node data map
	"""
	stack_delta_graph = vcg_Graph.vcgGraph()
	stack_delta_graph.set_attribute("manhattan_edges", "no" )
	edge_dict = {}
	firstnode = stack_delta_graph.Add_Node( "%x" % ea )
	firstnode.set_attribute( "label", '"%s-%x"' % ("START",ea))
	
	calls = get_calls_in_function_ext( ea )
	nextcalls = []
	# Add all the subfunctions
	while len( calls ) != 0 and recursion_depth != 0:
		for call in calls:
			#	create list of possible targets
			target_list = get_far_crefs_from( call[1] )
			target_ea = get_name_ea( call[1], call[ 3 ] )
			if target_ea != BADADDR:
				target_list.append( target_ea )
			for target_ea in target_list:
#				if target_ea != BADADDR:
				if not stack_delta_graph.has_node( "%x" % target_ea ):
					new_node = stack_delta_graph.Add_Node( "%x" % target_ea )
					new_node.set_attribute( "label", '"%s-%x"' % (get_name(0, target_ea) ,target_ea))
					nextcalls.extend( get_calls_in_function_ext( target_ea ))
				source = "%x" % call[0]
				targetstr = "%x" % target_ea
				delta = "%d" % get_spd( get_func( call[1] ), call[1])
				edge_dict_sig = (source, targetstr, delta)
				if not edge_dict.has_key( edge_dict_sig ):
					if edge_dict_sig[1] != firstnode.get_name():
						link = stack_delta_graph.Add_Link( edge_dict_sig[0], edge_dict_sig[1] )
						link.set_attribute( "label", '"'+edge_dict_sig[2]+'"' )
						edge_dict[ edge_dict_sig ] = 1
		calls = nextcalls
		nextcalls = []
		recursion_depth = recursion_depth - 1
	stack_delta_graph.write_VCG_File("c:\\test.vcg")
	return stack_delta_graph

	
def retrieve_all_fpo_funcs( ):
	ret = []
	i = 0
	while i < get_func_qty():
		func = getn_func( i )
		end = func.endEA - 1
		if func.flags == 0:
			lastinsns = []
			for k in range(0, 3):
				lastinsns.insert( 0, get_disasm_line( end ))
				end = get_first_cref_to( end )
				if end == BADADDR:
					break
			if len( lastinsns ) > 1:
				if lastinsns[1][1] == "add":
					print "%x: %s %s %s" % ( lastinsns[1][0], lastinsns[1][1], lastinsns[1][2], lastinsns[1][3])
			if lastinsns[0][1] == "pop" and lastinsns[1][1] == "pop":
				print "%x: %s %s %s" % ( lastinsns[0][0], lastinsns[0][1], lastinsns[0][2], lastinsns[0][3])
				print "%x: %s %s %s" % ( lastinsns[1][0], lastinsns[1][1], lastinsns[1][2], lastinsns[1][3])
				print "%x: %s %s %s" % ( lastinsns[2][0], lastinsns[2][1], lastinsns[2][2], lastinsns[2][3])
		i = i + 1

#deltagraph = create_stack_delta_graph_from_function( 0x432870 , 25)
#reachgraph = create_reachgraph_from_delta_graph( deltagraph, -200 )
#sicken = deltagraph.make_GML_output()
#f = file("c:\\sicken.gml", "wt")
#f.write(sicken)
#f.close()
#sicken = reachgraph.make_GML_output()
#f = file("c:\\sickreach.gml", "wt")
#f.write(sicken)
#f.close()

def build_reachgraph_from_path( path_delta_list, bottom_func_delta ):
	"""
		Build graphs for a number of different reachgraphs (one for each in the chain)
	"""
	lastidx = len( path_delta_list ) - 1
	while lastidx != 0:
		# create the first delta graph
		deltagraph = create_stack_delta_graph_from_function( path_delta_list[ lastidx ][0], 25 )
		sicken = deltagraph.make_GML_output()
		f = file("c:\\deltagraph_%lx.gml" % path_delta_list[ lastidx ][0], "wt")
		f.write(sicken)
		f.close()
		#reachgraph = create_reachgraph_from_delta_graph( deltagraph, -200 )
		# calculate total delta of the chain
		delta = 0
		count = lastidx
		while count != 0:
			delta = delta - path_delta_list[ count ][1]
			delta = delta - 4
			count = count - 1
		delta = delta - path_delta_list [ 0 ][1]
		print "Calling create_reachgraph from %lx with delta %d" % (path_delta_list[ lastidx ][0], delta )
		reachgraph = create_reachgraph_from_delta_graph( deltagraph, delta )	
		sicken = reachgraph.make_GML_output()
		f = file("c:\\reach_%lx_%d.gml" % (path_delta_list[lastidx][0], delta), "wt")
		f.write(sicken)
		f.close()
		lastidx = lastidx - 1

def get_real_frame_size( address ):
	"""
		Retrieves the real size of a frame
	"""
	frame = get_frame( get_func( address ))
	retaddr = get_member_by_name(frame, " r" )
	if retaddr != None:
		return (get_max_offset(frame) - (get_max_offset( frame ) - retaddr.get_soff()))
	else:
		print "Could not find retaddr at %lx\n" % address
		return 0

def strip_below_calls( firstaddress, flowgraph, targetaddress ):
	subcalls = get_calls_in_function( firstaddress )
	call_list = []
	for call in subcalls:
		targets = get_far_crefs_from( call[0] )
		if len( targets ) != 0:
			if targetaddress in targets:
				call_list.append( call[0] )
	remove_nodes_below( flowgraph, call_list )
		

def build_ibb_graph_from( ea_source, sourcenode, reachgraph ):
	"""
		Walks a reachgraph upwards, inlining every function on the path. 
	
		Allright, describe the algorithm first before writing shit down
	
		1. Retrieve first flowgraph and node
		2. Remove all that is not before node
		3. Scan upwards. Notice stack access in each basic block
			3a.	If you run into a call, and the target of the call is in the
				reachgraph, inline it
			3b. 	If you run into the beginning of the function, add the return
				nodes of all parents in the reachgraph to the graph
	"""
	flowgraph = create_flowgraph_from( 0x4423D0 )
	add_disasm_lines_to_flowgraph( flowgraph )
	flowgraph.write_VCG_File("C:\\test.vcg")

def build_flowgraph_from_path( path, target_addr ):
	i = len( path ) - 1
	graphlist = []
	while i != 0:
		print "Trying to generate flowgraph from %d" % i
		flowgraph = create_flowgraph_from( path[ i ][0] )
		flowgraph.write_VCG_File("c:\\%d.vcg" % i )
		print "Trying to strip %lx calls from %lx graph" % (path[i-1][0], path[i][0])
		strip_below_calls( path[i][0], flowgraph, path[i-1][0] )
		flowgraph.write_VCG_File("c:\\%d_strip.vcg" % i )
		graphlist.append( flowgraph )
		i = i - 1
	flowgraph = create_flowgraph_from( path[0][0] )
	remove_nodes_below( flowgraph, [target_addr] )
	graphlist.append( flowgraph )
	return merge_flowgraphs( graphlist )

def get_function_end_addresses( address ):
	flow = create_flowgraph_from( address )
	endnodes = flow.Get_Bottom_Nodes()
	end_list = []
	for x in endnodes:
		block = get_basic_block( string.atol( x, 16 ))
		end_list.append( block[-1][0] )
	return end_list
	
		
def get_basic_block_stack_delta( address ):
	"""
		Returns the difference between ESP upon entry and end of the basic block
	"""
	delta = 0
	blk = get_basic_block( address )
	if blk[-1][1] == "call":
		delta = 4
	if blk[-1][1] == "retn":
		delta = -4
	func = get_func( blk[0][0] )
	if blk[0][0] == blk[-1][0]:
		return get_sp_delta( func, blk[0][0] )
	else:
		spdelta = get_spd( func, blk[0][0] ) - get_spd( func, blk[-1][0] )
		spdelta = spdelta + delta
		return spdelta


def create_reachgraph_from_pathgraph( pathgraph, address ):
	"""
		Returns a graph of "reachable's with a given stack delta"
	"""
	reachgraph = vcg_Graph.vcgGraph()
	reachgraph.set_attribute("manhattan_edges", "no" )
	print "Creating Path Reachgraph"
	original_node_dict = {}
	delta_node_dict = {}
	
	rootnode = pathgraph.Get_Node("%lx" % address)
	new_node_str = rootnode.get_name() + "::0"
	print new_node_str
	print "parents" 
	print pathgraph.Get_Parents( rootnode.get_name() )
	original_node_dict[ new_node_str ] = rootnode
	delta_node_dict[ new_node_str ] = 0
	
	worklist = [ reachgraph.Add_Node( new_node_str ) ]
	worklist[0].set_attribute( "label", '"%s"' % new_node_str )
	counter = 0
	while len( worklist ) != 0:
		counter = counter + 1
		if counter > 1100:
			reachgraph.write_VCG_File("c:\\pathreach_%d.vcg" % counter )
			return reachgraph
		current_node = worklist.pop(0)
		#	Retrieve the delta and original node of this node 
		orig_node = original_node_dict[ current_node.get_name() ]
		curr_delta = delta_node_dict[ current_node.get_name() ]
		#	Get the incoming edges of the original node
		parents = pathgraph.Get_Parents( orig_node.get_name() )
		print parents
		for parent in parents:
			parent_delta = get_basic_block_stack_delta( string.atol ( parent, 16 ))
			target_delta = curr_delta + parent_delta
			#	Construct the name for the new node to be added
			new_node_str = parent + "::" + "%d" % target_delta 
			original_node_dict[ new_node_str ] = pathgraph.Get_Node( parent )
			delta_node_dict[ new_node_str ] = target_delta
			if not reachgraph.has_node( new_node_str ):
				new_node = reachgraph.Add_Node( new_node_str )
				newlabel = '"%s"' % new_node_str
				new_node.set_attribute( "label", newlabel )
				if target_delta < 0:	# delta dipped below zero !
					new_node.set_attribute( "color", "lightblue" )
					new_node.set_attribute( "bordercolor", "red" )
					new_node.set_attribute( "borderwidth", "10" )
				else:
					worklist.append( new_node )
			new_link = reachgraph.Add_Link( new_node_str, current_node.get_name() )
	reachgraph.write_VCG_File("c:\\pathreach.vcg")
	return reachgraph

def build_flowgraph_from_to( ea_source, ea_target ):
	#
	# Start out by getting the functions the basic blocks are in respectively
	#
	source_func = get_func_ea_from_ea( ea_source )
	target_func = get_func_ea_from_ea( ea_target )
	#
	# Because it's easier, construct a stack delta graph
	#

def get_return_value_summary( target_function ):
	""" Returns a (possibly sound) set of return values -- these can be:
		1) Concrete values
		2) Function names (if the return value of that function is returned)
		3) The term "THIS" if it returns ECX
		3) The term "UNKN" for anything else
		
	"""
	retvalset = sets.Set()
	flowgraph = create_flowgraph_from( target_function )
	endnodes = flowgraph.Get_Bottom_Nodes()
	i = 0
	for node in endnodes:
		blk = get_basic_block( string.atol( node, 16))
		[grph, bib] = slice_graph_bwd( blk[-1][0], "eax" )
		write_slice_graph( [grph,bib], "c:\\garbage\\%s-%d.vcg" % (node, i))
		i = i+1
		topnodes = grph.Get_Top_Nodes()
		for topnode in topnodes:
			if len( bib[topnode].lines ) == 0:
				if bib[topnode].reg == "ecx":
					retvalset.add( "THIS" )
				else:
					print "%s: Look at this, reg passed in ? !" % topnode
				continue
			line = bib[topnode].lines[0]
			addr = line[0]
			if line[ 1 ] == "call":
				target = get_name(0, get_first_fcref_from( line[0] ))
				if target != None:
					#if target == "@__security_check_cookie@4":
					# HANDLE sec check !	
					retvalset.add( target )
				else:
					retvalset.add( "UNKN")
			elif line[ 1 ] == "mov":
				if might_be_immediate( line[3] ):
					retvalset.add( line[3] )
				else:
					retvalset.add("UNKN")
			elif line[ 1 ] == "xor" and line[ 2] == line[3]:
				retvalset.add("0")
			elif line[ 1 ] == "and" and line[ 3] == "0":
				retvalset.add("0")
			elif line[ 1 ] == "or" and line[ 3 ] == "0FFFFFFFFh":
				retvalset.add("-1")
			elif line[ 1 ] == "or" and line[ 3 ] == "-1":
				retvalset.add("-1")
			else:
				print "Can't yet handle:"
				print line
	#print retvalset
	return retvalset

def get_method_calls_in_method( funcea ):
	g = slice_graph_fwd( funcea, "ecx")
	ddict = g[1]
	methods = set()
	for slice_node in ddict.values():
		if slice_node.reg == "ecx":
			instruc = get_disasm_line( slice_node.endea )
			if instruc[1] == "call":
				refs = get_far_crefs_from( slice_node.endea )
				for ref in refs:
					methods.add( ref )
	return methods
		

def get_retval_summaries():
	dict = {}
	ea = 0
	while ea != BADADDR :
		func = get_next_func( ea )
		if func:
			newea = func.startEA
		else:
			return dict		
		if newea == ea:
			return
		dict[newea] = get_return_value_summary( newea )
		ea = newea
	return dict

def get_retval_summaries_transitive():
	dict = get_retval_summaries()
	transitive_dict = {}
	for (ea, summary) in dict.items():
		"""for item in summary:
			if dict.hasKey( get_name_ea( item )):
				if not transitive_dict.hasKey( ea ):
					transitive_dict[ea] = sets.Set()
				transitive_dict[ ea ] = transitive_dict[ea].union( dict"""
				
		print "%lx:" % ea
		print summary

def get_pushes_before_call( callea, n ):
	"""
	"""
	
def get_push_before_call( callea, n ):
	x = get_spd( get_func( callea ), callea ) + (n*4)
	block = get_basic_block( callea )
	block.reverse()
	for insn2 in block:
		if get_spd( get_func( callea ), insn2[0]) == x:
			return insn2
	return None
	

class vtable:
	def __init__( self, begin, end, name ):
		self.begin = begin
		self.end = end
		self.name = name
		self.methods = []
		for addr in range( begin, end, 4 ):
			ref = get_drefs_from( addr )[ 0 ]
			self.methods.append( ref )
		self.constructors = []
		for ref in get_drefs_to( begin ):
			self.constructors.append( 
				get_func( ref ).startEA )
		return
	def __str__( self ):
		return "vtable"
	def __repr__( self ):
		return "vtable"

def vtables_to_relations_graph( vtablelist ):
	graph = vcg_Graph.vcgGraph()
	for vtable in vtablelist:
		vtable_node = graph.Add_Node( vtable.name )
		for method in vtable.methods:
			method_node = graph.Add_Node( get_name( 0,method ))
			graph.Add_Link( vtable.name, get_name( 0,method) )
		for constructor in vtable.constructors:
			ctr_node = graph.Add_Node( get_name( 0,constructor) )
			graph.Add_Link( get_name( 0,constructor ), vtable.name )
	graph.write_VCG_File( "c:\\output.vcg")
	return graph
		
def cpp_code_primer( begin, end ):
	vtables = []
	p = find_vtables_aggressive( begin, end)
	count = 0
	for i in p:
		set_name( i[0], "class_%d_vtable" % count, 0)
		vtables.append( vtable( i[0], i[1], "class_%d_vtable" % count ))
		count = count + 1
	graph = vtables_to_relations_graph( vtables )

	# Retrieve the constructors, e.g. roots of this graph
	
	# Retrieve the leafs
	
	for l_vtable in vtables:
		count = 0
		for method in l_vtable.methods:
			name = get_name( 0, method )
			parents = graph.Get_Parents( name )
			print "Node: " + name
			print "Parents: " + parents.__repr__()
			if len( parents ) == 1:
				set_name( method, "%s_method_%d" % (parents[0], count), 0 )
				print "Setting name of %lx to %s_method_%d" % (method, parents[0], count)
			count = count + 1
	
	return vtables
		

#get_retval_summaries_transitive()
#get_return_value_summary( get_screen_ea())


