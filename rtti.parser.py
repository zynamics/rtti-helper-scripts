from x86_RE_lib import *
import sets

class TypeDescriptor:
    def __init__( self, RTTI, address ):
        self.address = address
        self.name = get_string( address + 8 )
    def __repr__( self ):
        return "TypeDescriptor(%lx,%s)" % (self.address, self.name)

class CompleteObjectLocator:
    def __init__( self, RTTI, address ):
        print "[!] Dealing with CompleteObjectLocator at %lx" % address 
        self.address = address
        self.signature = Dword(address)
        self.offset = Dword(address+4)
        self.cdoffset = Dword(address+8)
        self.type = TypeDescriptor(RTTI, Dword(address+12))
        self.hierarchy = RTTI.load_hierarchy_descriptor( Dword(address+16))

class HierarchyDescriptor:
    def __init__( self, RTTI, address ):
        self.address = address
        self.signature = Dword( address )
        self.attributes = Dword( address + 4 )
        self.number_of_bases = Dword( address + 8 )
        if self.number_of_bases > 20000:
          raise "Attempting to parse %lx as Hierarchy Descriptor, but it isn't!" % self.address
    def __load_full__( self, RTTI ):
        print "[!] dealing with the hierarchy descriptor at %lx" % self.address
        print "[!] Number of bases is %d" % self.number_of_bases
        self.bases = [ RTTI.load_base_class_descriptor( Dword( Dword( self.address+12 ) + i*4 )) for i in range(0, self.number_of_bases) ]
        #print self.bases
        
    def get_derivation_poset( self, name ):
        result = {}
        result[ name ] = sets.Set()
        result[ name ].update( [ base.type.name for base in self.bases ] )
        for baseclass in self.bases:
            if baseclass.type.name != name:
                tempdict = baseclass.hierarchy_descriptor.get_derivation_poset( baseclass.type.name )
                # Now join the sets
                for classname in tempdict.keys():
                    if result.has_key( classname ):
                        result[ classname ].update( tempdict[classname] )
                    else:
                        result[ classname ] = tempdict[classname]
        return result
    def __repr__(self):
        return "HierarchyDescriptor(%lx)" % self.address

class BaseClassDescriptor:
    def __init__( self, RTTI, address ):
        self.address = address
        self.type = TypeDescriptor( RTTI, Dword(address))
        self.num_contained_bases = Dword( address + 4 )
        self.mdisp = Dword( address + 8 ) 
        self.pdisp = Dword( address + 12 )
        self.vdisp = Dword( address + 16 )
        self.attributes = Dword( address + 20 )
        
    def __load_full__( self, RTTI ):
        print "[!] Loading hierarchy descriptor for base class descriptor at %lx" % self.address
        self.hierarchy_descriptor = RTTI.load_hierarchy_descriptor( Dword( self.address+24))
        
    def __repr__( self ):
        s =     "BaseClassDescriptor(0x%lx)[%s]" % (self.address, self.type.name)
        return s

class VFTable:
    def __init__( self, RTTI, address ):
        self.address = address
        self.complete_object_locator = CompleteObjectLocator( RTTI, Dword( address - 4 ))
        # now scan forwards until no more code is found
        self.methods = []
        while isCode( getFlags( Dword(address) ) ):
            self.methods.append( Dword( address ))
            address = address + 4
        self.end_address = address
    
    def get_methods( self ):
      return self.methods
      
    def get_parent_class_and_offset( self, derivation_hasse_diagram, derivedclass ):
      """
        Returns the name of the parent class this vtable "comes from", if there are any
      """
      lastbase = ""
      vtable_offset = vtable.complete_object_locator.offset 
      parents = [ (base.mdisp, base) for base in vtable.complete_object_locator.hierarchy.bases \
        if base.type.name in self.derivation_hasse_diagram[ derivedclass ]]
      right_offset = max( [ x[0] for x in parents if vtable_offset > x[0]] )
      right_parent = [ x for x in parents if x[0] == right_offset ][0]
      vtable_in_parent = vtable_offset-x[0]
      return (vtable_in_parent, right_parent[1])
      
    def __repr__( self ):
        s =   "vtable at %lx with %d methods" % (self.address, len(self.methods))
        return s
    

class RTTI:
    def __init__( self, typeinfo_vtable ):
        self.base_class_descriptors = {}            # A dictionary mapping address->base class descriptors
        self.hierarchy_descriptors_by_address = {}  # A dictionary mapping address->hierarchy descriptors
        print "[!] scanning for vtables..."
        self.vtables_by_name = self.__scan_for_vtables_from_typeinfo( typeinfo_vtable ) # A dictionary mapping name->list of vtables
        print "[!] creating inheritance-poset..."
        self.derivation_poset = self.__create_derivation_poset( self.vtables_by_name )
        print "[!] creating inheritance hasse diagram..."
        self.derivation_hasse_diagram = self.__create_hasse_diagram( self.derivation_poset )
        print "[!] creating UML diagram %s.gml" % get_root_filename()
        self.create_UML_style_diagram( "c:\\%s.gml" % get_root_filename() )
        print "[!] Renaming vtables ... " 
        self.__rename_vtables( self.vtables_by_name )
        print "[!] Renaming class methods ..." 
        self.__rename_class_methods( self.vtables_by_name, self.derivation_hasse_diagram )
        print "[!] Done"
        
        
    def load_base_class_descriptor( self, address ):
        if self.base_class_descriptors.has_key( address ):
            return self.base_class_descriptors[ address ]
        else:
            base = BaseClassDescriptor( self, address )
            self.base_class_descriptors[ address ] = base
            base.__load_full__( self )
            return base
    
    def load_hierarchy_descriptor( self, address ):
        if self.hierarchy_descriptors_by_address.has_key( address ):
            return self.hierarchy_descriptors_by_address[ address ]
        else:
            hierarchy = HierarchyDescriptor( self, address )
            self.hierarchy_descriptors_by_address[ address ] = hierarchy
            hierarchy.__load_full__( self )
            return hierarchy

    def __create_derivation_poset( self, name_vtable_dict ):
        """
            The derivation poset is simply a dictionary mapping class names to sets of class names
            
        """
        derivation_poset = {}
        for classname in name_vtable_dict.keys():
            for vtable in name_vtable_dict[ classname ]:
                temp_dict = vtable.complete_object_locator.hierarchy.get_derivation_poset( classname )
                for name in temp_dict.keys():
                    if derivation_poset.has_key( name ):
                        derivation_poset[ name ].update( temp_dict[ name ])
                    else:
                        derivation_poset[ name ] = temp_dict[ name ] 
        return derivation_poset                    
      
    def __invert_edges( self, mapping ):
        edges = [ (k,v) for k in mapping.keys() for v in mapping[k] ]
        result_dictionary = {}
        for v, k in edges:
            if result_dictionary.has_key(k):
                result_dictionary.add( v )
            else:
                result_dictionary[k] = set([v])
        return result_dictionary
    
    def __assign_levels( self, hierarchy_diagram ):
        roots = [ n for n in hierarchy_diagram.get_nodes().keys() if len(hierarchy_diagram.Get_Parents(n)) == 0 ]
        name_to_hierarchy_index = {}
        index_counter = 0
        worklist = roots
        while len(worklist) > 0:
            for n in worklist:
                name_to_hierarchy_index[n] = index_counter
            index_counter = index_counter + 1
            new_worklists = [ hierarchy_diagram.Get_Children(n) for n in worklist ]
            new_worklist = set()
            for wk in new_worklists:
                new_worklist.update( wk )
            worklist = new_worklist
        return name_to_hierarchy_index
    
    def __create_function_to_class_map( self, name_to_vtables ):
        result = {}
        # Create a dictionary mapping each method to the set of submethods
        methods_to_process = set()
        full_method_count = 0
        for vtables in name_to_vtables.values():
            for vtable in vtables:
                methods_to_process.update( vtable.get_methods())
                full_method_count = full_method_count + len( vtable.get_methods())
        total_methods = len(methods_to_process)
        
        print "[!] Calculating submethods for %d methods..." % total_methods 
        methods_to_submethods = {}
        count = 0
        for m in methods_to_process:
            methods_to_submethods[ m ] = set(get_subfuncs_with_same_thisptr_rec(m))
            count = count + 1
            print "[!] Done with %d/%d" % (count, total_methods)
        
        method_count = 0
        for name, vtables in name_to_vtables.items():
            for vtable in vtables:
                for method in vtable.get_methods():
                    print "[!] Processing method %d out of %d" % (method_count, full_method_count)
                    method_count = method_count+1
                    if result.has_key( method ):
                        result[method].add( name )
                    else:
                        result[method] = set( [name] )
                    print "%lx: tracking into function" % method
                    extra_subfuncs = methods_to_submethods[ method ]
                    print "Got %d subfuncs..." % len(extra_subfuncs)
                    for m in extra_subfuncs:
                        if result.has_key( m ):
                            result[m].add(name)
                        else:
                            result[m] = set([name])
        return result

    def __rename_class_methods( self, name_to_vtables, name_to_parent_map ):
        hierarchy_diagram = self.create_UML_style_diagram()
        levels = self.__assign_levels( hierarchy_diagram )
        function_to_classes = self.__create_function_to_class_map( name_to_vtables )
        for function, classes in function_to_classes.items():
            commentstring = ""
            levels_for_classes = [ (levels[c], c) for c in classes ]
            min_level = min( [levels[c] for c in classes ] )
            minimum_classes = [ c for c in classes if levels[c] == min_level ]
            if len( minimum_classes ) > 1:
                for classname in classes:
                    commentstring = commentstring + "%d - %s\n" % (levels[classname], classname)
                MakeComm( function, commentstring )
                print "%lx: Warning -- ambiguous function assignment" % function
            else:
                new_name = minimum_classes[0] + "::" + Name(function)
                MakeName( function, new_name )
                print "Calling create_struct_from_ea for %lx, ecx, %s" % (function, minimum_classes[0])
                create_struct_from_ea( function, "ecx", minimum_classes[0])
      
    def __rename_vtables( self, name_to_vtables ):
        for name, vtables in name_to_vtables.items():
            for vtable in vtables:
                MakeName( vtable.address, "%s_vftable_%d" % (name, vtable.complete_object_locator.offset ))
    
    def __create_hasse_diagram( self, poset ):
        # Begin by duplicating the poset, but remove that X is derived from X
        tempdict = {}
        for key, derived_set in poset.items():
            new_set = sets.Set()
            new_set.update( derived_set )
            new_set.remove( key )
            tempdict[ key ] = new_set
        # Ok. Now iterate over all items and remove their parents
        for key in tempdict.keys():
            remove_set = sets.Set()
            for base_class in tempdict[ key ]:
                remove_set.update( tempdict[ base_class ] )
            tempdict[ key ] = tempdict[ key ].difference( remove_set )
        return tempdict
        
    def __scan_for_vtables_from_typeinfo( self, typeinfo_vtable ):
        """    Attempts to find all vtable's in an RTTI-enabled executable by walking
            backwards from the typeinfo vtable.

            Returns a dictionary mapping names to lists of vtables
        """
        result_dict = {}
        vtable_starts = []
        # 
        #   What follows is rather ugly hackish code that attempts
        #   to enumerate all vtables through references to the typeinfo
        #   vtable
        print typeinfo_vtable
        print typeinfo_vtable.__class__
        for reference in get_drefs_to( typeinfo_vtable ):
            name = get_string( reference + 8 )
            #name = self.__win32_demangle_CPP_symbol_name( name )
            if len( name ) <= 4:
                continue
            for reference2 in get_drefs_to( reference ):
                # We want only non-reffed ones
                if len( get_drefs_to( reference2 )) != 0:
                    continue
                estimated_locator = reference2-12
                last_refs = get_drefs_to( estimated_locator ) 
                for ref in last_refs:
                    # A vtable needs to be referenced, itself !
                    if len( get_drefs_to( ref+4 )) == 0:
                        continue
                    if len( get_drefs_from( ref + 4 )) == 0:
                        continue
                    if isCode( getFlags( get_drefs_from( ref+4)[0])):
                        vtable_starts.append( (name, ref+4) )
        for name, start in vtable_starts:
            #print "%lx: Adding vtable for %s" % (start, name)
            if result_dict.has_key( name ):
                result_dict[ name ].append( VFTable(  self, start ))
            else:
                result_dict[ name ] = [ VFTable( self, start) ]
        return result_dict
    
    def create_UML_style_diagram( self, filename="" ):
        diagram = vcg_Graph.vcgGraph()
        complete_set = sets.Set()
        hasse = self.derivation_hasse_diagram
        complete_set.update( hasse.keys())
        for values in hasse.values():
            complete_set.update( values )
        # Ok, we have all nodes in the graph
        for name in complete_set:
            node = diagram.Add_Node( name )
            #
            #   Now we have to produce a useful label
            #
            label = self.__create_UML_style_label( name, hasse[ name ], self.vtables_by_name )
            node.set_attribute( 'label', '"'+label+'"' )
        for edges in hasse.items():
            for target in edges[1]:
                diagram.Add_Link( target, edges[0] )
        #outfile = file(filename, "wt")
        #outfile.write( diagram.gen_VCG_string() )
        #outfile.close()
        if filename != "":
          outfile = file(filename + ".gml", "wt" )
          outfile.write( diagram.make_GML_output() )
          outfile.close()
        return diagram
    
    def __create_UML_style_label( self, derivedclass, baseclasses, type_to_vtables ):
        label = ""
        
        label = label+ "%s" % self.__win32_demangle_CPP_symbol_name( derivedclass )
        if not type_to_vtables.has_key( derivedclass ):
            return label
        vtables = type_to_vtables[ derivedclass ]
        label = label+ "\n    %d vtables, %d base classes" % (len(vtables), len(self.derivation_hasse_diagram[derivedclass]))
        # Now construct the rest of the label:
        label_list = []
        
        for vtable in vtables:
            label_list.append( (vtable.complete_object_locator.offset, 1, "\n        +%lx " % vtable.complete_object_locator.offset + vtable.__repr__() ))
        for base in vtable.complete_object_locator.hierarchy.bases:
            if base.type.name in self.derivation_hasse_diagram[ derivedclass ]:
                label_list.append( (base.mdisp, 0, "\n    +%lx Base class %s" % (base.mdisp, self.__win32_demangle_CPP_symbol_name( base.type.name ))))
        label_list.sort()
        for l in label_list:
            label = label+l[2]
        return label
    
    def __win32_demangle_CPP_symbol_name( self, symbolname ):
        """
            Uses the DBHGHLP.DLL to demangle a symbol name
        
            We use ctypes to call the following API function
            DWORD WINAPI UnDecorateSymbolName(
            __in   PCTSTR DecoratedName,
            __out  PTSTR UnDecoratedName,
            __in   DWORD UndecoratedLength,
            __in   DWORD Flags);
        
            The WinAPI CANNOT decode classnames (idiots!), it
            seems to only work for method names. Highly annoying.
        """
        import ctypes
        symbolname = symbolname[1:]
        dbghelp = ctypes.cdll.LoadLibrary("dbghelp.dll")
        demangledname = ctypes.c_char_p( ' ' * 10000 )
        prototype= ctypes.WINFUNCTYPE( ctypes.c_int, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_int, ctypes.c_int )
        UnDecorateSymbolName = prototype( ( "UnDecorateSymbolName", dbghelp ) )
        res = UnDecorateSymbolName( ctypes.c_char_p( symbolname ),
            demangledname ,
            ctypes.c_int( 10000 ),
            ctypes.c_int( 0xFFFF ))  # flags
        print "%d" % res
        return demangledname.value.replace('&', '&amp;')


#__win32_demangle_CPP_symbol_name( ".?AVVThreadedHostnameResolver@@")

#rtti = RTTI( 0x004F4314 )

dr = get_drefs_to( LocByName( "??_Etype_info@@UAEPAXI@Z_2" ))#"??_Etype_info@@UAEPAXI@Z"))
if len(dr) == 0:
	dr = get_drefs_to( LocByName( "??_Etype_info@@UAEPAXI@Z" ))#"??_Etype_info@@UAEPAXI@Z"))
	
if len(dr) > 0:
  addr = dr[0]
  print "[!] Parsing RTTI for %s" % get_root_filename()
  rtti = RTTI( addr )
else:
  print "[!] No RTTI info for %s found" % get_root_filename()
#Exit(0)
#for i in rtti.derivation_poset.items():
#    print "%s derives from %s" % (i[0], i[1])
#hierarchy = create_hierarchy( res )
#generate_UML_style_diagram( hierarchy, res, "c:\\awhlogon.gml" )
#generate_dot_diagram( hierarchy, "" )

RTTI( 0x10023f24)