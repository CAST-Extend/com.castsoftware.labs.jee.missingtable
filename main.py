import cast.analysers.jee
import cast.analysers.log
import re
import plyj.model
import cast.analysers.internal.knowledge_base
import cast.analysers.filter as filter
from symbol import if_stmt
import sys

class JavaTableExtension(cast.analysers.jee.Extension):

    parser = None
    project = None
    tables = {}
    procs = {}

    def start_analysis(self,options):
        options.add_parameterization("java.sql.Statement.executeUpdate(java.lang.String,java.lang.String[]", [1], self.parseSQL)
        options.add_parameterization("java.sql.Statement.addBatch(java.lang.String)", [1], self.parseSQL)
        options.add_parameterization("java.sql.Statement.execute(java.lang.String)", [1], self.parseSQL)
        options.add_parameterization("java.sql.Statement.execute(java.lang.String,int)", [1], self.parseSQL)
        options.add_parameterization("java.sql.Statement.execute(java.lang.String,int[])", [1], self.parseSQL)
        options.add_parameterization("java.sql.Statement.executeQuery(java.lang.String)", [1], self.parseSQL)
        options.add_parameterization("java.sql.Statement.executeUpdate(java.lang.String)", [1], self.parseSQL)
        options.add_parameterization("java.sql.Statement.executeUpdate(java.lang.String,int)", [1], self.parseSQL)
        options.add_parameterization("java.sql.Statement.executeUpdate(java.lang.String,int[])", [1], self.parseSQL)
        options.add_parameterization("java.sql.Connection.nativeSQL(java.lang.String)", [1], self.parseSQL)
        options.add_parameterization("java.sql.Connection.prepareCall(java.lang.String)", [1], self.parseSQL)
        options.add_parameterization("java.sql.Connection.prepareCall(java.lang.String,int,int)", [1], self.parseSQL)
        options.add_parameterization("java.sql.Connection.prepareCall(java.lang.String,int,int,int)", [1], self.parseSQL)
        options.add_parameterization("java.sql.Connection.prepareStatement(java.lang.String)", [1], self.parseSQL)
        options.add_parameterization("java.sql.Connection.prepareStatement(java.lang.String,int)", [1], self.parseSQL)
        options.add_parameterization("java.sql.Connection.prepareStatement(java.lang.String,int[])", [1], self.parseSQL)
        options.add_parameterization("java.sql.Connection.prepareStatement(java.lang.String,int,int)", [1], self.parseSQL)
        options.add_parameterization("java.sql.Connection.prepareStatement(java.lang.String,int,int,int)", [1], self.parseSQL)

        # patch for import bug...
        sys.path.insert(0,self.get_plugin().get_plugin_directory())
        
        
        
    def start_type(self, _type):
        ###cast.analysers.log.debug("Found Type " + str(_type.get_fullname()))   
        if self.parser is None:
            self.parser = self.create_parser()
        for position in _type.get_positions():
            path = position.get_file().get_path()
            if not path.endswith('.class'):                    
                tree = self.parser.parse_file(path)
                for type_declarations in tree.type_declarations:
                    if str(type_declarations) != 'EmptyDeclaration()':
                        for modifier in type_declarations.modifiers:
                            if hasattr(modifier, 'name'):
                                if modifier.name.value == "Table":
                                    for member in modifier.members:
                                        if hasattr(member, 'name') and hasattr(member.name, 'value') and member.name.value == "name":
                                            if hasattr(member, 'value') and hasattr(member.value, 'value'):
                                                # search all tables or views with table_name as name
                                                table_annotation_value=str(member.value.value.strip('"'))
                                                tables = cast.analysers.external_link.find_objects(table_annotation_value, filter.tables_or_views)
                                                if len(tables) == 0:
                                                    linktype="useLink"
                                                    self.create_link_to_unknown_table(_type, table_annotation_value, linktype, None)
                                                    cast.analysers.log.debug("Create Unknown Table from annotation:" + table_annotation_value)
                                                  
         
    def parseSQL(self, values, caller, line, column):
        import sqlparse
        cast.analysers.log.debug('-----------------------------------------------------------------------------------------')
        cast.analysers.log.debug('-----------------------------------------------------------------------------------------')
        cast.analysers.log.debug("Caller: "+str(caller))
        cast.analysers.log.debug(str(values.items()))
        caller_file=caller.get_position().get_file()
        begin_re=re.compile('[ \t]*begin[ \t]*')
        end_re=re.compile('[ \t]*end[ \t]*\;?')
        linkbookmark = cast.analysers.Bookmark(caller_file,line,column,line,-1)
        for key, value in values.items():
            cast.analysers.log.debug("* InfEng query[x]: "+str(value))
            for query in value:
                for request in sqlparse.split(query):
                    cast.analysers.log.debug('-----------------------------------------------------------------------------------------')
                    # Application specific cleanup preventing proper parsing
                    request=request.strip("{").strip("}")
                    request=begin_re.sub('',request)
                    request=end_re.sub('',request)
                    
                    # Exit if query is empty
                    if not str(request):
                        cast.analysers.log.debug('Empty Query String found: skipping...')
                        continue
                                        
                    cast.analysers.log.debug("** sqlparse.split[x]: "+str(request))
                    caller_fname=caller.get_fullname()                                                                                                                         
                    cast.analysers.log.debug("Found query in "+caller_fname+": " + request)
                    
                    querytype = extract_querytype(request)
                    
                    if querytype == "SELECT":
                        linktype="useSelectLink"
                    elif querytype == "INSERT":
                        linktype="useInsertLink"
                    elif querytype == "UPDATE":
                        linktype="useUpdateLink"
                    elif querytype == "DELETE":
                        linktype="useDeleteLink"
                    elif querytype == "CALL":
                        linktype="callLink"
                    else:                        
                        querytype="UNKNOWN"
                    
                    cast.analysers.log.debug("Query Type (parseSQL): "+querytype)
                    
                    if querytype=="CALL":                        
                        # Process call statement
                        p=re.compile('[ \t\(]+')
                        # Extract proc name
                        procname=p.sub(' ',request.lstrip()).split(' ')[1]

                        if procname.find('.') > 1:
                            # Strip schema prefix
                            procname=procname[procname.find('.')+1:]

                        existing_procs = cast.analysers.external_link.find_objects(procname, 'APM SQL Procedures')
                        if len(existing_procs) == 0:
                            self.create_link_to_unknown_procedure(caller, procname, linktype, linkbookmark)
                                
                    if querytype in ["INSERT","SELECT","UPDATE","DELETE"]:
                        tables = extract_tables_from_query(request,querytype)                        
                        cast.analysers.log.debug(querytype+" on Tables "+ str(tables))                                                            
                        for table in tables:                            
                            table=table.upper()
                            if table in ['DUAL']:
                                continue                             
                            ###cast.analysers.log.debug("Searching table:" + str(table))                            
                            existing_tables = cast.analysers.external_link.find_objects(str(table), filter.tables_or_views)
                            if len(existing_tables) == 0:
                                unktblname=str(table)                                
                                self.create_link_to_unknown_table(caller, unktblname, linktype, linkbookmark)                                                     
    
    def create_parser(self):
        """
        create and return a new plyj parser.
        """
        d = self.get_plugin().get_plugin_directory()
        import sys
        sys.path.append(d)
        
        import plyj.parser as plyj
        parser = plyj.Parser()
        
        sys.path.pop()

        return parser
    
    def create_link_to_unknown_table(self, caller, unktblname, linktype, linkbookmark):
        unknown_table = None
        if unktblname not in self.tables:
            # Unknown Table creation                          
            unknown_table = cast.analysers.CustomObject()                    
            unknown_table.set_name(unktblname)
            unknown_table.set_fullname(unktblname)
            unknown_table.set_type("UnknownTable")
            unknown_table.set_parent(caller.get_project())
            unknown_table.save()
            self.tables[unktblname] = unknown_table                
        else:
            # Unknown Table was already created. Retrieve the existing one
            unknown_table = self.tables[unktblname] 
            
        if linkbookmark == None:
            cast.analysers.create_link(linktype, caller, unknown_table)
        else:
            cast.analysers.create_link(linktype, caller, unknown_table, linkbookmark)
            
        
    def create_link_to_unknown_procedure(self, caller, unkprcname, linktype, linkbookmark):
        unknown_proc = None
        if unkprcname not in self.procs:
            # Unknown Procedure creation                          
            unknown_proc = cast.analysers.CustomObject()                    
            unknown_proc.set_name(unkprcname)
            unknown_proc.set_fullname(unkprcname)
            unknown_proc.set_type("UnknownProcedure")
            unknown_proc.set_parent(caller.get_project())
            unknown_proc.save()
            self.procs[unkprcname] = unknown_proc                
        else:
            # Unknown Procedure was already created. Retrieve the existing one
            unknown_proc = self.procs[unkprcname] 
            
        if linkbookmark == None:    
            cast.analysers.create_link(linktype, caller, unknown_proc)
        else:        
            cast.analysers.create_link(linktype, caller, unknown_proc, linkbookmark)
          

def extract_tables_from_query(query, querytype):
    import sqlparse
    stmtobj=sqlparse.parse(query)[0]
    cast.analysers.log.debug(" >>>>> stmtobj.tokens: "+str(stmtobj.tokens))
    if querytype in ["SELECT","DELETE"]:
        stream = extract_from_part(stmtobj)        
        return list(extract_table_identifiers(stream, querytype))
        
    if querytype == "INSERT":
        stream = extract_into_part(stmtobj)
        return list(extract_table_identifiers(stream, querytype))
    
    if querytype == "UPDATE":
        stream = extract_update_part(stmtobj)
        return list(extract_table_identifiers(stream, querytype))    
    

def extract_from_part(parsed):
    from sqlparse.tokens import Keyword

    from_seen = False    
    for item in parsed.tokens:
        if from_seen:
            if is_subselect(item):
                for x in extract_from_part(item):
                    yield x
            elif item.ttype is Keyword:
                raise StopIteration
            else:
                yield item
        elif item.ttype is Keyword and item.value.upper() == 'FROM':
            from_seen = True
            
def extract_into_part(parsed): 
    pt=parsed.tokens
    # INTO clause of INSERT statement:
    yield pt[4]

def extract_update_part(parsed): 
    pt=parsed.tokens
    # UPDATE clause:
    yield pt[2]
                       

def extract_table_identifiers(token_stream,querytype):
    from sqlparse.sql import IdentifierList, Identifier
    from sqlparse.tokens import Keyword

    for item in token_stream:
        cast.analysers.log.debug("** item:"+ str(item))
        if isinstance(item, IdentifierList):
            for identifier in item.get_identifiers():                
                tblstr=get_table_name(identifier)
                cast.analysers.log.debug("*********** CASE IdentifierList: "+tblstr)
                yield tblstr
        elif isinstance(item, Identifier):
            tblstr=get_table_name(item)
            cast.analysers.log.debug("*********** CASE Identifier: "+str(item)+" | "+tblstr)
            yield tblstr
        # It's a bug to check for Keyword here, but in the example
        # above some tables names are identified as keywords...
        elif item.ttype is Keyword:
            cast.analysers.log.debug("*********** CASE Keyword: "+str(item))
            yield get_table_name(item.value)
        else:            
            cast.analysers.log.debug("*********** CASE UNMNGT: "+str(item))
            if querytype=="INSERT":
                tablestr=str(item).lstrip()
                tablestr=tablestr[:tablestr.find(" ")]
                if "(" in tablestr:
                    tablestr=tablestr[:tablestr.find("(")].rstrip()
                yield tablestr            

def is_subselect(parsed):
    from sqlparse.tokens import DML

    if not parsed.is_group():
        return False
    for item in parsed.tokens:
        if item.ttype is DML and item.value.upper() == 'SELECT':
            return True
    return False

def get_table_name(identifier):
    tblstr=str(identifier).split(' ')   # deals with the "from TABLE ALIAS" syntax to extract table name only
    tblstr=tblstr[0]                
    if len(tblstr.split('.'))>1:        # deals with "SCHEMA.TABLE" naming syntax to remove "SCHEMA."
        tblstr=tblstr.split('.')
        tblstr=tblstr[1]
    return tblstr


def extract_querytype(query):
    import sqlparse

    #stream = extract_from_part(sqlparse.parse(query)[0])
    cast.analysers.log.debug("Query type (extract_querytype): "+str(sqlparse.parse(query)))
    query_type=sqlparse.parse(query)[0].get_type()
    cast.analysers.log.debug("Query type (extract_querytype): "+sqlparse.parse(query)[0].get_type())
    if query_type == "UNKNOWN":
        # Check if it is a procedure CALL using a RegExp
        p=re.compile('[ \t]*call[ \t\(]+.*')
        if p.match(query.lower()):
            query_type="CALL"            
    return query_type
