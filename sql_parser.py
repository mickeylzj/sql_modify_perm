# sql_parser.py

from collections import deque
from typing import Dict, Set, Optional
import sqlglot
from sqlglot import expressions as exp
from loguru import logger

class SQLTableExtractor:
    """SQL表信息提取器"""
    
    def __init__(self, system_tables: Set[str], dialect: str = 'mysql'):
        self.system_tables = system_tables
        self.dialect = dialect
        self.sql_keywords = {
            'SELECT', 'FROM', 'WHERE', 'JOIN', 'LEFT', 'RIGHT', 'INNER', 'OUTER',
            'ON', 'AND', 'OR', 'GROUP', 'ORDER', 'BY', 'HAVING', 'LIMIT',
            'UNION', 'ALL', 'DISTINCT', 'AS', 'CAST', 'CASE', 'WHEN', 'THEN',
            'ELSE', 'END', 'NULL', 'TRUE', 'FALSE', 'IS', 'NOT', 'IN', 'EXISTS'
        }
    
    #  TODO： 如果sql中的表没有schema，函数返回的内容是什么？可以多举几个例子说明
    #  TODO： 如果sql中的表没有alias，函数返回的内容是什么？可以多举几个例子说明
    def extract_table_info_with_schema(self, sql: str) -> Dict[str, str]:
        """
        提取表信息，支持schema.table格式
        返回格式: {'schema.table_name': 'alias'}
        """
        try:
            ast = sqlglot.parse_one(sql, dialect=self.dialect)
            tables = {}
            
            logger.info(f"开始分析AST: {type(ast).__name__}")
            
            # 使用BFS遍历AST
            tables_found = self._traverse_ast_for_tables(ast)
            
            # 过滤系统表
            for table_info in tables_found:
                if self._is_system_table(table_info['full_name']):
                    tables[table_info['full_name']] = table_info['alias']
                    logger.info(f"发现系统表: {table_info['full_name']} -> {table_info['alias']}")
            
            logger.info(f"表信息提取完成: {tables}")
            return tables
            
        except Exception as e:
            logger.error(f"AST分析失败: {e}")
            return self._extract_table_info_fallback(sql)
    
    # TODO： 这个函数的返回值 list[str] ? 返回函数签名备注

    def _traverse_ast_for_tables(self, ast: exp.Expression) -> list:
        """使用BFS遍历AST寻找表节点"""
        tables = []
        to_visit = deque([ast])
        visited = set()
        
        while to_visit:
            node = to_visit.popleft()
            node_id = id(node)
            
            if node_id in visited:
                continue
            visited.add(node_id)
            
            # 处理Table节点
            if isinstance(node, exp.Table):
                table_info = self._parse_table_node(node)
                if table_info:
                    tables.append(table_info)
            
            # 添加子节点到队列
            self._add_children_to_queue(node, to_visit)
        
        return tables
    
    def _parse_table_node(self, table_node: exp.Table) -> Optional[Dict[str, str]]:
        """解析表节点，提取schema和表名"""
        try:
            # 提取表名
            table_name = self._extract_table_name(table_node)
            if not table_name or table_name.upper() in self.sql_keywords:
                return None
            
            # 提取schema名
            schema_name = self._extract_schema_name(table_node)
            
            # 构建完整表名
            full_name = f"{schema_name}.{table_name}" if schema_name else table_name
            
            # 提取别名
            alias = self._extract_alias(table_node, table_name)
            
            return {
                'schema': schema_name,
                'table': table_name,
                'full_name': full_name.lower(),
                'alias': alias.lower()
            }
            
        except Exception as e:
            logger.error(f"解析表节点失败: {e}")
            return None
    
    def _extract_table_name(self, table_node: exp.Table) -> Optional[str]:
        """提取表名"""
        if hasattr(table_node, 'this'):
            if hasattr(table_node.this, 'this'):
                return str(table_node.this.this)
            elif hasattr(table_node.this, 'name'):
                return str(table_node.this.name)
            else:
                return str(table_node.this)
        elif hasattr(table_node, 'name'):
            return str(table_node.name)
        else:
            return str(table_node)
    
    def _extract_schema_name(self, table_node: exp.Table) -> Optional[str]:
        """提取schema名（数据库名）"""
        if hasattr(table_node, 'db') and table_node.db:
            return str(table_node.db)
        
        # 检查table.this.db路径
        if hasattr(table_node, 'this') and hasattr(table_node.this, 'db') and table_node.this.db:
            return str(table_node.this.db)
        
        return None
    
    def _extract_alias(self, table_node: exp.Table, default_alias: str) -> str:
        """提取别名"""
        if hasattr(table_node, 'alias') and table_node.alias:
            if hasattr(table_node.alias, 'this'):
                return str(table_node.alias.this)
            else:
                return str(table_node.alias)
        return default_alias
    
    def _add_children_to_queue(self, node: exp.Expression, queue: deque):
        """将子节点添加到队列"""
        if hasattr(node, 'args') and isinstance(node.args, dict):
            for key, value in node.args.items():
                if isinstance(value, exp.Expression):
                    queue.append(value)
                elif isinstance(value, list):
                    for item in value:
                        if isinstance(item, exp.Expression):
                            queue.append(item)
        
        # 处理其他可能包含表达式的属性
        for attr_name in ['this', 'expression']:
            if hasattr(node, attr_name):
                attr_value = getattr(node, attr_name)
                if isinstance(attr_value, exp.Expression):
                    queue.append(attr_value)
    
    def _is_system_table(self, full_table_name: str) -> bool:
        """检查是否为系统表，支持schema.table格式"""
        full_name_lower = full_table_name.lower()
        
        # 直接匹配完整名称
        if full_name_lower in self.system_tables:
            return True
        
        # 提取表名部分进行匹配
        table_name = full_name_lower.split('.')[-1]  # 取最后一部分作为表名
        if table_name in self.system_tables:
            return True
        
        # 模糊匹配
        for sys_table in self.system_tables:
            if sys_table in table_name or sys_table in full_name_lower:
                return True
        
        return False
    
    def _extract_table_info_fallback(self, sql: str) -> Dict[str, str]:
        import re
        
        tables = {}
        
        # 匹配 schema.table 格式
        schema_table_pattern = r'\b(\w+\.\w+)(?:\s+(?:as\s+)?(\w+))?\b'
        matches = re.finditer(schema_table_pattern, sql, re.IGNORECASE)
        
        for match in matches:
            full_name = match.group(1).lower()
            alias = match.group(2).lower() if match.group(2) else full_name.split('.')[-1]
            
            if self._is_system_table(full_name):
                tables[full_name] = alias
        
        # 匹配普通表名
        table_pattern = r'(?:FROM|JOIN)\s+(\w+)(?:\s+(?:as\s+)?(\w+))?'
        matches = re.finditer(table_pattern, sql, re.IGNORECASE)
        
        for match in matches:
            table_name = match.group(1).lower()
            alias = match.group(2).lower() if match.group(2) else table_name
            
            if self._is_system_table(table_name) and table_name not in tables:
                tables[table_name] = alias
        
        return tables

# TODO: 添加SQL改写放到sql_parser.py中
class SQLRewriteEngine:
    """SQL改写"""
    
    def __init__(self, dialect: str = 'mysql'):
        self.dialect = dialect
        self.sql_keywords = {
            'SELECT', 'FROM', 'WHERE', 'JOIN', 'LEFT', 'RIGHT', 'INNER', 'OUTER',
            'ON', 'AND', 'OR', 'GROUP', 'ORDER', 'BY', 'HAVING', 'LIMIT',
            'UNION', 'ALL', 'DISTINCT', 'AS', 'CAST', 'CASE', 'WHEN', 'THEN',
            'ELSE', 'END', 'NULL', 'TRUE', 'FALSE', 'IS', 'NOT', 'IN', 'EXISTS'
        }
    
    def validate_sql_security(self, sql: str) -> Dict:
        """SQL安全性验证"""
        security_report = {
            'is_safe': True,
            'warnings': [],
            'risks': [],
            'blocked_operations': []
        }
        
        ast = sqlglot.parse_one(sql, dialect=self.dialect)
        
        # 检查危险操作
        dangerous_checks = [
            (exp.Drop, "DROP操作"),
            (exp.Delete, "DELETE操作"),
            (exp.Update, "UPDATE操作"),
            (exp.Insert, "INSERT操作"),
            (exp.Alter, "ALTER操作"),
            (exp.Create, "CREATE操作")
        ]
        
        for op_type, op_name in dangerous_checks:
            dangerous_ops = list(ast.find_all(op_type))
            if dangerous_ops:
                security_report['is_safe'] = False
                security_report['blocked_operations'].append(f"{op_name} (发现 {len(dangerous_ops)} 个)")
        
        # 检查TRUNCATE
        if 'TRUNCATE' in sql.upper():
            security_report['is_safe'] = False
            security_report['blocked_operations'].append("TRUNCATE操作")
        
        # 检查危险函数
        risky_functions = ['LOAD_FILE', 'INTO OUTFILE', 'SYSTEM', 'EXEC', 'SHELL', 'EVAL']
        all_functions = list(ast.find_all((exp.Func, exp.Anonymous)))
        
        for func in all_functions:
            func_name = func.sql().upper() if hasattr(func, 'sql') else str(func).upper()
            for risky in risky_functions:
                if risky in func_name:
                    security_report['risks'].append(f"使用了潜在危险函数: {func_name}")
                    break
        
        logger.info(f"SQL安全检查完成: {'安全' if security_report['is_safe'] else '存在风险'}")
        return security_report
    
    def modify_sql_with_permissions(self, sql: str, user_permissions: Dict, table_info: Dict) -> str:
        """SQL权限改写 """
        if not table_info:
            logger.info("无需权限改写，返回原SQL")
            return sql
        
        logger.info(f"开始SQL权限改写: 涉及表={list(table_info.keys())}")
        
        # 检查表访问权限
        for table_name in table_info.keys():
            if table_name in user_permissions:
                table_perm = user_permissions[table_name]
                if not table_perm['access']:
                    raise PermissionError(f"没有访问表 {table_name} 的权限")
        
        # 收集需要过滤的表
        cte_clauses = []
        table_replacements = {}
        
        for table_name, alias in table_info.items():
            if table_name in user_permissions:
                table_perm = user_permissions[table_name]
                if table_perm['row_filter']:
                    # 替换占位符
                    modified_filter = self._replace_placeholders(
                        table_perm['row_filter'], 
                        user_permissions.get('context', {})
                    )
                    
                    # 去掉WHERE前缀
                    if modified_filter.strip().upper().startswith('WHERE'):
                        modified_filter = modified_filter[5:].strip()
                    
                    # 生成CTE
                    cte_name = f"filtered_{table_name.replace('.', '_')}"
                    cte_sql = f"{cte_name} AS (SELECT * FROM {table_name} WHERE {modified_filter})"
                    cte_clauses.append(cte_sql)
                    table_replacements[table_name] = table_name
                    
                    logger.info(f"生成权限过滤CTE: {table_name} -> {cte_name}")
        
        if not cte_clauses:
            logger.info("无需行级过滤，返回原SQL")
            return sql
        
        # 构建完整SQL
        cte_prefix = "WITH " + ", ".join(cte_clauses) + " "
        full_sql = cte_prefix + sql
        
        # 解析并修改AST
        ast = sqlglot.parse_one(full_sql, dialect=self.dialect)
        
        def replace_table_node(node):
            """递归替换表节点"""
            if isinstance(node, exp.Table):
                table_name_lower = self._extract_table_name_from_node(node)
                
                if table_name_lower in table_replacements:
                    if not self._is_in_cte_definition(node, ast):
                        new_table_name = table_replacements[table_name_lower]
                        node.this.set("this", exp.Identifier(this=new_table_name))
                        logger.info(f"表替换: {table_name_lower} -> {new_table_name}")
            
            return node
        
        # 应用表替换
        modified_ast = ast.transform(replace_table_node)
        modified_sql = modified_ast.sql(dialect=self.dialect)
        
        logger.info(f"SQL改写完成")
        return modified_sql
    
    def _extract_table_name_from_node(self, node: exp.Table) -> str:
        """从表节点提取表名"""
        if hasattr(node.this, 'name'):
            return str(node.this.name).lower()
        else:
            return str(node.this).lower()
    
    def _is_in_cte_definition(self, table_node: exp.Table, ast: exp.Expression) -> bool:
        """判断表节点是否在CTE定义中"""
        cte_nodes = list(ast.find_all(exp.CTE))
        for cte in cte_nodes:
            if cte.this and self._is_node_descendant(table_node, cte.this):
                return True

    
    def _is_node_descendant(self, child_node: exp.Expression, parent_node: exp.Expression) -> bool:
        """检查节点是否为后代节点"""
        queue = deque([parent_node])
        visited = set()
        
        while queue:
            current = queue.popleft()
            current_id = id(current)
            
            if current_id in visited:
                continue
            visited.add(current_id)
            
            if current is child_node:
                return True
            
            if hasattr(current, 'args'):
                for key, value in current.args.items():
                    if isinstance(value, exp.Expression):
                        queue.append(value)
                    elif isinstance(value, list):
                        for item in value:
                            if isinstance(item, exp.Expression):
                                queue.append(item)
        
        return False

    
    def _replace_placeholders(self, template: str, context: Dict) -> str:
        """替换SQL模板中的占位符"""
        logger.info(f'替换占位符: {template}')
        placeholders = re.findall(r'\$([a-zA-Z_]+)', template)
        for ph in set(placeholders):
            placeholder_key = f'\${ph}'
            if ph in context:
                value = context[ph]
                safe_value = str(value)  # 确保值安全
                template = template.replace(placeholder_key, safe_value)
                logger.info(f'替换 {placeholder_key} -> {safe_value}')
            else:
                logger.error(f'占位符 {placeholder_key} 未找到，替换为默认值 NULL')
                template = template.replace(placeholder_key, 'NULL')  # 默认替换为 NULL，避免SQL错误
        return template
