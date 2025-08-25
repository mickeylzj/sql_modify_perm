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
