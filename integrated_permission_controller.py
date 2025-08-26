# integrated_permission_controller.py - 完整版本

from collections import deque
from sqlalchemy import text, create_engine, and_
from sqlalchemy.orm import sessionmaker
from database_models import (Base, PermissionRule, UserRole, UserRoleMapping, PermissionLog, 
                            Employee, Company, Salary, Age, PermissionType, FilterType)
from typing import Dict, List, Optional, Tuple, Set
import sqlglot
from sqlglot import expressions as exp
import json
import time
import re
from datetime import datetime
from loguru import logger

from config_loader import ConfigLoader
from sql_parser import SQLTableExtractor

class UserManager:
    """用户信息管理类"""
    
    def __init__(self, session_factory):
        self.SessionLocal = session_factory
    
    def get_user_basic_info(self, user_id: int) -> Employee:
        """获取用户基本信息 - 返回ORM对象"""
        session = self.SessionLocal()
        employee = session.query(Employee).filter(Employee.user_id == user_id).first()
        session.close()
        if not employee:
            logger.warning(f"用户不存在: user_id={user_id}")
            raise ValueError(f"用户 {user_id} 不存在")
        logger.info(f"成功获取用户信息: {employee.user_name}, company_id={employee.company_id}")
        return employee
    
    def get_effective_role(self, user_id: int, default_role: str) -> str:
        """获取用户有效角色"""
        session = self.SessionLocal()
        role_mapping = session.query(UserRoleMapping).join(UserRole).filter(
            and_(
                UserRoleMapping.user_id == user_id,
                UserRoleMapping.is_active == True,
                UserRole.is_active == True
            )
        ).first()
        session.close()
        if role_mapping:
            effective_role = role_mapping.role.role_name
        else:
            effective_role = default_role
        logger.info(f"用户有效角色: {effective_role}")
        return effective_role

class PermissionManager:
    """权限管理类"""
    
    def __init__(self, session_factory):
        self.SessionLocal = session_factory
    
    def get_permission_rules(self) -> List[PermissionRule]:
        """获取活动的权限规则"""
        session = self.SessionLocal()
        rules = session.query(PermissionRule).filter(
            PermissionRule.is_active == True
        ).order_by(PermissionRule.priority.desc()).all()
        session.close()
        logger.info(f"获取权限规则完成: {len(rules)} 条规则")
        return rules
    
    def build_user_permissions(self, rules: List[PermissionRule], user_info: Employee, 
                             user_role: str, system_tables: Set[str]) -> Dict:
        permissions = {}
        logger.info(f"开始构建用户权限: user_id={user_info.user_id}, role={user_role}")
        
        for rule in rules:
            if rule.target_roles:
                target_roles = json.loads(rule.target_roles)

            else:
                target_roles = []
            
            if user_role not in target_roles and '*' not in target_roles:
                continue
            
            tables_to_apply = system_tables if rule.table_name == '*' else [rule.table_name]
            
            for table_name in tables_to_apply:
                if table_name not in permissions:
                    permissions[table_name] = {'access': True, 'row_filter': None}
                
                if rule.filter_type == FilterType.DENY_ALL:
                    permissions[table_name]['access'] = False
                elif rule.filter_type == FilterType.CUSTOM_SQL and rule.filter_sql:
                    permissions[table_name]['row_filter'] = rule.filter_sql
                elif rule.filter_type == FilterType.ALLOW_ALL:
                    permissions[table_name]['row_filter'] = None
        
        logger.info(f"用户权限构建完成: {len(permissions)} 个表的权限")
        return permissions

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

class LogManager:
    """日志管理类"""
    
    def __init__(self, session_factory):
        self.SessionLocal = session_factory
    
    def log_query_execution(self, user_id: int, original_sql: str, modified_sql: str = None,
                          table_names: List[str] = None, status: str = 'unknown',
                          execution_time: int = 0, error_message: str = None) -> PermissionLog:
        """记录查询执行日志 - 返回ORM对象"""
        session = self.SessionLocal()
        log_entry = PermissionLog(
            user_id=user_id,
            original_sql=original_sql,
            modified_sql=modified_sql,
            table_names=json.dumps(table_names or []),
            execution_result=status,
            execution_time=execution_time,
            error_message=error_message,
            created_at=datetime.now()
        )
        session.add(log_entry)
        session.commit()
        session.refresh(log_entry)
        logger.info(f"记录查询日志: log_id={log_entry.log_id}, status={status}")
        session.close()
        return log_entry

class CacheManager:
    """缓存管理类"""
    
    def __init__(self, cache_ttl: int = 300):
        self.cache_ttl = cache_ttl
        self.permission_cache = {}
        self.rule_cache = {}
        self.user_info_cache = {}
        logger.info("数据缓存管理器初始化完成")
    
    def get(self, cache_key: str, cache_type: str = 'permission') -> Optional[any]:
        """获取缓存数据"""
        cache_dict = self._get_cache_dict(cache_type)
        if cache_key in cache_dict:
            cached_data, timestamp = cache_dict[cache_key]
            if time.time() - timestamp < self.cache_ttl:
                logger.info(f"缓存命中: {cache_type}:{cache_key}")
                return cached_data
            else:
                del cache_dict[cache_key]
                logger.info(f"缓存过期: {cache_type}:{cache_key}")
        return None
    
    def set(self, cache_key: str, data: any, cache_type: str = 'permission'):
        """设置缓存数据"""
        cache_dict = self._get_cache_dict(cache_type)
        cache_dict[cache_key] = (data, time.time())
        logger.info(f"数据已缓存: {cache_type}:{cache_key}")
    
    def clear(self, cache_type: Optional[str] = None):
        """清除缓存"""
        if cache_type is None:
            self.permission_cache.clear()
            self.rule_cache.clear()
            self.user_info_cache.clear()
            logger.info("所有缓存已清除")
        else:
            cache_dict = self._get_cache_dict(cache_type)
            cache_dict.clear()
            logger.info(f"{cache_type}缓存已清除")
    
    def _get_cache_dict(self, cache_type: str) -> Dict:
        """获取对应类型的缓存字典"""
        cache_dicts = {
            'permission': self.permission_cache,
            'rule': self.rule_cache,
            'user_info': self.user_info_cache
        }
        if cache_type not in cache_dicts:
            raise ValueError(f"未知的缓存类型: {cache_type}")
        return cache_dicts[cache_type]

class RefactoredPermissionController:
    
    def __init__(self, config_path: str = "config.yaml"):
        """初始化权限控制器"""
        logger.info("开始初始化权限控制器")
        
        # 加载配置
        self.config = ConfigLoader(config_path)
        
        # 初始化数据库
        self._init_database()
        
        # 初始化组件
        self.user_manager = UserManager(self.SessionLocal)
        self.permission_manager = PermissionManager(self.SessionLocal)
        self.log_manager = LogManager(self.SessionLocal)
        self.cache_manager = CacheManager(self.config.get('cache.default_ttl', 300))
        
        # 初始化SQL处理组件
        self.sql_rewrite_engine = SQLRewriteEngine()
        self.system_tables = self._load_system_tables()
        self.sql_extractor = SQLTableExtractor(self.system_tables)
        
        logger.info("权限控制器初始化完成")
        self._ensure_database_ready()
    
    def _load_system_tables(self) -> Set[str]:
        session = self.SessionLocal()
        system_tables_query = session.query(PermissionRule.table_name).distinct().all()
        result = set([row.table_name for row in system_tables_query])
        session.close()
        return result  # 确保只从数据库加载

    def _init_database(self):
        """初始化数据库连接"""
        db_config = self.config.get_db_config()
        
        self.db_url = self.config.get_db_url()  # 封装到config中
        
        self.engine = create_engine(
            self.db_url,
            echo=self.config.get('environment.debug', False),
            pool_pre_ping=True,
            pool_recycle=3600,
            pool_size=10,
            max_overflow=20
        )
        
        self.SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=self.engine)
    
    def _ensure_database_ready(self):
        """确保数据库表结构就绪"""
        # 根据配置决定是否自动建表
        auto_create = self.config.get('database.auto_create_tables', True)
        if auto_create:
            Base.metadata.create_all(bind=self.engine)
            logger.info("ORM自动建表完成")
        else:
            logger.info("跳过自动建表（配置禁用）")
    
    def get_user_permissions_with_cache(self, user_id: int) -> Dict:
        """获取用户权限（带缓存）"""
        cache_key = f"user_perm_{user_id}"
        cached_data = self.cache_manager.get(cache_key, 'permission')
        
        if cached_data:
            return cached_data
        
        logger.info(f"开始构建用户权限: user_id={user_id}")
        
        # 获取用户信息 - 使用ORM对象
        user_info = self.user_manager.get_user_basic_info(user_id)
        
        # 获取有效角色
        effective_role = self.user_manager.get_effective_role(user_id, user_info.role)
        
        # 获取权限规则
        rules = self.get_permission_rules_with_cache()
        
        # 构建权限
        permissions = self.permission_manager.build_user_permissions(
            rules, user_info, effective_role, self.system_tables
        )
        
        # 构建结果（包含用户上下文信息用于占位符替换）
        result = {
            'user_id': user_info.user_id,
            'user_name': user_info.user_name,
            'company_id': user_info.company_id,
            'role': user_info.role,
            'effective_role': effective_role,
            'table_permissions': permissions,
            'context': {
                'user_id': user_info.user_id,
                'user_company_id': user_info.company_id,
                'user_role': effective_role
            }
        }
        
        # 缓存结果
        self.cache_manager.set(cache_key, result, 'permission')
        logger.info(f"用户权限构建完成并缓存: user_id={user_id}")
        
        return result
    
    def get_permission_rules_with_cache(self) -> List[PermissionRule]:
        """获取权限规则（带缓存）"""
        cache_key = "permission_rules"
        cached_rules = self.cache_manager.get(cache_key, 'rule')
        
        if cached_rules:
            return cached_rules
        
        logger.info("开始从数据库读取权限规则")
        rules = self.permission_manager.get_permission_rules()
        logger.info(f"权限规则读取完成: {len(rules)} 条")
        
        self.cache_manager.set(cache_key, rules, 'rule')
        return rules
    
    def execute_query_with_permissions(self, sql: str, user_id: int, log_execution: bool = True) -> PermissionLog:
        self._load_system_tables()  # 确保系统表加载
        start_time = time.time()
        log_entry = None
        original_sql = sql
        modified_sql = None
        table_names = []
        result = None
        status = 'unknown'
        error_message = None
        
        security_report = self.sql_rewrite_engine.validate_sql_security(sql)
        if not security_report['is_safe']:
            error_message = f'SQL安全检查失败: {security_report["blocked_operations"]}'
            status = 'error'
        else:
            tables = self.sql_extractor.extract_table_info_with_schema(sql)
            for table_name in tables:
                model = globals().get(table_name.capitalize())  # 确保模型定义
                if model:
                    with self.SessionLocal() as session:  # 使用上下文管理
                        result = session.query(model).all()  # 纯 ORM 查询
                        status = 'success'
        
        execution_time = int((time.time() - start_time) * 1000)
        if log_execution:
            log_entry = self.log_manager.log_query_execution(user_id, original_sql, modified_sql, table_names, status, execution_time, error_message)
            log_entry.result = result
        return log_entry
    
    def _execute_sql_direct(self, sql: str) -> List[Tuple]:
        """直接执行SQL"""
        session = self.SessionLocal()
        result = session.execute(text(sql)).fetchall()
        session.close()
        return [tuple(row) for row in result]